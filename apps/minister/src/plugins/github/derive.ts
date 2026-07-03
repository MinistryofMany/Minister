import type { IssuedBadge } from "@minister/plugin-sdk";
import { ACCOUNT_AGE_MONTHS, FOLLOWERS_BUCKETS } from "@minister/shared";

// Pure badge-derivation logic for the GitHub plugin. Kept out of index.ts so
// the threshold/bucket rules are unit-testable without mocking the network:
// feed a fixed set of GitHub /user facts + a `now` and assert the claims.

const PROVIDER = "github" as const;

export interface GithubUserFacts {
  id: number;
  login: string;
  // Optional so a partial /user response still yields the oauth-account badge.
  createdAt?: string; // ISO 8601, GitHub `created_at`
  twoFactor?: boolean; // GitHub `two_factor_authentication`
  followers?: number; // GitHub `followers`
}

// Whole months elapsed between two dates (calendar months, not 30-day blocks),
// so "older than 12 months" means a real year has passed regardless of month
// lengths. Never negative.
export function monthsBetween(from: Date, to: Date): number {
  let months = (to.getFullYear() - from.getFullYear()) * 12 + (to.getMonth() - from.getMonth());
  if (to.getDate() < from.getDate()) months -= 1;
  return Math.max(0, months);
}

// Highest ascending bucket that `value` reaches, or null if it clears none.
// Assumes `buckets` is sorted ascending.
export function highestBucket(value: number, buckets: readonly number[]): number | null {
  let best: number | null = null;
  for (const b of buckets) {
    if (value >= b) best = b;
  }
  return best;
}

// Build every badge we can attest from one GitHub /user response. Always
// includes oauth-account; appends account-age / two-factor / social-following
// only when the source data supports a threshold. `now` is injected for tests.
export function buildGithubBadges(facts: GithubUserFacts, now: Date): IssuedBadge[] {
  const accountId = String(facts.id);
  const badges: IssuedBadge[] = [
    {
      type: "oauth-account",
      attributes: { provider: PROVIDER, accountId, handle: facts.login },
      claims: { provider: PROVIDER, accountId, handle: facts.login },
    },
  ];

  if (facts.createdAt) {
    const created = new Date(facts.createdAt);
    if (!Number.isNaN(created.getTime())) {
      const bucket = highestBucket(monthsBetween(created, now), ACCOUNT_AGE_MONTHS);
      if (bucket !== null) {
        badges.push({
          type: "account-age",
          attributes: { provider: PROVIDER, olderThanMonths: bucket },
          claims: { provider: PROVIDER, olderThanMonths: bucket },
        });
      }
    }
  }

  if (facts.twoFactor === true) {
    badges.push({
      type: "two-factor",
      attributes: { provider: PROVIDER },
      claims: { provider: PROVIDER },
    });
  }

  if (typeof facts.followers === "number") {
    const bucket = highestBucket(facts.followers, FOLLOWERS_BUCKETS);
    if (bucket !== null) {
      badges.push({
        type: "social-following",
        attributes: { provider: PROVIDER, followersAtLeast: bucket },
        claims: { provider: PROVIDER, followersAtLeast: bucket },
      });
    }
  }

  return badges;
}
