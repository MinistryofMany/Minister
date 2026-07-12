import { createHash, randomBytes } from "node:crypto";

import type { IssuedBadge } from "@minister/plugin-sdk";
import { ACCOUNT_AGE_MONTHS, type OAuthProvider } from "@minister/shared";

// Shared, network-free helpers for the OAuth / OpenID badge plugins
// (reddit, google, x, steam, hackernews). Kept out of any single plugin so the
// threshold math and PKCE derivation are unit-testable without mocking a
// provider, and so six flows don't each re-derive the same rules. The github
// plugin predates this module and keeps its own copy in github/derive.ts.

// Whole calendar months elapsed between two dates (not 30-day blocks), so
// "older than 12 months" means a real year regardless of month lengths. Never
// negative. Identical rule to github/derive.ts:monthsBetween.
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

// A Date from a unix-seconds timestamp (reddit `created_utc`, HN `created`), or
// null for a non-finite / NaN input. Callers that already hold an ISO string
// build the Date themselves.
export function dateFromUnixSeconds(seconds: number): Date | null {
  if (!Number.isFinite(seconds)) return null;
  const d = new Date(seconds * 1000);
  return Number.isNaN(d.getTime()) ? null : d;
}

// Build an `account-age` badge from a known account-creation date, or null when
// the account is too new to clear the lowest bucket (12 months) or the date is
// missing. Discloses only the COARSE "older than N months" lower bound, never
// the exact date. `anchor` is the same immutable per-provider Sybil anchor the
// oauth-account badge carries, so both dedup against the one scarce account.
export function accountAgeBadge(
  provider: OAuthProvider,
  created: Date | null,
  anchor: string,
  now: Date,
): IssuedBadge | null {
  if (!created) return null;
  const bucket = highestBucket(monthsBetween(created, now), ACCOUNT_AGE_MONTHS);
  if (bucket === null) return null;
  return {
    type: "account-age",
    attributes: { provider, olderThanMonths: bucket },
    claims: { provider, olderThanMonths: bucket },
    sybilAnchor: anchor,
  };
}

// A random, URL-safe opaque token. Used for the OAuth `state` correlation value
// (lifted to WizardSession.pendingToken) and for the HackerNews challenge token.
export function randomToken(bytes = 24): string {
  return randomBytes(bytes).toString("base64url");
}

// A PKCE S256 pair. `challenge = base64url(sha256(verifier))`. The verifier is
// stashed server-side in wizard `data` across the redirect and replayed at the
// token exchange; it never crosses the wire to the browser (toClientState
// scrubs `data`). Required for X (Twitter); harmless-but-unused elsewhere.
export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

// Presence check for deployment-time OAuth client credential env vars. Shared
// by every OAuth plugin's `isConfigured()` probe (github/google/reddit — steam
// and hackernews need no credentials and skip the probe entirely) so the
// add-a-badge menu can hide a provider, and the wizard entry point can refuse
// to start it, instead of routing a user into a flow that throws on its first
// step. Checks presence only — never reads, logs, or returns the values.
export function hasEnvCreds(names: readonly string[]): boolean {
  return names.every((name) => Boolean(process.env[name]));
}
