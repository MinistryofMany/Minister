import type { IssuedBadge } from "@minister/plugin-sdk";

import { accountAgeBadge, dateFromUnixSeconds } from "../oauth-common";

// Pure, network-free helpers for the Hacker News challenge flow, kept out of
// index.ts so the token match and badge derivation are unit-testable without the
// public API.

const PROVIDER = "hackernews" as const;

// HN usernames are 2-15 chars: letters, digits, underscore, and hyphen. Anchored
// so a pasted profile URL or trailing junk is rejected before we build a token.
const USERNAME_RE = /^[a-zA-Z0-9_-]{2,15}$/u;

export function isValidHackerNewsUsername(name: string): boolean {
  return USERNAME_RE.test(name);
}

// The challenge token must appear somewhere in the user's `about` text. HN
// renders `about` as HTML and may entity-escape, but the token is plain
// [a-z0-9-] so it survives verbatim; a substring check is enough.
export function aboutContainsToken(about: string | null | undefined, token: string): boolean {
  if (!about || !token) return false;
  return about.includes(token);
}

export interface HackerNewsUserFacts {
  // HN's `id` IS the immutable, case-sensitive username — both the disclosed
  // handle and the Sybil anchor (there is no separate numeric id).
  id: string;
  // Unix seconds (`created`). Optional: a partial response still yields the
  // oauth-account badge.
  created?: number;
}

export function buildHackerNewsBadges(facts: HackerNewsUserFacts, now: Date): IssuedBadge[] {
  // The username is BOTH the anchor and the disclosed handle, so it legitimately
  // appears in the claims — opt out of the runtime's anchor-leak guard
  // (revealsAnchor), exactly as email-exact does. Dedup still nullifies it.
  const anchor = facts.id;
  const badges: IssuedBadge[] = [
    {
      type: "oauth-account",
      attributes: { provider: PROVIDER, handle: facts.id },
      claims: { provider: PROVIDER, handle: facts.id },
      sybilAnchor: anchor,
      revealsAnchor: true,
    },
  ];

  const age =
    typeof facts.created === "number"
      ? accountAgeBadge(PROVIDER, dateFromUnixSeconds(facts.created), anchor, now)
      : null;
  if (age) badges.push(age);

  return badges;
}
