import type { IssuedBadge } from "@minister/plugin-sdk";

import { accountAgeBadge } from "../oauth-common";

// Pure badge-derivation for the X (Twitter) plugin, kept out of index.ts so the
// anchor + account-age rules are unit-testable without the network.

const PROVIDER = "x" as const;

export interface XUserFacts {
  // X's immutable numeric user id (a string in the v2 API). The Sybil anchor.
  id: string;
  // The @handle. Renameable, so it is the DISCLOSED handle, never the anchor.
  username: string;
  // ISO 8601 `created_at`. Optional: a partial response still yields the
  // oauth-account badge.
  createdAt?: string;
}

export function buildXBadges(facts: XUserFacts, now: Date): IssuedBadge[] {
  const anchor = facts.id;
  const badges: IssuedBadge[] = [
    {
      type: "oauth-account",
      attributes: { provider: PROVIDER, handle: facts.username },
      claims: { provider: PROVIDER, handle: facts.username },
      sybilAnchor: anchor,
    },
  ];

  if (facts.createdAt) {
    const created = new Date(facts.createdAt);
    if (!Number.isNaN(created.getTime())) {
      const age = accountAgeBadge(PROVIDER, created, anchor, now);
      if (age) badges.push(age);
    }
  }

  return badges;
}
