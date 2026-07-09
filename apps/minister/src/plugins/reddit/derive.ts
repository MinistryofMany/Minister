import type { IssuedBadge } from "@minister/plugin-sdk";

import { accountAgeBadge, dateFromUnixSeconds } from "../oauth-common";

// Pure badge-derivation for the Reddit plugin, kept out of index.ts so the
// anchor construction and account-age threshold are unit-testable without the
// network.

const PROVIDER = "reddit" as const;

export interface RedditUserFacts {
  // Reddit's `/api/v1/me` returns the base36 id WITHOUT the type prefix; the
  // immutable "fullname" is `t2_<id>`. We anchor on the fullname so a username
  // rename can't evade dedup.
  id: string;
  // The username. Renameable, so it is the DISCLOSED handle, never the anchor.
  name: string;
  // Unix seconds (Reddit `created_utc`). Optional: a partial response still
  // yields the oauth-account badge.
  createdUtc?: number;
}

// The immutable Reddit fullname (`t2_<id>`) is the Sybil anchor. It is nullified
// and discarded by the wizard runtime; only the renameable `name` handle is
// revealed in the VC.
export function redditFullname(id: string): string {
  return `t2_${id}`;
}

export function buildRedditBadges(facts: RedditUserFacts, now: Date): IssuedBadge[] {
  const anchor = redditFullname(facts.id);
  const badges: IssuedBadge[] = [
    {
      type: "oauth-account",
      attributes: { provider: PROVIDER, handle: facts.name },
      claims: { provider: PROVIDER, handle: facts.name },
      sybilAnchor: anchor,
    },
  ];

  const age =
    typeof facts.createdUtc === "number"
      ? accountAgeBadge(PROVIDER, dateFromUnixSeconds(facts.createdUtc), anchor, now)
      : null;
  if (age) badges.push(age);

  return badges;
}
