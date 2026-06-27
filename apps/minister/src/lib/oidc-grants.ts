import type { Prisma } from "@/generated/prisma";

import { prisma } from "@/lib/prisma";

// Grant tracking for the OIDC "you've already proven these to this
// platform" transparency section (Phase-3 step 2). An OidcGrant is the
// durable, per-(userId, clientId) record of which badge TYPES and profile
// sub-claims a user has ever disclosed to a given RP.
//
// The grant is a RECORD of disclosure, never an authorization to skip
// consent: every authorize still renders consent, re-discloses a live VC,
// and runs minimizeToPolicy. It holds TYPES only (no VC, no attributes, no
// issued-at) so it can never satisfy a constrained leaf on its own.

// Shape returned by loadGrant — the durably-granted set for a (user, client).
export interface GrantState {
  badgeTypes: string[];
  profileName: boolean;
  profileAvatar: boolean;
}

const EMPTY_GRANT: GrantState = {
  badgeTypes: [],
  profileName: false,
  profileAvatar: false,
};

// Read the durable grant for a user+client. Returns an empty grant (no
// types, no profile flags) when none exists yet — the common first-visit
// path. The lookup key is server-supplied (session userId + validated
// clientId); no client input participates.
export async function loadGrant(userId: string, clientId: string): Promise<GrantState> {
  const row = await prisma.oidcGrant.findUnique({
    where: { userId_clientId: { userId, clientId } },
    select: { badgeTypes: true, profileName: true, profileAvatar: true },
  });
  if (!row) return { ...EMPTY_GRANT };
  return {
    badgeTypes: row.badgeTypes,
    profileName: row.profileName,
    profileAvatar: row.profileAvatar,
  };
}

// Stable, deduplicated union of two type lists. Used to accumulate the
// monotone "ever proven to this platform" set on each consent.
export function unionTypes(a: readonly string[], b: readonly string[]): string[] {
  return [...new Set([...a, ...b])];
}

// Of the types the RP requested for THIS room (via `badge:<type>` scopes),
// which are already durably granted to this client. This is the set the
// locked "already proven" section is built from — granted AND relevant to
// the room. A previously-granted type the room does not request is NOT
// returned here, and so is neither shown nor disclosed for this room
// (per-room minimal disclosure, F-2(a)).
export function grantedRelevantTypes(
  grant: GrantState,
  requestedBadgeTypes: ReadonlySet<string> | readonly string[],
): string[] {
  const requested =
    requestedBadgeTypes instanceof Set ? requestedBadgeTypes : new Set(requestedBadgeTypes);
  return grant.badgeTypes.filter((t) => requested.has(t));
}

// Upsert (create-or-accumulate) the grant inside the caller's transaction.
// `tx` is a Prisma transaction client so the grant write commits atomically
// with the auth-code create — a failed consent leaves no orphan grant.
// badgeTypes accumulate by union; profile flags accumulate by OR (once
// shown to this client, they stay in the transparency section).
export async function upsertGrant(
  tx: Prisma.TransactionClient,
  params: {
    userId: string;
    clientId: string;
    badgeTypes: string[];
    profileName: boolean;
    profileAvatar: boolean;
  },
): Promise<void> {
  const { userId, clientId, badgeTypes, profileName, profileAvatar } = params;
  const existing = await tx.oidcGrant.findUnique({
    where: { userId_clientId: { userId, clientId } },
    select: { badgeTypes: true, profileName: true, profileAvatar: true },
  });
  const mergedTypes = unionTypes(existing?.badgeTypes ?? [], badgeTypes);
  await tx.oidcGrant.upsert({
    where: { userId_clientId: { userId, clientId } },
    create: {
      userId,
      clientId,
      badgeTypes: mergedTypes,
      profileName,
      profileAvatar,
    },
    update: {
      badgeTypes: { set: mergedTypes },
      profileName: (existing?.profileName ?? false) || profileName,
      profileAvatar: (existing?.profileAvatar ?? false) || profileAvatar,
    },
  });
}
