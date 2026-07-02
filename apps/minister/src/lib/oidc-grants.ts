import type { Prisma } from "@/generated/prisma";

import { prisma } from "@/lib/prisma";

// Grant tracking for the OIDC "you've already proven these to this
// platform" transparency section (Phase-3 step 2). An OidcGrant is the
// durable, per-(userId, clientId) record of which badge TYPES, which badge
// INSTANCES, and which profile sub-claims a user has ever disclosed to a
// given RP.
//
// The grant is a RECORD of disclosure, never an authorization to skip
// consent: every authorize still renders consent, re-discloses a live VC,
// and runs minimizeToPolicy. It holds TYPES + instance ids (no VC, no
// attributes, no issued-at) so it can never satisfy a constrained leaf on
// its own. The instance ids exist so the "already proven" fold can force in
// exactly the badges the user previously disclosed, not every instance of a
// granted type (audit W1).

// Shape returned by loadGrant — the durably-granted set for a (user, client).
export interface GrantState {
  badgeTypes: string[];
  // Specific badge instance ids ever disclosed to this client.
  badgeIds: string[];
  profileName: boolean;
  profileAvatar: boolean;
}

const EMPTY_GRANT: GrantState = {
  badgeTypes: [],
  badgeIds: [],
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
    select: { badgeTypes: true, badgeIds: true, profileName: true, profileAvatar: true },
  });
  if (!row) return { ...EMPTY_GRANT };
  return {
    badgeTypes: row.badgeTypes,
    badgeIds: row.badgeIds,
    profileName: row.profileName,
    profileAvatar: row.profileAvatar,
  };
}

// Stable, deduplicated union of two string lists. Used to accumulate the
// monotone "ever proven to this platform" sets on each consent — reused for
// both badge TYPES and badge INSTANCE ids (both are just string sets).
export function unionTypes(a: readonly string[], b: readonly string[]): string[] {
  return [...new Set([...a, ...b])];
}

// The SPECIFIC badge instances previously disclosed to this client whose type
// the room still requests, restricted to instances the user still owns. This
// is the id-based "already proven" set (audit W1): force-including exactly
// these preserves the "can't untick what you already proved" guarantee
// WITHOUT re-disclosing sibling instances of a granted TYPE the user never
// chose. `owned` supplies id→type; a granted id of a non-requested type, or a
// since-deleted badge, is dropped. A previously-granted instance whose type
// the room does not request is excluded (per-room minimal disclosure, F-2(a)).
export function grantedRelevantBadgeIds(
  grant: GrantState,
  requestedBadgeTypes: ReadonlySet<string> | readonly string[],
  owned: ReadonlyArray<{ id: string; type: string }>,
): string[] {
  const requested =
    requestedBadgeTypes instanceof Set ? requestedBadgeTypes : new Set(requestedBadgeTypes);
  const granted = new Set(grant.badgeIds);
  return owned.filter((b) => granted.has(b.id) && requested.has(b.type)).map((b) => b.id);
}

// Upsert (create-or-accumulate) the grant inside the caller's transaction.
// `tx` is a Prisma transaction client so the grant write commits atomically
// with the auth-code create — a failed consent leaves no orphan grant.
// badgeTypes and badgeIds accumulate by union (the monotone "ever disclosed"
// sets); profile flags accumulate by OR (once shown to this client, they stay
// in the transparency section). `badgeIds` are the specific instances truly
// disclosed this round (the minimized set), matching `badgeTypes`.
export async function upsertGrant(
  tx: Prisma.TransactionClient,
  params: {
    userId: string;
    clientId: string;
    badgeTypes: string[];
    badgeIds: string[];
    profileName: boolean;
    profileAvatar: boolean;
  },
): Promise<void> {
  const { userId, clientId, badgeTypes, badgeIds, profileName, profileAvatar } = params;
  const existing = await tx.oidcGrant.findUnique({
    where: { userId_clientId: { userId, clientId } },
    select: { badgeTypes: true, badgeIds: true, profileName: true, profileAvatar: true },
  });
  const mergedTypes = unionTypes(existing?.badgeTypes ?? [], badgeTypes);
  const mergedIds = unionTypes(existing?.badgeIds ?? [], badgeIds);
  await tx.oidcGrant.upsert({
    where: { userId_clientId: { userId, clientId } },
    create: {
      userId,
      clientId,
      badgeTypes: mergedTypes,
      badgeIds: mergedIds,
      profileName,
      profileAvatar,
    },
    update: {
      badgeTypes: { set: mergedTypes },
      badgeIds: { set: mergedIds },
      profileName: (existing?.profileName ?? false) || profileName,
      profileAvatar: (existing?.profileAvatar ?? false) || profileAvatar,
    },
  });
}
