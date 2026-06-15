import { prisma } from "@/lib/prisma";

// The user fields both OIDC claim paths need. Kept minimal and explicit so
// the pure resolver below has no Prisma dependency and is trivially
// unit-testable.
export interface ClaimsUser {
  displayName: string | null;
  name: string | null;
  avatarUrl: string | null;
  image: string | null;
}

// The common claim subset shared by the ID token (/oidc/token) and the
// userinfo response (/oidc/userinfo). `sub` is NOT included here: each path
// sources `sub` differently (the ID token mints a fresh pairwise sub; the
// userinfo response echoes the access token's sub), and OIDC only requires
// the two `sub` values to match, which they already do by construction.
export interface ResolvedUserClaims {
  // Present only when the `profile` scope was granted. `null` is a
  // meaningful "no value" that still gets emitted, matching prior behavior.
  name?: string | null;
  picture?: string | null;
  // The approved badges' VC JWTs. Empty array means "emit no
  // minister_badges claim" — callers check length before attaching.
  ministerBadges: string[];
}

// Single source of truth for the profile/badge claim mapping. OIDC Core
// requires /oidc/token (ID token) and /oidc/userinfo to return identical
// claims for the same grant; before this, each route derived the mapping
// independently with nothing enforcing agreement. Centralizing the
// `displayName ?? name` / `avatarUrl ?? image` precedence and the
// profile-scope gate here makes that agreement structural.
//
// Pure given its inputs (the user row, the granted scopes, the already
// loaded badge JWTs) so it can be unit-tested without a database.
export function resolveUserClaims(
  user: ClaimsUser,
  scopes: string[],
  approvedBadgeJwts: string[],
): ResolvedUserClaims {
  const resolved: ResolvedUserClaims = { ministerBadges: approvedBadgeJwts };

  if (scopes.includes("profile")) {
    resolved.name = user.displayName ?? user.name ?? null;
    resolved.picture = user.avatarUrl ?? user.image ?? null;
  }

  return resolved;
}

// Loads the VC JWTs for the badges the user approved for this grant. Scoped
// to the owning user so a stale approvedBadgeIds list can never surface
// another user's badge. Shared by both OIDC paths so the badge set is
// loaded identically.
export async function loadApprovedBadgeJwts(userId: string, badgeIds: string[]): Promise<string[]> {
  if (badgeIds.length === 0) return [];
  const rows = await prisma.badge.findMany({
    where: { userId, id: { in: badgeIds } },
    select: { vcJwt: true },
  });
  return rows.map((r) => r.vcJwt);
}
