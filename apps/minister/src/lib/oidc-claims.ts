import { buildPairwiseUserDid, reMintVc } from "@minister/vc";

import { getIssuer } from "@/lib/issuer";
import { pairwiseJti } from "@/lib/oidc-tokens";
import { prisma } from "@/lib/prisma";

// The user fields both OIDC claim paths need. Deliberately only the
// user-curated profile values — the upstream auth identity (`User.name`,
// `User.image` from a Google/GitHub login) is NOT included, so it cannot
// leak into a disclosed claim by construction. Kept minimal and explicit
// so the pure resolver below has no Prisma dependency and is trivially
// unit-testable.
export interface ClaimsUser {
  displayName: string | null;
  avatarUrl: string | null;
}

// Which profile sub-claims the user consented to disclose for this grant.
// `name` and `avatar` are independent: a user may share their display
// name without their avatar, or vice versa. When the `profile` scope was
// not granted at all, both are false.
export interface ProfileGrant {
  name: boolean;
  avatar: boolean;
}

// The common claim subset shared by the ID token (/oidc/token) and the
// userinfo response (/oidc/userinfo). `sub` is NOT included here: each path
// sources `sub` differently (the ID token mints a fresh pairwise sub; the
// userinfo response echoes the access token's sub), and OIDC only requires
// the two `sub` values to match, which they already do by construction.
export interface ResolvedUserClaims {
  // Present only when the corresponding sub-claim was granted AND the user
  // has a curated value for it. Absent (the property is omitted) otherwise —
  // we never emit a claim for a field the user did not approve, and never
  // emit the upstream auth identity.
  name?: string;
  picture?: string;
  // The approved badges' VC JWTs. Empty array means "emit no
  // minister_badges claim" — callers check length before attaching.
  ministerBadges: string[];
}

// Single source of truth for the profile/badge claim mapping. OIDC Core
// requires /oidc/token (ID token) and /oidc/userinfo to return identical
// claims for the same grant; before this, each route derived the mapping
// independently with nothing enforcing agreement. Centralizing the
// curated-value mapping and the per-claim grant gate here makes that
// agreement structural.
//
// Privacy: only the user-curated `displayName`/`avatarUrl` are ever
// disclosed. The upstream auth identity (`User.name`/`User.image`) is not
// a parameter here, so it cannot leak. When a granted claim has no curated
// value, it is omitted entirely rather than falling back or emitting a
// misleading placeholder.
//
// Pure given its inputs (the user's curated profile, the per-claim grant,
// the already loaded badge JWTs) so it can be unit-tested without a database.
export function resolveUserClaims(
  user: ClaimsUser,
  profile: ProfileGrant,
  approvedBadgeJwts: string[],
): ResolvedUserClaims {
  const resolved: ResolvedUserClaims = { ministerBadges: approvedBadgeJwts };

  if (profile.name && user.displayName !== null) {
    resolved.name = user.displayName;
  }
  if (profile.avatar && user.avatarUrl !== null) {
    resolved.picture = user.avatarUrl;
  }

  return resolved;
}

// Loads and RE-MINTS the VC JWTs for the badges the user approved for this
// grant. Scoped to the owning user so a stale approvedBadgeIds list can never
// surface another user's badge. Shared by both OIDC paths so the badge set is
// disclosed identically.
//
// The stored VC carries a STABLE cross-RP subject (`did:web:<domain>:users:<userId>`)
// and a stable `jti = badge.id`; disclosing it verbatim would let two colluding
// relying parties re-link the user despite the pairwise id_token `sub`. So we
// never disclose the stored VC. Each approved badge is re-minted, bound to
// (userId, clientId):
//   - `sub` / `credentialSubject.id` → the PAIRWISE subject DID for this RP.
//   - `jti` → a per-RP value (never the raw badge id).
//   - `iat`/`nbf` → re-stamped to now; `exp` clamped so lifetime never extends.
//   - `iss`, `kid`, and every claim value → unchanged.
//
// `sub` is threaded in from the caller (the exact value stamped as the id_token
// `sub`) rather than recomputed here, so the disclosed badge subject's trailing
// component equals the id_token `sub` even when an account-merge SubjectOverride
// makes that differ from the pure `pairwiseSub(userId, clientId)`. That equality
// is what lets a relying party bind a disclosed badge to the login.
export async function loadApprovedBadgeJwts(
  userId: string,
  clientId: string,
  sub: string,
  badgeIds: string[],
): Promise<string[]> {
  if (badgeIds.length === 0) return [];
  const rows = await prisma.badge.findMany({
    where: { userId, id: { in: badgeIds } },
    select: { id: true, vcJwt: true, expiresAt: true },
  });
  if (rows.length === 0) return [];

  const issuer = await getIssuer();
  const subjectId = buildPairwiseUserDid(issuer.domain, sub);

  return Promise.all(
    rows.map((row) =>
      reMintVc(issuer, row.vcJwt, {
        subjectId,
        jti: pairwiseJti(row.id, clientId),
        maxExpiresAt: row.expiresAt,
      }),
    ),
  );
}
