import { buildPairwiseUserDid, reissueVcWithSubject, type Issuer } from "@minister/vc";

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

// Identifies the relying party a badge is being disclosed to. The pairwise
// `sub` MUST be the merge-aware value from resolveSub (NOT raw pairwiseSub),
// so a merged account keeps a consistent per-RP badge subject. The issuer
// re-signs the re-minted VC with the same key used at issuance.
export interface DisclosureContext {
  // Per-RP pairwise pseudonym from resolveSub (oidc-subject.ts).
  sub: string;
  issuer: Issuer;
}

// Loads the badges the user approved for this grant and re-mints each one
// under a per-RP PAIRWISE subject before disclosure. Scoped to the owning
// user so a stale approvedBadgeIds list can never surface another user's
// badge.
//
// Privacy: the VC stored in `Badge.vcJwt` carries the global holder DID
// (did:web:<domain>:users:<rawUserId>), which would correlate the user
// across relying parties and leak the internal id. We never disclose it.
// Instead each disclosed VC is re-signed with credentialSubject.id == JWT
// sub == did:web:<domain>:u:<sub>, where `sub` is the per-RP pairwise
// pseudonym. Every other claim (type, jti, exp, nbf, iat, the credential
// claims) is preserved verbatim, so re-minting cannot extend validity and
// the credential keeps its identity. The stored global-DID VC stays as
// Minister's internal record.
export async function loadApprovedBadgeJwts(
  userId: string,
  badgeIds: string[],
  ctx: DisclosureContext,
): Promise<string[]> {
  if (badgeIds.length === 0) return [];
  const rows = await prisma.badge.findMany({
    where: { userId, id: { in: badgeIds } },
    select: { vcJwt: true },
  });

  const pairwiseSubjectDid = buildPairwiseUserDid(ctx.issuer.domain, ctx.sub);
  return Promise.all(
    rows.map((r) => reissueVcWithSubject(ctx.issuer, r.vcJwt, pairwiseSubjectDid)),
  );
}
