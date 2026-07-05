import { buildPairwiseUserDid, reMintVc } from "@minister/vc";

import { audit } from "@/lib/audit";
import { sanitizeDisclosedClaims } from "@/lib/disclosure-claims";
import { getIssuer } from "@/lib/issuer";
import { assertNullifierDriftConsistent, NullifierDriftError } from "@/lib/nullifier/drift-cache";
import { nullifierService } from "@/lib/nullifier";
import { ACCESS_TOKEN_TTL, pairwiseJti } from "@/lib/oidc-tokens";
import { prisma } from "@/lib/prisma";

// Presentation lifetime of a disclosed badge VC = the access-token TTL (1h),
// the longest-lived artifact of the same OIDC grant. Evidence for the bound:
// the id_token lives 10 min (ID_TOKEN_TTL_SECONDS) and the SDK verifies it
// with a 30s clock tolerance, so a badge disclosed alongside it must stay
// valid ≥ ~10.5 min or it would expire before the token that carried it;
// /oidc/userinfo (reachable for the access token's 1h) re-mints badges at
// call time, so its consumers also get a full TTL from the moment they fetch.
// No RP holds a disclosed badge past its carrying token: Discreetly re-verifies
// the raw id_token on every gated call (dead at 10 min by its own model) and
// gates rooms once, at join, against a freshly minted per-room token.
const BADGE_DISCLOSURE_TTL_SECONDS = ACCESS_TOKEN_TTL;

// audit() is a bare prisma.auditLog.create with no internal error handling. In
// the fail-closed disclosure catch it MUST NOT be able to reject into the
// enclosing Promise.all — a degraded-DB audit-write failure there would fail
// the whole token/userinfo request and break the "login unaffected" invariant.
// Mirror the runPostCommit pattern: swallow with a console fallback (the record
// being written is a non-secret ledger/omission note, never user data).
async function safeAudit(
  userId: string,
  action: string,
  metadata: Record<string, unknown>,
): Promise<void> {
  try {
    await audit(userId, action, metadata);
  } catch (auditErr) {
    console.error(`[oidc-claims] failed to write audit ${action}:`, auditErr);
  }
}

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
//   - `iat`/`nbf` → re-stamped to now; `exp` → PRESENTATION-SHAPED:
//     min(now + BADGE_DISCLOSURE_TTL_SECONDS, original exp, Badge.expiresAt).
//     The issuance-derived exp (issuance + fixed 1y, second granularity) was a
//     stable ~25-bit cross-RP correlator; the disclosed exp now reflects only
//     disclosure time and never extends the badge's real lifetime.
//   - `iss`, `kid`, and every claim value → unchanged.
//
// Rows are additionally scoped to `issuer = <Minister's own DID>`, and reMintVc
// itself verifies the stored VC's signature against Minister's key before
// re-signing — so neither a foreign-issuer row (the future badge-import
// feature) nor a tampered/forged vcJwt can ever be laundered through the
// disclosure path into a fresh Minister-signed credential.
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
  const issuer = await getIssuer();
  const rows = await prisma.badge.findMany({
    // `issuer` scoping: only Minister's own badges are disclosable via re-mint.
    // A foreign-issuer row (badge import is a future feature) is silently not
    // disclosed rather than 500ing the login — reMintVc would refuse to re-sign
    // it anyway (signature check), this just keeps that refusal out of the
    // grant's happy path.
    where: { userId, id: { in: badgeIds }, issuer: issuer.did },
    // `nullifierRef` (crypto-core M5): opaque ledger handle for badges anchored
    // to a scarce credential. Non-null → this badge discloses a per-RP Sybil
    // nullifier bound under the signature; null → discloses exactly as before.
    select: { id: true, vcJwt: true, expiresAt: true, nullifierRef: true },
  });
  if (rows.length === 0) return [];

  const subjectId = buildPairwiseUserDid(issuer.domain, sub);

  // The user's opaque owner handle, needed to owner-check every nullifier
  // disclosure. Looked up ONCE, and ONLY when at least one selected badge
  // actually carries a ledger ref (the common no-nullifier grant does zero
  // extra work). A ref-bearing badge whose user has no handle is an
  // inconsistency that fails THAT badge closed below (never a nullifier-less
  // copy of a nullifier-bearing type).
  const needsOwnerHandle = rows.some((row) => Boolean(row.nullifierRef));
  const ownerHandle = needsOwnerHandle
    ? ((
        await prisma.user.findUnique({
          where: { id: userId },
          select: { dedupHandle: true },
        })
      )?.dedupHandle ?? null)
    : null;

  // Per-badge FAIL-CLOSED OMIT (ADR M5): a re-mint / sanitize throw on ONE badge
  // (a stored VC the current schema now rejects, a signature check failure, an
  // issuer drift) must omit only THAT badge — never fail the whole token /
  // userinfo request and 500 the login. A bare Promise.all would reject on the
  // first throw and take every other badge (and the sign-in) down with it. The
  // omitted badge is audit-logged so a systematic drift is visible rather than
  // silently swallowed.
  const minted = await Promise.all(
    rows.map(async (row) => {
      try {
        // Ref-bearing badges (crypto-core M5): derive the per-RP Sybil
        // nullifier and stamp it INSIDE the signed credentialSubject. Any
        // failure here — a missing owner handle, a Signet/owner-check error, or
        // a drift-cache mismatch — FAILS CLOSED: this badge is omitted from the
        // disclosure (login is unaffected) and audited. We NEVER fall back to a
        // nullifier-less copy of a nullifier-bearing badge type: dropping the
        // gating tag while still disclosing the fact would silently defeat the
        // RP's Sybil gate. `disclose` and the drift check run OUTSIDE any
        // transaction (§2.6 network-I/O rule).
        let nullifier: string | undefined;
        if (row.nullifierRef) {
          if (ownerHandle === null) {
            throw new Error("badge carries a nullifierRef but the user has no dedupHandle");
          }
          const nrp = await nullifierService.disclose({
            entryRef: row.nullifierRef,
            ownerHandle,
            clientId,
          });
          await assertNullifierDriftConsistent(row.nullifierRef, clientId, nrp);
          nullifier = nrp;
        }

        return await reMintVc(issuer, row.vcJwt, {
          subjectId,
          jti: pairwiseJti(row.id, clientId),
          maxExpiresAt: row.expiresAt,
          disclosureTtlSeconds: BADGE_DISCLOSURE_TTL_SECONDS,
          // Strip any legacy claim the current schema has since removed (e.g. the
          // pre-Phase-1 oauth-account Sybil anchor) before re-signing.
          sanitizeClaims: sanitizeDisclosedClaims,
          ...(nullifier !== undefined ? { nullifier } : {}),
        });
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        // A drift throw means Signet returned a different N_rp than first
        // recorded — a possible integrity failure of the ONLY runtime detector
        // Minister has (stage 2 carries no DLEQ). Raise a DEDICATED, alertable
        // signal (console.error + its own audit action), NOT the generic
        // omission record that also covers benign re-mint/schema failures, so a
        // lying/compromised Signet is not buried in omission noise.
        if (err instanceof NullifierDriftError) {
          console.error(`[nullifier] ${reason}`);
          await safeAudit(userId, "nullifier.drift_detected", {
            badgeId: row.id,
            clientId,
            reason,
          });
        }
        // Fail-closed omit. audit() is a bare prisma write with no internal
        // error handling; if it rejected here (DB degraded after the reads
        // succeeded) the rejection would escape into Promise.all and take down
        // the whole token/userinfo request — inverting the "login unaffected"
        // invariant precisely in the degraded conditions this path exists to
        // survive. Guard it so an audit-write failure can never do that.
        await safeAudit(userId, "oidc.badge_disclosure_omitted", {
          badgeId: row.id,
          clientId,
          reason,
        });
        return null;
      }
    }),
  );
  return minted.filter((jwt): jwt is string => jwt !== null);
}
