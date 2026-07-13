import { buildPairwiseUserDid, type CredentialStatusEntry, reMintVc } from "@minister/vc";

import { Prisma } from "@/generated/prisma";
import { audit } from "@/lib/audit";
import { sanitizeDisclosedClaims } from "@/lib/disclosure-claims";
import { GROUP_MEMBERSHIP_BADGE_TYPE } from "@/lib/group-roles";
import { getIssuer } from "@/lib/issuer";
import { assertNullifierDriftConsistent, NullifierDriftError } from "@/lib/nullifier/drift-cache";
import { nullifierService } from "@/lib/nullifier";
import { ACCESS_TOKEN_TTL } from "@/lib/oidc-tokens";
import { derivePairwiseJti } from "@/lib/pairwise-backend";
import { prisma } from "@/lib/prisma";
import { allocateStatusEntry, credentialStatusFor } from "@/lib/status-list";

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

// The per-relying-party persona snapshot for this grant (OidcProfileOverride),
// or `null` when NO override row exists for this RP. When the row exists it is
// AUTHORITATIVE for both fields: a null field means "share nothing for this
// field with this app", never a fall-through to the global default. Only a
// missing row (`null`) falls back to the global curated value (legacy grants).
// This is ONLY the snapshotted per-RP override — never the upstream auth
// identity, which is not a source anywhere in this resolver.
export interface ProfileOverride {
  displayName: string | null;
  avatarUrl: string | null;
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
  // Coarse anti-sybil bucket (0-4), snapshotted at consent. Present ONLY when
  // the `sybil-score` grant is true AND a bucket was actually stamped (non-null)
  // at consent — never recomputed here. Absent (property omitted) otherwise.
  // 0 is a real value and is emitted; only null/ungranted omit the claim.
  sybilBucket?: number;
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
// Precedence, PER FIELD, and only when that field's grant boolean is true.
// The snapshot-per-app model makes an EXISTING override row AUTHORITATIVE — a
// null field on a present row means "share nothing for this field with this
// app", NOT "fall back to the global default". The global value is ONLY a
// legacy fallback for a grant that predates personas (no override row at all):
//   - override row present  -> use `override.<field>` verbatim (null => omit);
//   - no override row (null) -> use the GLOBAL `user.<field>` (null => omit).
// In both cases a null resolved value omits the claim entirely (no null, no
// placeholder).
//
// Why authoritative-on-present: once a user has shaped a persona for an app,
// clearing a field must DOWNGRADE disclosure (share nothing) rather than
// silently UPGRADE it to the global real name/avatar. Falling back per-null-
// field would make "clear the field" leak the global default — the opposite
// of the user's intent.
//
// Privacy: both sources are user-curated. The upstream auth identity
// (`User.name`/`User.image`) is NOT a parameter here, so it can never leak
// through either source.
//
// Pure given its inputs (the global curated profile, the per-RP override
// snapshot, the per-claim grant, the already loaded badge JWTs) so it can be
// unit-tested without a database.
// The sybil-score disclosure is snapshotted at consent (the grant boolean +
// the bucket stamped on the auth code, denormalized onto the access token) and
// passed in here — never recomputed. This resolver only GATES emission:
//   - `sybilScoreGrant` false            -> omit (RP was not granted the scope);
//   - `sybilBucket` null                 -> omit (compute failed / omitted at
//                                            consent — fail-closed-omit);
//   - both satisfied                     -> emit `sybilBucket` verbatim.
// Bucket 0 is a REAL disclosed value ("hardest to fake: no"), so it must NOT be
// dropped — the gate is `!== null`, never falsy.
export function resolveUserClaims(
  user: ClaimsUser,
  profile: ProfileGrant,
  approvedBadgeJwts: string[],
  override: ProfileOverride | null,
  sybilScoreGrant: boolean,
  sybilBucket: number | null,
): ResolvedUserClaims {
  const resolved: ResolvedUserClaims = { ministerBadges: approvedBadgeJwts };

  if (sybilScoreGrant && sybilBucket !== null) {
    resolved.sybilBucket = sybilBucket;
  }

  if (profile.name) {
    const name = override ? override.displayName : user.displayName;
    if (name !== null) resolved.name = name;
  }
  if (profile.avatar) {
    // The curated avatarUrl is an external https URL (a custom link or a
    // Gravatar). A DETERMINISTIC avatar has no stored URL (avatarUrl is null),
    // so `picture` is simply OMITTED — we never synthesize a `data:` URI of the
    // generated identicon into the claim (it would bloat the token, and there
    // is nothing the user curated to disclose). The RP falls back to its own
    // default avatar. As before, the upstream User.image is never a source.
    const picture = override ? override.avatarUrl : user.avatarUrl;
    if (picture !== null) resolved.picture = picture;
  }

  return resolved;
}

// Fail-safe loader for the per-RP profile persona override, shared by both
// disclosure paths (and the consent preview). Returns null — the resolver
// then uses the legacy global fallback — in two cases that must NEVER 500 a
// login (the "login unaffected" invariant):
//   1. no profile field is granted (`wantsProfile` false): skip the query
//      entirely. The resolver gates both fields off regardless, and this drops
//      a hot-path lookup from the common badge-only / no-profile login.
//   2. the OidcProfileOverride table does not exist (Prisma P2021), e.g. a
//      deploy where this migration has not run yet: no override rows can exist,
//      so null is the correct, safe answer.
// ONLY P2021 is swallowed; every other error propagates exactly as the
// surrounding user/badge reads on these paths already do.
export async function loadProfileOverride(
  userId: string,
  clientId: string,
  wantsProfile: boolean,
): Promise<ProfileOverride | null> {
  if (!wantsProfile) return null;
  try {
    return await prisma.oidcProfileOverride.findUnique({
      where: { userId_clientId: { userId, clientId } },
      select: { displayName: true, avatarUrl: true },
    });
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2021") {
      return null;
    }
    throw err;
  }
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
    // `type`/`attributes`: needed to spot a `group-membership` badge and read its
    // `groupId` for the live revocation re-check below.
    select: {
      id: true,
      vcJwt: true,
      expiresAt: true,
      nullifierRef: true,
      type: true,
      attributes: true,
      // Revocation (§5.4): non-null on a revocable badge (group-membership today).
      // Drives per-RP status allocation + the credentialStatus stamp below.
      statusAnchor: true,
    },
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

        // Group membership is REVOCABLE via the live GroupMembership row (the
        // source of truth). Re-check it here at every disclosure: NO row
        // (member removed / group deleted) → OMIT this badge; a CHANGED role →
        // disclose the current role, overriding the value baked into the stored
        // VC at issuance. This governs what Minister MINTS. Invalidating a VC a
        // relying party ALREADY holds mid-lifetime is a separate credential-
        // status upgrade (the StatusList2021 seam noted on GroupMembership),
        // deliberately NOT a short-TTL forced re-disclosure. §2.6: this read is
        // outside any transaction.
        let claimSanitizer = sanitizeDisclosedClaims;
        if (row.type === GROUP_MEMBERSHIP_BADGE_TYPE) {
          const attrs =
            row.attributes !== null && typeof row.attributes === "object"
              ? (row.attributes as Record<string, unknown>)
              : {};
          const groupId = typeof attrs.groupId === "string" ? attrs.groupId : null;
          if (groupId === null) {
            // Malformed group badge (no groupId) — fail closed via the per-badge
            // catch below (omit + audit), never disclose an unpinnable claim.
            throw new Error("group-membership badge is missing its groupId attribute");
          }
          const membership = await prisma.groupMembership.findUnique({
            where: { groupId_userId: { groupId, userId } },
            select: { role: true },
          });
          if (!membership) {
            await safeAudit(userId, "group.membership_disclosure_omitted", {
              badgeId: row.id,
              clientId,
              groupId,
            });
            return null;
          }
          const liveRole = membership.role;
          claimSanitizer = (claims, vcType) => ({
            ...sanitizeDisclosedClaims(claims, vcType),
            role: liveRole,
          });
        }

        // Revocation (§5.2/§5.4): a revocable badge (statusAnchor set) gets a
        // per-RP (listId, bitIndex) handle allocated at FIRST disclosure to this
        // RP (idempotent thereafter) and a `credentialStatus` stamped onto the
        // re-minted VC. Per-RP by construction — the anchor never leaves Minister;
        // only the RP-scoped (list, index) is disclosed, so it is NOT a cross-RP
        // correlator (same discipline as the pairwise sub/jti). Allocation failure
        // FAILS CLOSED via the per-badge catch: a revocable badge we cannot make
        // revocable is omitted, never disclosed unrevocably. §2.6: this write is
        // outside any transaction.
        let credentialStatus: CredentialStatusEntry | undefined;
        if (row.statusAnchor) {
          const alloc = await allocateStatusEntry({
            statusAnchor: row.statusAnchor,
            clientId,
          });
          credentialStatus = credentialStatusFor(alloc.listId, alloc.bitIndex);
        }

        return await reMintVc(issuer, row.vcJwt, {
          subjectId,
          // Route through the Phase 7 seam (async) so the per-RP jti can be
          // staged into Signet; byte-identical to pairwiseJti in `local` mode.
          // §2.6: no open prisma.$transaction is held here.
          jti: await derivePairwiseJti(row.id, clientId),
          maxExpiresAt: row.expiresAt,
          disclosureTtlSeconds: BADGE_DISCLOSURE_TTL_SECONDS,
          // Strip any legacy claim the current schema has since removed (e.g. the
          // pre-Phase-1 oauth-account Sybil anchor) before re-signing. For a
          // group badge this ALSO overrides `role` with the live value.
          sanitizeClaims: claimSanitizer,
          ...(nullifier !== undefined ? { nullifier } : {}),
          ...(credentialStatus !== undefined ? { credentialStatus } : {}),
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
