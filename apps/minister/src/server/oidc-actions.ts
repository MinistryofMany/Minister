"use server";

import { randomBytes } from "node:crypto";

import { redirect } from "next/navigation";
import { z } from "zod";

import { env } from "@/env";
import { audit } from "@/lib/audit";
import { holderCountsByType } from "@/lib/anonymity-sets";
import { getIssuer } from "@/lib/issuer";
import { buildErrorRedirect, buildSuccessRedirect } from "@/lib/oidc-authorize";
import { loadGrant, upsertGrant } from "@/lib/oidc-grants";
import { type PolicyNode, type UserBadge } from "@/lib/oidc-policy";
import { verifyOidcRequest } from "@/lib/oidc-request-token";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";
import {
  loadSybilScoringConfig,
  type ScorableBadge,
  type SybilScoringConfig,
} from "@/lib/sybil-config";
import { sybilScore } from "@/lib/sybil-score";
import { minimizeToPolicy, toPolicyUserBadge } from "@/server/oidc-consent-minimize";
import { normalizeProfileInput } from "@/server/profile-validation";
import { effectiveScopes } from "@/server/wizard-helpers";

const ApproveInput = z.object({
  requestToken: z.string().min(1),
  approvedBadgeIds: z.array(z.string().cuid()),
  // The `profile` scope is consented at claim granularity: the user may
  // approve their display name, their avatar, neither, or both.
  approveName: z.boolean(),
  approveAvatar: z.boolean(),
  // Whether the user approved disclosing their coarse anti-sybil bucket. The
  // scope must also have been requested (masked server-side below); the bucket
  // itself is computed here at consent, never trusted from the client.
  approveSybilScore: z.boolean(),
  // The raw inline-edit text for the per-RP persona (snapshot per app). Only
  // meaningful for a field whose toggle is on; validated + snapshotted into
  // OidcProfileOverride below. Optional so an old client or a name-only
  // approval need not send them.
  nameValue: z.string().optional(),
  avatarValue: z.string().optional(),
});

const DenyInput = z.object({
  requestToken: z.string().min(1),
});

// Random URL-safe authorization code. 32 bytes → 43 chars base64url,
// well above OIDC's "guessable by a brute-force attacker" threshold.
function newAuthCode(): string {
  return randomBytes(32).toString("base64url");
}

const CODE_TTL_SECONDS = 60; // per CLAUDE.md "Required security" §

export async function approveConsent(
  input: z.infer<typeof ApproveInput>,
): Promise<never | { error: string } | { redirectTo: string; anonAppId: string }> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    return { error: "Not signed in" };
  }

  const parsed = ApproveInput.safeParse(input);
  if (!parsed.success) {
    return { error: parsed.error.issues[0]?.message ?? "Invalid input" };
  }

  let request;
  try {
    request = await verifyOidcRequest(parsed.data.requestToken);
  } catch {
    return {
      error: "This consent request expired or has been tampered with. Reload and try again.",
    };
  }

  // The scope↔badge binding is SERVER-enforced here, not trusted from the
  // submitted approvedBadgeIds. A badge is disclosable only if it is BOTH
  // (a) owned by the current user AND (b) of a type the RP actually
  // requested via a `badge:<type>` scope. A tampered consent POST that
  // adds an owned-but-unrequested badge id therefore discloses nothing
  // the user wasn't shown — "private by default", enforced authoritatively.
  const requestedBadgeTypes = new Set(
    request.scopes.filter((s) => s.startsWith("badge:")).map((s) => s.slice("badge:".length)),
  );
  // Load id+type (+ attributes/issuedAt for policy evaluation) for the
  // submitted ids, scoped to the owning user (the ownership drop). Then
  // keep only those whose type was requested.
  const ownedBadges = await loadBadgesForUser(session.user.id, parsed.data.approvedBadgeIds);
  const requestedBadges = ownedBadges.filter((b) => requestedBadgeTypes.has(b.type));

  // Phase-3 transparency: fold the already-proven, room-relevant badge
  // INSTANCES into the candidate set BEFORE minimization, so the user need
  // not re-select what they have already proven to this client. The locked
  // checkboxes in the consent UI are an affordance only — the server
  // independently forces these in so a tampered POST that *unticks* a
  // locked box still includes it.
  //
  // Audit W1: the fold force-includes only the SPECIFIC instances the user
  // previously disclosed (grant.badgeIds), NOT every instance of a granted
  // TYPE. loadBadgesForUser scopes to the owning user and yields the type,
  // so a since-deleted granted id drops out; the type filter keeps this to
  // the room's requested types (a granted instance the room does NOT request
  // is neither loaded nor disclosed — per-room minimal disclosure, F-2(a)).
  // This closes the flat-flow leak where a sibling instance of a granted
  // type (e.g. a second oauth-account the user never chose) rode in.
  //
  // This does NOT widen disclosure: minimizeToPolicy below STILL trims the
  // union (submitted ∪ granted-relevant) to one minimal satisfying set when a
  // policy is present. On the flat / no-policy path minimize is the identity,
  // so the id-scoped fold is itself the bound — it can only re-include
  // instances the user already proved.
  const grant = await loadGrant(session.user.id, request.clientId);
  const grantedBadges =
    grant.badgeIds.length > 0
      ? (await loadBadgesForUser(session.user.id, grant.badgeIds)).filter((b) =>
          requestedBadgeTypes.has(b.type),
        )
      : [];
  const candidateBadges = unionBadgesById(requestedBadges, grantedBadges);

  // When the RP sent a structured policy, STRICTLY minimize the disclosure
  // server-side: trim the submitted set down to ONE minimal satisfying set
  // (the most-anonymous one). This is the authoritative over-disclosure
  // guard (Phase-2 design F-5/§8.3) — a tampered POST that ticks two
  // satisfying anyOf branches, or extra badges past `atLeast n`, can never
  // reach minister_badges as more than one minimal set. The UI radio/pick-n
  // is convenience; this is the enforcement. If the submission doesn't
  // satisfy the policy, the minimal set is empty (disclose nothing extra) —
  // Discreetly's gate is the admission authority and will deny.
  //
  // AUDIT L-2 (documented, deferred): when no policy is present (the param
  // was absent or stripped on the front channel) minimizeToPolicy is the
  // identity and consent falls back to the flat per-scope flow. That flow
  // is already bounded (it discloses only owned ∩ requested badges) and the
  // structured policy path is opt-in / default-off, so a stripped policy
  // cannot widen disclosure beyond the flat menu. Optional future
  // hardening: bind a signed "policy expected" signal so a stripped policy
  // is detectable rather than silently downgraded. Not implemented now.
  const userBadges = minimizeToPolicy(
    request.policy,
    candidateBadges,
    await holderCountsForPolicy(request.policy),
  );
  const approvedBadgeIds = userBadges.map((b) => b.id);

  // H-1 (authoritative gate): profile disclosure is only ever permitted when
  // the RP actually requested the `profile` scope. The consent-screen re-login
  // pre-check seeds approveName/approveAvatar from the durable grant, which can
  // arrive true on a badge-only re-login where the profile card is never even
  // rendered; without this server-side mask a client that dropped `profile`
  // would still get name/avatar re-disclosed off the stale grant. Mask BOTH
  // booleans HERE, before ANY persistence, so the auth code, the grant, the
  // audit fields, and the override upsert all see the same masked truth.
  const profileRequested = request.scopes.includes("profile");
  const approveName = profileRequested && parsed.data.approveName;
  const approveAvatar = profileRequested && parsed.data.approveAvatar;

  // The `profile` scope is retained in the RP-facing granted scopes if the
  // user approved either profile sub-claim; the exact name/avatar split is
  // persisted separately so the resolver can emit them independently.
  const approveProfile = approveName || approveAvatar;

  // Anti-sybil bucket disclosure (mirrors the profile mask). The scope gates
  // it authoritatively: a client that never requested `sybil-score` can never
  // get a bucket even if a tampered POST sets approveSybilScore true.
  const sybilScoreRequested = request.scopes.includes("sybil-score");
  const approveSybilScore = sybilScoreRequested && parsed.data.approveSybilScore;

  // Per-RP profile persona (snapshot per app). Validate the inline-edit text
  // for whichever field(s) were approved this round, using the same validator
  // the global profile editor uses (it validates BOTH fields together and
  // throws on invalid — e.g. a non-https avatar URL). Only an approved field's
  // raw value is fed in; an unapproved field passes "" (normalizes to null) so
  // a stale/malformed value for a field the user didn't tick can't block the
  // approval. Validation errors are RETURNED (not thrown) so the consent
  // screen renders them inline, same as every other error shape here.
  let overrideName: string | null = null;
  let overrideAvatar: string | null = null;
  try {
    const normalized = normalizeProfileInput({
      displayName: approveName ? (parsed.data.nameValue ?? "") : "",
      avatarUrl: approveAvatar ? (parsed.data.avatarValue ?? "") : "",
    });
    overrideName = normalized.displayName;
    overrideAvatar = normalized.avatarUrl;
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Invalid profile value" };
  }

  // Write only the field(s) approved this round; leave the other field of the
  // override untouched (a prior persona for it survives an approval that only
  // re-ticks the sibling field).
  const overrideWrite: { displayName?: string | null; avatarUrl?: string | null } = {};
  if (approveName) overrideWrite.displayName = overrideName;
  if (approveAvatar) overrideWrite.avatarUrl = overrideAvatar;

  // Compute the coarse anti-sybil bucket EXACTLY ONCE, here at consent, and
  // snapshot it onto the auth code. It is NEVER recomputed at /token or
  // /userinfo — those read the stamped value back verbatim. FAIL-CLOSED-OMIT:
  // any error computing the bucket (badge load, config load, issuer load)
  // leaves `sybilBucket` null so the resolver omits the claim, audits the
  // omission, and lets the login proceed unaffected. The scorer itself is pure
  // and never throws; only the surrounding I/O can. Bucket 0 is a real value —
  // null strictly means "not computed / omitted", distinct from a computed 0.
  let sybilBucket: number | null = null;
  if (approveSybilScore) {
    try {
      const [scorableBadges, config, issuer] = await Promise.all([
        loadScorableBadges(session.user.id),
        loadSybilScoringConfig(),
        getIssuer(),
      ]);
      // Defense in depth: a silently-empty/partial config (tables present but
      // unseeded, so no weights and/or missing cutoffs) does NOT throw in the
      // loader, but scoring it would emit a WRONG (too-low) bucket as a real
      // disclosed value. Treat a degenerate config exactly like a thrown compute
      // error: omit + audit, login unaffected.
      if (isDegenerateSybilConfig(config)) {
        sybilBucket = null;
        try {
          await audit(session.user.id, "oidc.sybil_score_omitted", {
            clientId: request.clientId,
            reason: "degenerate-config",
          });
        } catch (auditErr) {
          console.error("[oidc-actions] failed to write sybil omit audit:", auditErr);
        }
      } else {
        sybilBucket = sybilScore(scorableBadges, config, {
          now: Date.now(),
          nativeIssuerDid: issuer.did,
        }).bucket;
      }
    } catch (err) {
      sybilBucket = null;
      const reason = err instanceof Error ? err.message : String(err);
      // audit() is a bare prisma write; guard it so an audit-write failure in a
      // degraded DB can never itself break the login this omit path protects.
      try {
        await audit(session.user.id, "oidc.sybil_score_omitted", {
          clientId: request.clientId,
          reason,
        });
      } catch (auditErr) {
        console.error("[oidc-actions] failed to write sybil omit audit:", auditErr);
      }
    }
  }

  const code = newAuthCode();
  // The types actually disclosed this round (the minimized set). These — not
  // the whole locked set — are what we record into the grant, so the grant
  // reflects what was truly sent on the wire. badgeTypes accumulate by union
  // inside upsertGrant ("ever proven to this platform").
  const disclosedTypes = [...new Set(userBadges.map((b) => b.type))];
  // Create the auth code and accumulate the grant atomically: a failed
  // consent leaves no orphan grant, and the grant is never recorded for a
  // disclosure that did not mint a code.
  await prisma.$transaction(async (tx) => {
    await tx.oidcAuthorizationCode.create({
      data: {
        code,
        clientId: request.clientId,
        userId: session.user.id,
        redirectUri: request.redirectUri,
        // Effective granted scopes: openid always; profile only if the
        // user approved at least one profile sub-claim; each badge:<type>
        // scope kept only if at least one badge of that type was disclosed.
        scopes: effectiveScopes(request.scopes, {
          approveProfile,
          approveSybilScore,
          approvedBadgeIds,
          userBadges,
        }),
        approvedBadgeIds,
        // Granular profile grant. Masked to false unless `profile` was
        // requested (H-1), so a badge-only re-login never persists a profile
        // grant off the stale pre-check.
        profileName: approveName,
        profileAvatar: approveAvatar,
        // Anti-sybil snapshot: the grant boolean + the bucket computed once
        // above. Masked to false unless `sybil-score` was requested. The bucket
        // is null when omitted (declined / not requested / compute failed).
        sybilScore: approveSybilScore,
        sybilBucket,
        // Echoed back in id_token at /token time — see CLAUDE.md.
        nonce: request.nonce,
        codeChallenge: request.codeChallenge,
        codeChallengeMethod: request.codeChallengeMethod,
        expiresAt: new Date(Date.now() + CODE_TTL_SECONDS * 1000),
      },
    });
    await upsertGrant(tx, {
      userId: session.user.id,
      clientId: request.clientId,
      badgeTypes: disclosedTypes,
      // Record the specific instances actually disclosed this round (the
      // minimized set), so the next visit's fold force-includes exactly
      // these — not every instance of the type (audit W1).
      badgeIds: approvedBadgeIds,
      profileName: approveName,
      profileAvatar: approveAvatar,
      // Record that the account-strength bucket was disclosed to this client,
      // so the next visit's consent pre-checks it (mirrors profile). Union-OR
      // accumulated inside upsertGrant.
      sybilScore: approveSybilScore,
    });
    // Snapshot the per-RP profile persona ATOMICALLY with the grant/auth-code:
    // a failed consent must not leave a persona for an RP the user didn't
    // actually authorize this round. Only touched when a profile field was
    // approved (masked by profileRequested); the update payload sets only the
    // approved field(s), so a name-only approval leaves a prior avatar intact.
    if (approveName || approveAvatar) {
      await tx.oidcProfileOverride.upsert({
        where: {
          userId_clientId: { userId: session.user.id, clientId: request.clientId },
        },
        create: {
          userId: session.user.id,
          clientId: request.clientId,
          ...overrideWrite,
        },
        update: overrideWrite,
      });
    }
  });

  await audit(session.user.id, "oidc.consent_approved", {
    clientId: request.clientId,
    requestedScopes: request.scopes,
    disclosedBadgeIds: approvedBadgeIds,
    disclosedProfileName: approveName,
    disclosedProfileAvatar: approveAvatar,
    disclosedSybilScore: approveSybilScore,
    sybilBucket,
  });

  const successUrl = buildSuccessRedirect(request.redirectUri, code, request.state);

  // Anon-identity fragment delivery (spec §8.2). For an anon-enabled client
  // (the feature flag is on AND the client carries an anonAppId), the final hop
  // becomes CLIENT-driven: RETURN the same code+state success URL so the consent
  // client can append the per-app-secret fragment — which the server never
  // holds (§2) — before navigating. The authorization code is UNCHANGED: still
  // PKCE(S256)- and state-bound, single-use, 60s TTL, created transiently in the
  // transaction above and never re-issued here. A non-anon client, or the flag
  // off, keeps the existing server-side redirect byte-for-byte (§8.3), so the
  // whole feature is inert until both conditions hold.
  if (env.ANON_IDENTITY_ENABLED) {
    const client = await prisma.oidcClient.findUnique({
      where: { clientId: request.clientId },
      select: { anonAppId: true },
    });
    if (client?.anonAppId) {
      return { redirectTo: successUrl, anonAppId: client.anonAppId };
    }
  }

  redirect(successUrl);
}

export async function denyConsent(
  input: z.infer<typeof DenyInput>,
): Promise<never | { error: string }> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    return { error: "Not signed in" };
  }

  const parsed = DenyInput.safeParse(input);
  if (!parsed.success) return { error: "Invalid input" };

  let request;
  try {
    request = await verifyOidcRequest(parsed.data.requestToken);
  } catch {
    return { error: "Consent request expired" };
  }

  await audit(session.user.id, "oidc.consent_denied", {
    clientId: request.clientId,
    scopes: request.scopes,
  });

  redirect(
    buildErrorRedirect(
      request.redirectUri,
      "access_denied",
      "The user declined to share data",
      request.state,
    ),
  );
}

// Load id/type/attributes/issuedAt for the submitted ids, scoped to the
// owning user. attributes + issuedAt are needed to evaluate a structured
// policy's `where`/`maxAgeDays` leaves during server-side minimization.
// issuedAt is COARSENED to the issuance-month start inside toPolicyUserBadge
// so consent-side maxAgeDays agrees with the RP's coarse gate.
async function loadBadgesForUser(userId: string, badgeIds: string[]): Promise<UserBadge[]> {
  if (badgeIds.length === 0) return [];
  const rows = await prisma.badge.findMany({
    where: { userId, id: { in: badgeIds } },
    select: { id: true, type: true, attributes: true, issuedAt: true },
  });
  return rows.map(toPolicyUserBadge);
}

// A scoring config is DEGENERATE (unsafe to score) when it carries no actual
// weight entry, or its bucket cutoffs are not all finite numbers. Either shape
// would let the pure scorer emit a real-but-wrong (too-low) bucket instead of an
// omission. loadSybilScoringConfig throws on a missing SybilBucketConfig
// singleton, but an empty/partially-deleted BadgeWeight table returns a valid
// object with an empty weights map — this catches that (design spec §4, fail
// closed).
function isDegenerateSybilConfig(config: SybilScoringConfig): boolean {
  let hasWeight = false;
  for (const byQualifier of config.weights.values()) {
    if (byQualifier.size > 0) {
      hasWeight = true;
      break;
    }
  }
  if (!hasWeight) return true;

  const c = config.cutoffs;
  return (
    !Number.isFinite(c.b1) ||
    !Number.isFinite(c.b2) ||
    !Number.isFinite(c.b3) ||
    !Number.isFinite(c.b4) ||
    !Number.isFinite(c.b3Cats) ||
    !Number.isFinite(c.b4Cats)
  );
}

// Load ALL of a user's badges in the shape the pure sybil scorer consumes
// (`type`, denormalized `attributes`, `expiresAt`, `issuer`). The scorer itself
// applies the native-issuer + unexpired hygiene, so this is deliberately an
// unfiltered read of every held badge. Distinct from loadBadgesForUser (which
// is scoped to submitted ids and shaped for policy minimization).
async function loadScorableBadges(userId: string): Promise<ScorableBadge[]> {
  const rows = await prisma.badge.findMany({
    where: { userId },
    select: { type: true, attributes: true, expiresAt: true, issuer: true },
  });
  return rows.map((row) => ({
    type: row.type,
    attributes: row.attributes as Record<string, unknown>,
    expiresAt: row.expiresAt,
    issuer: row.issuer,
  }));
}

// Union two badge lists by id, preserving the first occurrence. Order is
// stable (a then b) so minimizeToPolicy's order-sensitive tie-breaks stay
// deterministic.
function unionBadgesById(a: UserBadge[], b: UserBadge[]): UserBadge[] {
  const seen = new Set(a.map((x) => x.id));
  return [...a, ...b.filter((x) => !seen.has(x.id))];
}

// Only fetch anonymity counts when a policy is present (they drive WHICH
// minimal set is chosen on a tie); flat flows skip the query entirely.
async function holderCountsForPolicy(policy: PolicyNode | null): Promise<Map<string, number>> {
  return policy ? holderCountsByType() : new Map();
}
