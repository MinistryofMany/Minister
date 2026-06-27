"use server";

import { randomBytes } from "node:crypto";

import { redirect } from "next/navigation";
import { z } from "zod";

import { audit } from "@/lib/audit";
import { holderCountsByType } from "@/lib/anonymity-sets";
import { buildErrorRedirect, buildSuccessRedirect } from "@/lib/oidc-authorize";
import { grantedRelevantTypes, loadGrant, upsertGrant } from "@/lib/oidc-grants";
import { type PolicyNode, type UserBadge } from "@/lib/oidc-policy";
import { verifyOidcRequest } from "@/lib/oidc-request-token";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";
import { coerceAttrs, minimizeToPolicy } from "@/server/oidc-consent-minimize";
import { effectiveScopes } from "@/server/wizard-helpers";

const ApproveInput = z.object({
  requestToken: z.string().min(1),
  approvedBadgeIds: z.array(z.string().cuid()),
  // The `profile` scope is consented at claim granularity: the user may
  // approve their display name, their avatar, neither, or both.
  approveName: z.boolean(),
  approveAvatar: z.boolean(),
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
): Promise<never | { error: string }> {
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

  // Phase-3 transparency: fold the already-granted-AND-room-relevant types
  // into the candidate set BEFORE minimization, so the user need not
  // re-select what they have already proven to this client. The locked
  // checkboxes in the consent UI are an affordance only — the server
  // independently forces these in so a tampered POST that *unticks* a
  // locked box still includes it. The locked set is scoped to types the
  // room actually requested (grantedRelevantTypes) AND of which the user
  // still holds a badge — a granted type the room does NOT request is
  // neither loaded nor disclosed (per-room minimal disclosure, F-2(a)).
  //
  // This does NOT widen disclosure: minimizeToPolicy below STILL trims the
  // union (submitted ∪ granted-relevant) to one minimal satisfying set, so
  // a granted type the room's minimal set does not need is trimmed away
  // (shown in the locked section for transparency, but not sent on the
  // wire unless this room needs it).
  const grant = await loadGrant(session.user.id, request.clientId);
  const grantedRelevant = new Set(grantedRelevantTypes(grant, requestedBadgeTypes));
  const grantedBadges =
    grantedRelevant.size > 0
      ? await loadBadgesOfTypesForUser(session.user.id, grantedRelevant)
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

  // The `profile` scope is retained in the RP-facing granted scopes if the
  // user approved either profile sub-claim; the exact name/avatar split is
  // persisted separately so the resolver can emit them independently.
  const approveProfile = parsed.data.approveName || parsed.data.approveAvatar;

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
          approvedBadgeIds,
          userBadges,
        }),
        approvedBadgeIds,
        // Granular profile grant. Only meaningful when `profile` was requested
        // and survives effectiveScopes; harmless (false) otherwise.
        profileName: parsed.data.approveName,
        profileAvatar: parsed.data.approveAvatar,
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
      profileName: parsed.data.approveName,
      profileAvatar: parsed.data.approveAvatar,
    });
  });

  await audit(session.user.id, "oidc.consent_approved", {
    clientId: request.clientId,
    requestedScopes: request.scopes,
    disclosedBadgeIds: approvedBadgeIds,
    disclosedProfileName: parsed.data.approveName,
    disclosedProfileAvatar: parsed.data.approveAvatar,
  });

  redirect(buildSuccessRedirect(request.redirectUri, code, request.state));
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
async function loadBadgesForUser(userId: string, badgeIds: string[]): Promise<UserBadge[]> {
  if (badgeIds.length === 0) return [];
  const rows = await prisma.badge.findMany({
    where: { userId, id: { in: badgeIds } },
    select: { id: true, type: true, attributes: true, issuedAt: true },
  });
  return rows.map((r) => ({
    id: r.id,
    type: r.type,
    attributes: coerceAttrs(r.attributes),
    issuedAt: Math.floor(r.issuedAt.getTime() / 1000),
  }));
}

// Load the user's owned badges whose TYPE is in `types`, regardless of
// whether the consent POST submitted them. Used to force the already-
// granted, room-relevant set into the candidate disclosure independently of
// the (untrusted) submitted ids — so a tampered POST that unticks a locked
// box still includes it. Same UserBadge shape as loadBadgesForUser so the
// two sets union cleanly before minimization.
async function loadBadgesOfTypesForUser(
  userId: string,
  types: ReadonlySet<string>,
): Promise<UserBadge[]> {
  if (types.size === 0) return [];
  const rows = await prisma.badge.findMany({
    where: { userId, type: { in: [...types] } },
    select: { id: true, type: true, attributes: true, issuedAt: true },
  });
  return rows.map((r) => ({
    id: r.id,
    type: r.type,
    attributes: coerceAttrs(r.attributes),
    issuedAt: Math.floor(r.issuedAt.getTime() / 1000),
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
