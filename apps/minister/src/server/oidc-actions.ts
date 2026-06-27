"use server";

import { randomBytes } from "node:crypto";

import { redirect } from "next/navigation";
import { z } from "zod";

import { audit } from "@/lib/audit";
import { holderCountsByType } from "@/lib/anonymity-sets";
import { buildErrorRedirect, buildSuccessRedirect } from "@/lib/oidc-authorize";
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
    requestedBadges,
    await holderCountsForPolicy(request.policy),
  );
  const approvedBadgeIds = userBadges.map((b) => b.id);

  // The `profile` scope is retained in the RP-facing granted scopes if the
  // user approved either profile sub-claim; the exact name/avatar split is
  // persisted separately so the resolver can emit them independently.
  const approveProfile = parsed.data.approveName || parsed.data.approveAvatar;

  const code = newAuthCode();
  await prisma.oidcAuthorizationCode.create({
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

// Only fetch anonymity counts when a policy is present (they drive WHICH
// minimal set is chosen on a tie); flat flows skip the query entirely.
async function holderCountsForPolicy(policy: PolicyNode | null): Promise<Map<string, number>> {
  return policy ? holderCountsByType() : new Map();
}
