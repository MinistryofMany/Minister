"use server";

import { randomBytes } from "node:crypto";

import { redirect } from "next/navigation";
import { z } from "zod";

import { audit } from "@/lib/audit";
import {
  buildErrorRedirect,
  buildSuccessRedirect,
} from "@/lib/oidc-authorize";
import { verifyOidcRequest } from "@/lib/oidc-request-token";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";

const ApproveInput = z.object({
  requestToken: z.string().min(1),
  approvedBadgeIds: z.array(z.string().cuid()),
  approveProfile: z.boolean(),
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
      error:
        "This consent request expired or has been tampered with. Reload and try again.",
    };
  }

  // approvedBadgeIds must all belong to the current user. Anything not
  // owned is silently dropped — the badges the user actually claimed
  // are the ones we'll disclose.
  const ownedIds = new Set(
    (
      await prisma.badge.findMany({
        where: { userId: session.user.id, id: { in: parsed.data.approvedBadgeIds } },
        select: { id: true },
      })
    ).map((b) => b.id),
  );
  const approvedBadgeIds = parsed.data.approvedBadgeIds.filter((id) =>
    ownedIds.has(id),
  );

  const code = newAuthCode();
  await prisma.oidcAuthorizationCode.create({
    data: {
      code,
      clientId: request.clientId,
      userId: session.user.id,
      redirectUri: request.redirectUri,
      // Effective granted scopes: openid always; profile only if the
      // user said yes; each badge:<type> scope kept only if at least
      // one badge was disclosed for it.
      scopes: effectiveScopes(request.scopes, {
        approveProfile: parsed.data.approveProfile,
        approvedBadgeIds,
        userBadges: await loadBadgeTypesForUser(session.user.id, approvedBadgeIds),
      }),
      approvedBadgeIds,
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
    disclosedProfile: parsed.data.approveProfile,
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

// Reduce the requested scope set to what the user actually agreed to
// disclose. Drops badge:<type> scopes the user gave nothing for, and
// drops profile if they didn't tick the toggle.
function effectiveScopes(
  requestedScopes: string[],
  args: {
    approveProfile: boolean;
    approvedBadgeIds: string[];
    userBadges: Array<{ id: string; type: string }>;
  },
): string[] {
  const out: string[] = [];
  for (const scope of requestedScopes) {
    if (scope === "openid") {
      out.push(scope);
      continue;
    }
    if (scope === "profile") {
      if (args.approveProfile) out.push(scope);
      continue;
    }
    if (scope.startsWith("badge:")) {
      const type = scope.slice("badge:".length);
      const anyApproved = args.userBadges.some(
        (b) => b.type === type && args.approvedBadgeIds.includes(b.id),
      );
      if (anyApproved) out.push(scope);
      continue;
    }
    // Unknown scopes shouldn't reach here (validation rejected them),
    // but be conservative and drop them.
  }
  return out;
}

async function loadBadgeTypesForUser(
  userId: string,
  badgeIds: string[],
): Promise<Array<{ id: string; type: string }>> {
  if (badgeIds.length === 0) return [];
  return prisma.badge.findMany({
    where: { userId, id: { in: badgeIds } },
    select: { id: true, type: true },
  });
}
