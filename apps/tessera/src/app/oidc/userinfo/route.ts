import { jwtVerify } from "jose";
import { NextResponse } from "next/server";

import { getIssuer } from "@/lib/issuer";
import { oidcIssuerUrl } from "@/lib/oidc-config";
import { prisma } from "@/lib/prisma";

// OIDC userinfo endpoint per OIDC Core 1.0 §5.3. RPs call this with the
// bearer access token to fetch user claims. We return the same shape an
// RP could have read from the ID token at /token — useful for clients
// that don't persist the id_token, or for re-fetching badge VCs.
//
// Bearer token validation: we verify the JWT signature, iss, aud, exp,
// and that `token_use = "access"` to refuse use of an ID token here.

export async function GET(request: Request) {
  const authz = request.headers.get("authorization") ?? "";
  if (!authz.toLowerCase().startsWith("bearer ")) {
    return unauthorized("invalid_token", "Bearer token required");
  }
  const token = authz.slice(7).trim();

  const issuer = await getIssuer();

  let payload;
  try {
    const verified = await jwtVerify(token, issuer.publicKey, {
      issuer: oidcIssuerUrl(),
      audience: oidcIssuerUrl(),
      algorithms: ["EdDSA"],
      typ: "at+jwt",
    });
    payload = verified.payload;
  } catch (err) {
    return unauthorized(
      "invalid_token",
      err instanceof Error ? err.message : "Token verification failed",
    );
  }

  if (payload.token_use !== "access") {
    return unauthorized("invalid_token", "Token is not an access token");
  }
  const userId = payload.tessera_uid;
  if (typeof userId !== "string") {
    return unauthorized("invalid_token", "Token missing principal claim");
  }

  const scopeStr = typeof payload.scope === "string" ? payload.scope : "";
  const scopes = scopeStr.split(/\s+/).filter(Boolean);

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      name: true,
      displayName: true,
      image: true,
      avatarUrl: true,
    },
  });
  if (!user) {
    return unauthorized("invalid_token", "user no longer exists");
  }

  const claims: Record<string, unknown> = {
    // OIDC requires `sub` in userinfo to match the ID token's `sub`.
    // We stored the pairwise on the JWT's `sub` claim.
    sub: payload.sub,
  };

  if (scopes.includes("profile")) {
    claims.name = user.displayName ?? user.name ?? null;
    claims.picture = user.avatarUrl ?? user.image ?? null;
  }

  // Any badge:<type> scope grants the consented VC subset for that
  // type. We re-look up via the most recent authorization code for this
  // user/client to find which badges they consented to. (Stage 9 should
  // move this lookup to a per-grant table; the auth code's TTL is
  // short, so this is best-effort and may be empty if /userinfo is hit
  // long after the code was consumed.)
  const badgeScopes = scopes.filter((s) => s.startsWith("badge:"));
  if (badgeScopes.length > 0) {
    const clientId =
      typeof payload.client_id === "string" ? payload.client_id : null;
    if (clientId) {
      const recent = await prisma.oidcAuthorizationCode.findFirst({
        where: { userId, clientId, consumedAt: { not: null } },
        orderBy: { expiresAt: "desc" },
        select: { approvedBadgeIds: true },
      });
      if (recent && recent.approvedBadgeIds.length > 0) {
        const badges = await prisma.badge.findMany({
          where: { userId, id: { in: recent.approvedBadgeIds } },
          select: { vcJwt: true },
        });
        const vcs = badges.map((b) => b.vcJwt);
        if (vcs.length > 0) claims.tessera_badges = vcs;
      }
    }
  }

  return NextResponse.json(claims, {
    headers: { "Cache-Control": "no-store" },
  });
}

function unauthorized(error: string, description: string): NextResponse {
  return NextResponse.json(
    { error, error_description: description },
    {
      status: 401,
      headers: {
        "Cache-Control": "no-store",
        "WWW-Authenticate": `Bearer error="${error}", error_description="${description}"`,
      },
    },
  );
}
