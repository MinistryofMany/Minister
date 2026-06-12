import { jwtVerify } from "jose";
import { NextResponse } from "next/server";

import { getIssuer } from "@/lib/issuer";
import { oidcIssuerUrl } from "@/lib/oidc-config";
import { prisma } from "@/lib/prisma";
import { clientIpFrom, oidcUserinfoLimiter } from "@/lib/rate-limit";

// OIDC userinfo endpoint per OIDC Core 1.0 §5.3. RPs call this with the
// bearer access token to fetch user claims; we return the same shape an
// RP could have read from the ID token at /token.
//
// Bearer token validation:
//   1. Verify JWT signature, iss, aud, exp, token_use = "access".
//   2. Look up the matching OidcAccessToken row by `jti`. The row
//      carries the userId and approvedBadgeIds — the JWT itself is
//      privacy-clean (no raw userId), so a stolen-and-decoded token
//      can't leak that data either.
//   3. Reject if the row is revoked or expired (defense beyond JWT
//      `exp` — a server-side revoke is supposed to take immediate
//      effect, not wait for token expiration).

export async function GET(request: Request) {
  const limit = oidcUserinfoLimiter.check(clientIpFrom(request.headers));
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "temporarily_unavailable" },
      {
        status: 429,
        headers: { "Retry-After": String(limit.retryAfterSeconds) },
      },
    );
  }

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
  const jti = payload.jti;
  if (typeof jti !== "string") {
    return unauthorized("invalid_token", "Token missing jti");
  }

  const row = await prisma.oidcAccessToken.findUnique({
    where: { jti },
    include: {
      user: {
        select: {
          id: true,
          name: true,
          displayName: true,
          image: true,
          avatarUrl: true,
        },
      },
    },
  });
  if (!row) {
    return unauthorized("invalid_token", "Token is not recognized");
  }
  if (row.revokedAt) {
    return unauthorized("invalid_token", "Token has been revoked");
  }
  if (row.expiresAt < new Date()) {
    return unauthorized("invalid_token", "Token has expired");
  }

  const scopeStr = typeof payload.scope === "string" ? payload.scope : "";
  const scopes = scopeStr.split(/\s+/).filter(Boolean);

  const claims: Record<string, unknown> = {
    // OIDC requires `sub` in userinfo to match the ID token's `sub`.
    // The pairwise pseudonymous value lives on the JWT's `sub` claim.
    sub: payload.sub,
  };

  if (scopes.includes("profile")) {
    claims.name = row.user.displayName ?? row.user.name ?? null;
    claims.picture = row.user.avatarUrl ?? row.user.image ?? null;
  }

  if (row.approvedBadgeIds.length > 0) {
    const badges = await prisma.badge.findMany({
      where: { userId: row.userId, id: { in: row.approvedBadgeIds } },
      select: { vcJwt: true },
    });
    const vcs = badges.map((b) => b.vcJwt);
    if (vcs.length > 0) claims.tessera_badges = vcs;
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
