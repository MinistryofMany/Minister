import { randomBytes } from "node:crypto";

import { NextResponse } from "next/server";

import { getIssuer } from "@/lib/issuer";
import { findClient, verifyClientSecret } from "@/lib/oidc-clients";
import {
  ACCESS_TOKEN_TTL,
  mintAccessToken,
  mintIdToken,
  pairwiseSub,
  verifyPkceS256,
} from "@/lib/oidc-tokens";
import { prisma } from "@/lib/prisma";
import { audit } from "@/lib/audit";
import { clientIpFrom, oidcTokenLimiter } from "@/lib/rate-limit";

// 429 with Retry-After. `temporarily_unavailable` is the closest
// RFC 6749 §5.2 error code; clients should back off and retry.
function rateLimited(retryAfterSeconds: number) {
  return NextResponse.json(
    {
      error: "temporarily_unavailable",
      error_description: "Rate limit exceeded; retry later",
    },
    {
      status: 429,
      headers: { "Retry-After": String(retryAfterSeconds) },
    },
  );
}

// OIDC token endpoint per RFC 6749 §3.2 + OIDC Core §3.1.3.
//
// Accepts application/x-www-form-urlencoded. Client auth either via
// HTTP Basic (RFC 6749 §2.3.1) or via client_id/client_secret in the
// form body. Public (PKCE-only) clients send just client_id.
//
// All errors return JSON with `error` + `error_description` per RFC.
// 400 for protocol errors, 401 for invalid_client (with WWW-Authenticate
// when Basic was used).
export async function POST(request: Request) {
  const limit = oidcTokenLimiter.check(clientIpFrom(request.headers));
  if (!limit.allowed) {
    return rateLimited(limit.retryAfterSeconds);
  }

  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return tokenError("invalid_request", "Content-Type must be application/x-www-form-urlencoded");
  }

  const body = new URLSearchParams(await request.text());

  if (body.get("grant_type") !== "authorization_code") {
    return tokenError(
      "unsupported_grant_type",
      "Only grant_type=authorization_code is supported",
    );
  }

  const code = body.get("code");
  const redirectUri = body.get("redirect_uri");
  const codeVerifier = body.get("code_verifier");

  if (!code || !redirectUri || !codeVerifier) {
    return tokenError("invalid_request", "code, redirect_uri and code_verifier are required");
  }

  // ---------------------------------------------------------------------------
  // Client authentication
  // ---------------------------------------------------------------------------
  const clientCreds = readClientCredentials(request, body);
  if (!clientCreds.clientId) {
    return tokenError("invalid_request", "client_id is required");
  }

  const client = await findClient(clientCreds.clientId);
  if (!client) {
    return clientError("Unknown client", clientCreds.fromBasic);
  }

  if (client.clientSecretHash) {
    // Confidential client. client_secret is required.
    if (!clientCreds.clientSecret) {
      return clientError("client_secret required", clientCreds.fromBasic);
    }
    const ok = await verifyClientSecret(
      clientCreds.clientSecret,
      client.clientSecretHash,
    );
    if (!ok) {
      return clientError("Bad client_secret", clientCreds.fromBasic);
    }
  }

  // ---------------------------------------------------------------------------
  // Authorization code consumption (single-use; race-condition-safe)
  // ---------------------------------------------------------------------------
  const consumed = await prisma.oidcAuthorizationCode.updateMany({
    where: { code, consumedAt: null },
    data: { consumedAt: new Date() },
  });
  if (consumed.count === 0) {
    // Either the code never existed or it was already consumed. Either
    // way, the right RFC error is invalid_grant. We also audit-log the
    // failure in case it's a replay attack.
    await audit(null, "oidc.token.invalid_grant", {
      clientId: client.clientId,
      reason: "code_missing_or_already_consumed",
    });
    return tokenError("invalid_grant", "code is invalid or already used");
  }
  const stored = await prisma.oidcAuthorizationCode.findUnique({
    where: { code },
  });
  if (!stored) {
    // Lost a race against another consumer or row was deleted; refuse.
    return tokenError("invalid_grant", "code is invalid");
  }

  if (stored.expiresAt < new Date()) {
    return tokenError("invalid_grant", "code is expired");
  }
  if (stored.clientId !== client.clientId) {
    return tokenError("invalid_grant", "code was issued to a different client");
  }
  if (stored.redirectUri !== redirectUri) {
    return tokenError("invalid_grant", "redirect_uri does not match the one used at /authorize");
  }
  if (stored.codeChallengeMethod !== "S256") {
    return tokenError("invalid_grant", "unsupported code_challenge_method");
  }
  if (!verifyPkceS256(codeVerifier, stored.codeChallenge)) {
    return tokenError("invalid_grant", "PKCE verification failed");
  }

  // ---------------------------------------------------------------------------
  // Mint tokens
  // ---------------------------------------------------------------------------
  const user = await prisma.user.findUnique({
    where: { id: stored.userId },
    select: {
      id: true,
      name: true,
      displayName: true,
      image: true,
      avatarUrl: true,
    },
  });
  if (!user) {
    return tokenError("invalid_grant", "user no longer exists");
  }

  const sub = pairwiseSub(user.id, client.clientId);
  const issuer = await getIssuer();

  const minister_badges = await loadApprovedBadgeJwts(
    user.id,
    stored.approvedBadgeIds,
  );

  const idToken = await mintIdToken(issuer, {
    sub,
    aud: client.clientId,
    // Echoed verbatim from the /authorize nonce per OIDC Core §3.1.3.7.
    nonce: stored.nonce,
    scopes: stored.scopes,
    name: user.displayName ?? user.name ?? null,
    picture: user.avatarUrl ?? user.image ?? null,
    minister_badges: minister_badges.length > 0 ? minister_badges : undefined,
  });

  // jti links the access JWT to a server-side OidcAccessToken row.
  // /userinfo resolves user identity via the row, so the JWT itself
  // carries no raw user id — the pairwise `sub` is the only
  // user-shaped value an RP that decodes the token sees.
  const jti = randomBytes(24).toString("base64url");
  const accessTokenExpiresAt = new Date(Date.now() + ACCESS_TOKEN_TTL * 1000);
  await prisma.oidcAccessToken.create({
    data: {
      jti,
      userId: user.id,
      clientId: client.clientId,
      scopes: stored.scopes,
      approvedBadgeIds: stored.approvedBadgeIds,
      expiresAt: accessTokenExpiresAt,
    },
  });
  const accessToken = await mintAccessToken(issuer, {
    jti,
    sub,
    clientId: client.clientId,
    scopes: stored.scopes,
  });

  await audit(user.id, "oidc.token_issued", {
    clientId: client.clientId,
    scopes: stored.scopes,
    badgeCount: minister_badges.length,
  });

  return NextResponse.json(
    {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL,
      id_token: idToken,
      scope: stored.scopes.join(" "),
    },
    {
      headers: {
        "Cache-Control": "no-store",
        Pragma: "no-cache",
      },
    },
  );
}

interface ClientCreds {
  clientId: string | null;
  clientSecret: string | null;
  fromBasic: boolean;
}

function readClientCredentials(
  request: Request,
  body: URLSearchParams,
): ClientCreds {
  const authz = request.headers.get("authorization");
  if (authz?.startsWith("Basic ")) {
    try {
      const decoded = Buffer.from(authz.slice(6), "base64").toString("utf8");
      const idx = decoded.indexOf(":");
      if (idx >= 0) {
        return {
          clientId: decodeURIComponent(decoded.slice(0, idx)),
          clientSecret: decodeURIComponent(decoded.slice(idx + 1)),
          fromBasic: true,
        };
      }
    } catch {
      // fall through to form
    }
  }
  return {
    clientId: body.get("client_id"),
    clientSecret: body.get("client_secret"),
    fromBasic: false,
  };
}

async function loadApprovedBadgeJwts(
  userId: string,
  badgeIds: string[],
): Promise<string[]> {
  if (badgeIds.length === 0) return [];
  const rows = await prisma.badge.findMany({
    where: { userId, id: { in: badgeIds } },
    select: { vcJwt: true },
  });
  return rows.map((r) => r.vcJwt);
}

function tokenError(
  error: string,
  description: string,
  status = 400,
): NextResponse {
  return NextResponse.json(
    { error, error_description: description },
    { status, headers: { "Cache-Control": "no-store" } },
  );
}

function clientError(description: string, fromBasic: boolean): NextResponse {
  const headers: Record<string, string> = { "Cache-Control": "no-store" };
  if (fromBasic) headers["WWW-Authenticate"] = 'Basic realm="oidc"';
  return NextResponse.json(
    { error: "invalid_client", error_description: description },
    { status: 401, headers },
  );
}
