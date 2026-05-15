import { createHash, createHmac } from "node:crypto";

import { SignJWT } from "jose";

import type { Issuer } from "@tessera/vc";

import { oidcIssuerUrl } from "@/lib/oidc-config";

// Token TTLs. CLAUDE.md "Required security" pins auth codes at 60s; the
// token TTLs are project-level decisions:
//   id_token : 10 minutes — RPs are expected to verify on receipt and
//              then derive their own session. They don't poll.
//   access_token: 1 hour — used to call /oidc/userinfo. No refresh in
//              v1; the RP re-initiates the OIDC flow if it needs more.
const ID_TOKEN_TTL_SECONDS = 10 * 60;
const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;

// Pairwise pseudonymous `sub` per OIDC Core 1.0 §8.1. Different RPs see
// different subject identifiers for the same user, so they can't
// correlate across RPs. Stable per (userId, clientId).
export function pairwiseSub(userId: string, clientId: string): string {
  const secret = process.env.OIDC_PAIRWISE_SECRET ?? process.env.AUTH_SECRET;
  if (!secret) {
    throw new Error(
      "OIDC_PAIRWISE_SECRET (or AUTH_SECRET fallback) must be set",
    );
  }
  const mac = createHmac("sha256", secret)
    .update(`${userId}:${clientId}`)
    .digest();
  return mac.toString("base64url");
}

// PKCE: verify the code_verifier received on /token matches the
// code_challenge stored at /authorize. S256: challenge = base64url(SHA-256(verifier))
export function verifyPkceS256(
  codeVerifier: string,
  storedChallenge: string,
): boolean {
  const hash = createHash("sha256").update(codeVerifier).digest();
  const computed = hash.toString("base64url");
  // Same length, fixed string compare — timing leak isn't meaningful
  // here (challenge is public to anyone who sniffed /authorize).
  return computed === storedChallenge;
}

export interface IdTokenClaims {
  sub: string;
  aud: string;
  nonce: string;
  scopes: string[];
  name?: string | null;
  picture?: string | null;
  tessera_badges?: string[];
}

export async function mintIdToken(
  issuer: Issuer,
  claims: IdTokenClaims,
): Promise<string> {
  const payload: Record<string, unknown> = {
    nonce: claims.nonce,
  };
  if (claims.scopes.includes("profile")) {
    if (claims.name !== undefined) payload.name = claims.name;
    if (claims.picture !== undefined) payload.picture = claims.picture;
  }
  if (claims.tessera_badges && claims.tessera_badges.length > 0) {
    payload.tessera_badges = claims.tessera_badges;
  }

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "EdDSA", kid: issuer.kid, typ: "JWT" })
    .setIssuer(oidcIssuerUrl())
    .setSubject(claims.sub)
    .setAudience(claims.aud)
    .setIssuedAt()
    .setExpirationTime(`${ID_TOKEN_TTL_SECONDS}s`)
    .sign(issuer.privateKey);
}

export interface AccessTokenClaims {
  jti: string;          // random; key into the OidcAccessToken row
  sub: string;          // pairwise pseudonymous identifier, same as ID token
  clientId: string;
  scopes: string[];
}

// RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens). Signed with the
// same Ed25519 key as ID tokens; RPs verify via /.well-known/jwks.json.
//
// We deliberately do NOT include a raw userId in the JWT. /userinfo
// resolves the principal via OidcAccessToken row lookup keyed by `jti`.
// This preserves the pairwise pseudonymous `sub` privacy property —
// two RPs that decode their access tokens see different `sub` and *no*
// shared underlying identifier.
export async function mintAccessToken(
  issuer: Issuer,
  claims: AccessTokenClaims,
): Promise<string> {
  return new SignJWT({
    scope: claims.scopes.join(" "),
    client_id: claims.clientId,
    token_use: "access",
  })
    .setProtectedHeader({ alg: "EdDSA", kid: issuer.kid, typ: "at+jwt" })
    .setIssuer(oidcIssuerUrl())
    .setSubject(claims.sub)
    .setAudience(oidcIssuerUrl())
    .setJti(claims.jti)
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TOKEN_TTL_SECONDS}s`)
    .sign(issuer.privateKey);
}

export const ACCESS_TOKEN_TTL = ACCESS_TOKEN_TTL_SECONDS;
