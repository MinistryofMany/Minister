import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import { SignJWT } from "jose";

import type { Issuer } from "@minister/vc";

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
  // No AUTH_SECRET fallback: falling back silently re-keys every pairwise `sub`
  // if OIDC_PAIRWISE_SECRET is ever unset in prod (env.ts requires it at boot;
  // Phase 7's Signet sub backend relaxes that). Fail fast instead.
  const secret = process.env.OIDC_PAIRWISE_SECRET;
  if (!secret) {
    throw new Error("OIDC_PAIRWISE_SECRET must be set");
  }
  const mac = createHmac("sha256", secret).update(`${userId}:${clientId}`).digest();
  return mac.toString("base64url");
}

// Per-RP `jti` for a badge VC re-minted at disclosure. Deterministic per
// (badge, relying-party) — a stable revocation handle — but unlinkable across
// relying parties (different `clientId` → different `jti`), so two colluding
// RPs cannot join on `jti` the way they could on the raw stored `badge.id`.
//
// Domain-separated from `pairwiseSub` with a `"jti:"` prefix: both HMACs share
// OIDC_PAIRWISE_SECRET, and userId/badgeId are both cuids from different
// tables, so the prefix guarantees a `pairwiseSub(userId, clientId)` can never
// collide with a `pairwiseJti(badgeId, clientId)`.
export function pairwiseJti(badgeId: string, clientId: string): string {
  // No AUTH_SECRET fallback — same fail-fast rationale as pairwiseSub.
  const secret = process.env.OIDC_PAIRWISE_SECRET;
  if (!secret) {
    throw new Error("OIDC_PAIRWISE_SECRET must be set");
  }
  const mac = createHmac("sha256", secret).update(`jti:${badgeId}:${clientId}`).digest();
  return mac.toString("base64url");
}

// PKCE: verify the code_verifier received on /token matches the
// code_challenge stored at /authorize.
// S256: challenge = base64url(SHA-256(verifier)).
// Compare in constant time. The challenge was public to anyone who
// sniffed /authorize, but the verifier is supposed to be a secret
// known only to the RP — defense-in-depth.
export function verifyPkceS256(codeVerifier: string, storedChallenge: string): boolean {
  const computed = createHash("sha256").update(codeVerifier).digest();
  // Buffer.from(_, "base64url") never throws — it silently drops any
  // non-base64url bytes — so a malformed challenge that decodes to the
  // wrong length is caught by the length check below, and the
  // constant-time compare rejects anything that survives it.
  const stored = Buffer.from(storedChallenge, "base64url");
  if (stored.length !== computed.length) return false;
  return timingSafeEqual(computed, stored);
}

export interface IdTokenClaims {
  sub: string;
  aud: string;
  nonce: string;
  // Each profile claim is emitted iff present. The caller (the resolver)
  // already applied the per-claim consent gate and the curated-value
  // requirement, so an undefined value here means "do not emit" — there is
  // no separate `profile` scope gate to re-apply.
  name?: string;
  picture?: string;
  minister_badges?: string[];
}

export async function mintIdToken(issuer: Issuer, claims: IdTokenClaims): Promise<string> {
  const payload: Record<string, unknown> = {
    nonce: claims.nonce,
  };
  if (claims.name !== undefined) payload.name = claims.name;
  if (claims.picture !== undefined) payload.picture = claims.picture;
  if (claims.minister_badges && claims.minister_badges.length > 0) {
    payload.minister_badges = claims.minister_badges;
  }

  // Tokens sign with the in-process token key (#key-3), never KMS: an id_token
  // can exceed KMS's 4096-byte RAW-sign limit once several badges are embedded.
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "EdDSA", kid: issuer.token.kid, typ: "JWT" })
    .setIssuer(oidcIssuerUrl())
    .setSubject(claims.sub)
    .setAudience(claims.aud)
    .setIssuedAt()
    .setExpirationTime(`${ID_TOKEN_TTL_SECONDS}s`)
    .sign(issuer.token.privateKey);
}

export interface AccessTokenClaims {
  jti: string; // random; key into the OidcAccessToken row
  sub: string; // pairwise pseudonymous identifier, same as ID token
  clientId: string;
  scopes: string[];
}

// RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens). Signed with the
// same in-process token key (#key-3) as ID tokens; RPs verify via
// /.well-known/jwks.json.
//
// We deliberately do NOT include a raw userId in the JWT. /userinfo
// resolves the principal via OidcAccessToken row lookup keyed by `jti`.
// This preserves the pairwise pseudonymous `sub` privacy property —
// two RPs that decode their access tokens see different `sub` and *no*
// shared underlying identifier.
export async function mintAccessToken(issuer: Issuer, claims: AccessTokenClaims): Promise<string> {
  return new SignJWT({
    scope: claims.scopes.join(" "),
    client_id: claims.clientId,
    token_use: "access",
  })
    .setProtectedHeader({ alg: "EdDSA", kid: issuer.token.kid, typ: "at+jwt" })
    .setIssuer(oidcIssuerUrl())
    .setSubject(claims.sub)
    .setAudience(oidcIssuerUrl())
    .setJti(claims.jti)
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TOKEN_TTL_SECONDS}s`)
    .sign(issuer.token.privateKey);
}

export const ACCESS_TOKEN_TTL = ACCESS_TOKEN_TTL_SECONDS;
