import { randomBytes } from "node:crypto";

import { SignJWT, jwtVerify } from "jose";

import { prisma } from "@/lib/prisma";

// Nonce-bound magic-link tokens for the EMAIL-DOMAIN live re-proof (slice 4,
// the one plugin wired end-to-end for threshold recovery).
//
// The live re-proof for an email-domain badge is: prove you still control an
// email address at a domain you hold a (non-public) email-domain badge for, by
// clicking a one-time link sent to that address. This module mints + verifies
// the link token. It is the per-plugin "live verification, bound to the attempt
// nonce" step that PRECEDES recordReProof in the contract documented in
// recovery-threshold.ts.
//
// Why a signed token (not a bare random in a column): the link must carry the
// attempt it belongs to, the badge type, and the proven domain, all tamper-
// evident, AND be bound to the attempt's freshness nonce so a link minted for
// one attempt can't be replayed into another. We reuse the recovery-ticket
// shape exactly (HS256 over AUTH_SECRET + a durable single-use marker in
// VerificationToken), differing only in the claim set.
//
// Security shape (mirrors recovery-ticket.ts):
//   * HS256 JWT over AUTH_SECRET carrying { attemptId, badgeType, domain,
//     nonceBinding } with a short exp. Tampering breaks the signature.
//   * nonceBinding ties the token to RecoveryAttempt.nonce: the verify step
//     re-reads the live attempt and rejects unless the binding still matches,
//     so a captured link is dead the moment the attempt's nonce rotates (a new
//     attempt = a new nonce).
//   * Single-use is durable (cross-process): the jti is recorded in
//     VerificationToken at mint and consumed with one atomic delete at verify.
//     A second verify finds nothing to delete and is rejected.

const ALG = "HS256";
const TYP = "minister-recovery-reproof";
const TTL_SECONDS = 15 * 60;

// Namespace for the single-use markers. Prefixed so it can never collide with
// Auth.js magic-link tokens (keyed on the bare email) or recovery-ticket
// markers (keyed on "recovery-ticket").
const CONSUMPTION_IDENTIFIER = "recovery-reproof";

function key(): Uint8Array {
  const secret = process.env.AUTH_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_SECRET must be set (≥32 chars) for recovery re-proof tokens");
  }
  return new TextEncoder().encode(secret);
}

export interface ReProofTokenClaims {
  attemptId: string;
  badgeType: string;
  // The domain the user is re-proving control of (must match a held,
  // non-public email-domain badge).
  domain: string;
  // Binds the token to the live attempt's freshness nonce.
  nonceBinding: string;
}

// Mint a single-use, nonce-bound re-proof link token. Records the durable
// marker BEFORE returning, so a token is never valid without a consumable
// marker behind it.
export async function issueReProofToken(claims: ReProofTokenClaims): Promise<string> {
  const jti = randomBytes(24).toString("base64url");

  await prisma.verificationToken.create({
    data: {
      identifier: CONSUMPTION_IDENTIFIER,
      token: jti,
      expires: new Date(Date.now() + TTL_SECONDS * 1000),
    },
  });

  return new SignJWT({
    attemptId: claims.attemptId,
    badgeType: claims.badgeType,
    domain: claims.domain,
    nonceBinding: claims.nonceBinding,
  })
    .setProtectedHeader({ alg: ALG, typ: TYP })
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime(`${TTL_SECONDS}s`)
    .sign(key());
}

// Verify signature + exp + typ, then atomically consume the single-use marker.
// Returns the bound claims on success, null on any failure (bad signature,
// expired, wrong typ, malformed, missing claims, or already-consumed). Never
// throws on a bad token. The CALLER must still re-read the live attempt and
// confirm `nonceBinding` matches the attempt's current nonce — this function
// proves the token is authentic + single-use, not that the attempt is live.
export async function verifyReProofToken(token: string): Promise<ReProofTokenClaims | null> {
  let claims: ReProofTokenClaims;
  let jti: string;
  try {
    const { payload } = await jwtVerify(token, key(), { algorithms: [ALG], typ: TYP });
    if (
      typeof payload.attemptId !== "string" ||
      typeof payload.badgeType !== "string" ||
      typeof payload.domain !== "string" ||
      typeof payload.nonceBinding !== "string" ||
      typeof payload.jti !== "string"
    ) {
      return null;
    }
    claims = {
      attemptId: payload.attemptId,
      badgeType: payload.badgeType,
      domain: payload.domain,
      nonceBinding: payload.nonceBinding,
    };
    jti = payload.jti;
  } catch {
    return null;
  }

  // Atomic single-use: delete the marker. A missing row (already consumed or
  // swept) throws P2025 and we reject — a verified-but-unconsumable token must
  // not pass.
  try {
    await prisma.verificationToken.delete({
      where: {
        identifier_token: { identifier: CONSUMPTION_IDENTIFIER, token: jti },
      },
    });
  } catch {
    return null;
  }

  return claims;
}
