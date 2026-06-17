import { randomBytes } from "node:crypto";

import { SignJWT, jwtVerify } from "jose";

import { prisma } from "@/lib/prisma";

// Server-minted, single-use, short-TTL ticket that authorizes a "recovery"
// sign-in. Slices 3 and 4, once they've established that the user satisfied
// a recovery flow (redeemed a recovery code, or cleared the badge
// threshold), mint a ticket with issueRecoveryTicket(userId) and immediately
// hand it to Auth.js: signIn("recovery", { ticket, redirect: false }). The
// recovery Credentials provider's authorize() calls verifyRecoveryTicket;
// the jwt callback then stamps the session aal=1 + recovered=true.
//
// Security shape:
//   * The ticket is an HS256 JWT over AUTH_SECRET (same key handling as the
//     OIDC request token), carrying { userId, jti } with a ~10 min exp.
//     Tampering breaks the signature; an expired ticket fails jwtVerify.
//   * Single-use is enforced DURABLY (cross-process), not just by exp: at
//     issue we record the jti in VerificationToken under a namespaced
//     identifier; at verify we consume it with one atomic delete. A second
//     verify of the same ticket finds nothing to delete and is rejected.
//     This survives multiple app instances because the marker lives in the DB.

const ALG = "HS256";
const TYP = "minister-recovery-ticket";
const TTL_SECONDS = 10 * 60;

// Namespace for the single-use markers in the VerificationToken table.
// Auth.js's email flow keys that table on the bare email address, so this
// prefixed identifier can never collide with a real magic-link token.
const CONSUMPTION_IDENTIFIER = "recovery-ticket";

function key(): Uint8Array {
  const secret = process.env.AUTH_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_SECRET must be set (≥32 chars) for recovery tickets");
  }
  return new TextEncoder().encode(secret);
}

export async function issueRecoveryTicket(userId: string): Promise<string> {
  // Random per-ticket id. It is both the JWT jti and the single-use marker
  // key, so a ticket can be consumed exactly once even if minted twice for
  // the same user.
  const jti = randomBytes(24).toString("base64url");

  // Record the marker BEFORE returning the ticket so a ticket can never be
  // valid without a consumable marker behind it. expires lines up with the
  // JWT exp; a sweep (or the next verify) clears stale rows.
  await prisma.verificationToken.create({
    data: {
      identifier: CONSUMPTION_IDENTIFIER,
      token: jti,
      expires: new Date(Date.now() + TTL_SECONDS * 1000),
    },
  });

  return new SignJWT({ userId })
    .setProtectedHeader({ alg: ALG, typ: TYP })
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime(`${TTL_SECONDS}s`)
    .sign(key());
}

// Verify signature + exp, then atomically consume the single-use marker.
// Returns the userId on success, null on any failure (bad signature,
// expired, wrong typ, malformed, or already-consumed). Never throws on a
// bad ticket — the caller (the provider's authorize) treats null as "auth
// failed".
export async function verifyRecoveryTicket(ticket: string): Promise<{ userId: string } | null> {
  let userId: string;
  let jti: string;
  try {
    const { payload } = await jwtVerify(ticket, key(), {
      algorithms: [ALG],
      typ: TYP,
    });
    if (typeof payload.userId !== "string" || typeof payload.jti !== "string") {
      return null;
    }
    userId = payload.userId;
    jti = payload.jti;
  } catch {
    // Bad signature, expired, wrong typ, or malformed — all auth failures.
    return null;
  }

  // Atomic single-use: delete the marker for this jti. If the row is gone
  // (already consumed, or expired-and-swept), this throws P2025 and we
  // reject — a verified-but-unconsumable ticket must not authenticate.
  try {
    await prisma.verificationToken.delete({
      where: {
        identifier_token: { identifier: CONSUMPTION_IDENTIFIER, token: jti },
      },
    });
  } catch {
    return null;
  }

  return { userId };
}
