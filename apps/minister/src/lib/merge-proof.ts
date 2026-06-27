import { randomBytes } from "node:crypto";

import { SignJWT, jwtVerify } from "jose";

import { prisma } from "@/lib/prisma";

// Server-minted, single-use, short-TTL DONOR-PROOF ticket for the account
// merge ceremony (slice 5). It is the second half of merge's dual control:
// the SURVIVOR drives the merge from an AAL2 session; this ticket is the
// portable proof that the same human ALSO controls the DONOR account.
//
// The merge flow mints one only AFTER the donor has authenticated (a magic
// link delivered to a verified donor email, or — as a documented future
// seam — a donor passkey assertion). confirmMerge then verifies the ticket
// and, crucially, binds it to a specific donorUserId so a ticket minted for
// one donor can never authorize merging a DIFFERENT account in.
//
// Security shape (mirrors recovery-ticket.ts deliberately — same key
// handling, same durable single-use marker):
//   * HS256 JWT over AUTH_SECRET carrying { donorUserId, jti } with a short
//     exp. Tampering breaks the signature; an expired ticket fails verify.
//   * Single-use is enforced DURABLY (cross-process), not just by exp: at
//     issue we record the jti in VerificationToken under a namespaced
//     identifier; at verify we consume it with one atomic delete. A second
//     verify finds nothing to delete and is rejected. This survives multiple
//     app instances because the marker lives in the DB.
//   * The donorUserId is carried IN the signed ticket and returned to the
//     caller, so confirmMerge re-checks it against the donor it intends to
//     merge — the ticket is bound to one account, not a bare "someone
//     proved a donor" bit.

const ALG = "HS256";
const TYP = "minister-donor-proof";

// Short TTL: the donor-proof is consumed immediately after issue in the same
// merge ceremony, so it does not need the 10-minute window a recovery
// sign-in does. Five minutes leaves room for a human to click through the
// confirm step without leaving a long-lived "merge this account in" token
// usable if intercepted.
const TTL_SECONDS = 5 * 60;

// Namespace for the single-use markers in the VerificationToken table.
// Distinct from the recovery-ticket namespace and from Auth.js's email flow
// (which keys that table on the bare email address), so a donor-proof marker
// can never collide with either.
const CONSUMPTION_IDENTIFIER = "donor-proof-ticket";

function key(): Uint8Array {
  const secret = process.env.AUTH_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_SECRET must be set (≥32 chars) for donor-proof tickets");
  }
  return new TextEncoder().encode(secret);
}

// Mint a single-use donor-proof ticket bound to donorUserId. Callers issue
// this only after the donor has authenticated (see merge-actions). The
// returned string is handed to confirmMerge, which verifies + consumes it.
export async function issueDonorProof(donorUserId: string): Promise<string> {
  // Random per-ticket id. It is both the JWT jti and the single-use marker
  // key, so a ticket can be consumed exactly once even if minted twice for
  // the same donor.
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

  return new SignJWT({ donorUserId })
    .setProtectedHeader({ alg: ALG, typ: TYP })
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime(`${TTL_SECONDS}s`)
    .sign(key());
}

// Verify signature + exp + typ, then atomically consume the single-use
// marker. Returns the bound donorUserId on success, null on any failure (bad
// signature, expired, wrong typ, malformed, missing donorUserId, or
// already-consumed). Never throws on a bad ticket — confirmMerge treats null
// as "donor proof failed". The caller MUST additionally check the returned
// donorUserId equals the donor it intends to merge.
export async function verifyDonorProof(ticket: string): Promise<{ donorUserId: string } | null> {
  let donorUserId: string;
  let jti: string;
  try {
    const { payload } = await jwtVerify(ticket, key(), {
      algorithms: [ALG],
      typ: TYP,
    });
    if (typeof payload.donorUserId !== "string" || typeof payload.jti !== "string") {
      return null;
    }
    donorUserId = payload.donorUserId;
    jti = payload.jti;
  } catch {
    // Bad signature, expired, wrong typ, or malformed — all proof failures.
    return null;
  }

  // Atomic single-use: delete the marker for this jti. If the row is gone
  // (already consumed, or expired-and-swept), this throws and we reject — a
  // verified-but-unconsumable ticket must not authorize a merge.
  try {
    await prisma.verificationToken.delete({
      where: {
        identifier_token: { identifier: CONSUMPTION_IDENTIFIER, token: jti },
      },
    });
  } catch {
    return null;
  }

  return { donorUserId };
}
