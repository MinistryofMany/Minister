import { createHmac, randomInt, timingSafeEqual } from "node:crypto";

import { prisma } from "@/lib/prisma";

// Email one-time sign-in code. Delivered in the same email as the magic
// link so a user reading mail on their phone can type the code to sign in
// on another device. The link and the code are independent credentials for
// the same verified identity; either completes auth.
//
// Security posture (a short code is brute-forceable in a way a 32-byte link
// token is not):
//   * short TTL, matched to the magic-link token TTL (1h)
//   * single-use: a correct code is deleted the moment it verifies
//   * per-code lockout: MAX_ATTEMPTS wrong guesses burns the code
//   * stored as an HMAC over AUTH_SECRET, never plaintext, so a DB read
//     alone can't reveal a live code
// Per-IP and per-identity rate limiting live at the call site (the
// email-otp credentials provider), on top of the per-code lockout here.

// 1 hour — matches the magic-link `maxAge` on the email provider so the two
// credentials in one email expire together.
export const OTP_TTL_MS = 60 * 60 * 1000;

// Wrong guesses tolerated on a single code before it is burned. Low, because
// the code is short; a fresh code is one email away.
export const OTP_MAX_ATTEMPTS = 5;

const OTP_LENGTH = 8;

// Unambiguous alphabet: no 0/O, 1/I/L. Uppercase only; input is uppercased
// before matching so users can type either case.
const OTP_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";

// Normalize user-typed input to the stored form: uppercase, and strip any
// separators (spaces, dashes) a client might insert for readability.
export function normalizeOtp(input: string): string {
  return input.toUpperCase().replace(/[^0-9A-Z]/g, "");
}

// Generate a fresh code with node:crypto's rejection-sampling randomInt (no
// modulo bias). Not exported — codes are only ever minted through
// createSignInOtp.
function generateCode(): string {
  let out = "";
  for (let i = 0; i < OTP_LENGTH; i++) {
    out += OTP_ALPHABET[randomInt(OTP_ALPHABET.length)];
  }
  return out;
}

// Read AUTH_SECRET directly (like recovery-ticket / oidc-request-token) rather
// than through the full env schema, so this module doesn't drag DATABASE_URL
// et al. into unit tests. Enforce the same 32-char floor the env schema does.
function authSecret(): string {
  const secret = process.env.AUTH_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_SECRET must be set and at least 32 chars to hash sign-in codes");
  }
  return secret;
}

// Keyed hash so the stored value is useless without AUTH_SECRET (a plain
// unsalted hash of a short code is brute-forceable offline from a DB leak).
function hashCode(code: string): string {
  return createHmac("sha256", authSecret()).update(normalizeOtp(code)).digest("hex");
}

function hashesEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

// Mint a single-use code for `identifier` (the verified email, lowercased by
// the caller). Any prior codes for that identifier are cleared first, so at
// most one live code exists per address. Returns the plaintext code for the
// caller to email — it is never persisted in the clear.
export async function createSignInOtp(identifier: string): Promise<string> {
  const code = generateCode();
  await prisma.$transaction([
    prisma.signInOtp.deleteMany({ where: { identifier } }),
    prisma.signInOtp.create({
      data: {
        identifier,
        codeHash: hashCode(code),
        expires: new Date(Date.now() + OTP_TTL_MS),
      },
    }),
  ]);
  return code;
}

// Outcome of a verification attempt. `ok` drives the sign-in; `reason` is
// server-side only (audit metadata) — the user always sees one uniform
// error so the form can't be used to distinguish "wrong code" from "no such
// pending sign-in".
export type OtpVerifyResult =
  { ok: true } | { ok: false; reason: "no-code" | "expired" | "mismatch" | "locked-out" };

// Verify a submitted code for `identifier`. Consumes the code on success
// (single-use). On a wrong guess, increments the attempt counter and burns
// the code once it crosses OTP_MAX_ATTEMPTS. Expired or exhausted codes are
// deleted as they're encountered.
export async function verifySignInOtp(
  identifier: string,
  submitted: string,
): Promise<OtpVerifyResult> {
  const row = await prisma.signInOtp.findFirst({
    where: { identifier },
    orderBy: { createdAt: "desc" },
  });
  if (!row) return { ok: false, reason: "no-code" };

  if (row.expires.getTime() <= Date.now()) {
    await prisma.signInOtp.deleteMany({ where: { identifier } });
    return { ok: false, reason: "expired" };
  }

  if (hashesEqual(row.codeHash, hashCode(submitted))) {
    // Single-use: remove every code for this identifier so a captured code
    // can't be replayed and no stale sibling survives.
    await prisma.signInOtp.deleteMany({ where: { identifier } });
    return { ok: true };
  }

  const attempts = row.attempts + 1;
  if (attempts >= OTP_MAX_ATTEMPTS) {
    // Burn the code: further guessing must wait for a freshly emailed one.
    await prisma.signInOtp.deleteMany({ where: { identifier } });
    return { ok: false, reason: "locked-out" };
  }
  await prisma.signInOtp.update({ where: { id: row.id }, data: { attempts } });
  return { ok: false, reason: "mismatch" };
}
