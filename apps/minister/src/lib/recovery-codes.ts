import { randomInt } from "node:crypto";

import { hashClientSecret, verifyClientSecret } from "@/lib/oidc-clients";
import { prisma } from "@/lib/prisma";
import { RECOVERY_CODE_COUNT } from "@/lib/assurance";

// Recovery codes — the cold-start backstop (DESIGNDECISIONS #6). Generate
// RECOVERY_CODE_COUNT codes, show them once, store only Argon2id hashes.
// Redeeming one consumes it (single-use) and the caller mints a recovery
// ticket that lands a quarantined AAL1 session.
//
// Hashing: we REUSE the OidcClient.clientSecretHash hasher
// (@/lib/oidc-clients → @node-rs/argon2id). No new hashing dependency. Argon2's
// verify is constant-time over the encoded hash, so per-row comparison does not
// leak via timing which code (if any) matched.
//
// Security guarantees documented inline at each function.

// ---------------------------------------------------------------------------
// Code format
// ---------------------------------------------------------------------------

// Crockford base32 alphabet minus the visually ambiguous I/L/O/U — readable
// when transcribed by hand, no homoglyph confusion. 32 symbols = 5 bits each.
const ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ0123456789";
const GROUPS = 3;
const GROUP_LEN = 4;
// 12 symbols × 5 bits = 60 bits of entropy per code — far beyond brute-force
// reach for a single-use credential behind a rate limiter and an Argon2id hash.
const CODE_SYMBOLS = GROUPS * GROUP_LEN;

// Format: XXXX-XXXX-XXXX. Each symbol is drawn from a CSPRNG via
// crypto.randomInt (rejection-sampled, unbiased) — never Math.random.
function generateCode(): string {
  const groups: string[] = [];
  for (let g = 0; g < GROUPS; g++) {
    let group = "";
    for (let i = 0; i < GROUP_LEN; i++) {
      group += ALPHABET[randomInt(ALPHABET.length)];
    }
    groups.push(group);
  }
  return groups.join("-");
}

// Canonicalize user input before hashing/comparison: strip whitespace and
// separators, uppercase, and map the few characters humans commonly substitute
// for the omitted alphabet members back onto the alphabet (I/L→1, O→0, U→V).
// generateCode never emits the substituted characters, so this only ever
// REPAIRS a transcription; it cannot turn one valid code into a different one.
export function normalizeRecoveryCode(input: string): string {
  return input
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0")
    .replace(/U/g, "V");
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

// Generate a fresh batch of recovery codes for the user.
//
// Regeneration INVALIDATES the previous batch: all of the user's UNUSED rows
// are deleted first (already-redeemed rows are retained as a spent-audit
// trail). Generation and the delete run in one transaction so a partial batch
// can never coexist with a half-cleared previous batch.
//
// Returns the PLAINTEXT codes. They are shown to the user exactly once; only
// the Argon2id hashes are ever persisted. The caller MUST NOT log or store the
// returned plaintext.
export async function generateRecoveryCodes(userId: string): Promise<string[]> {
  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, generateCode);

  // Hash outside the transaction — Argon2id is intentionally slow and we don't
  // want to hold a DB transaction open across RECOVERY_CODE_COUNT hashes. The
  // hash is over the NORMALIZED form so redemption (which normalizes its input)
  // verifies against the same bytes regardless of separators/case.
  const codeHashes = await Promise.all(
    codes.map((code) => hashClientSecret(normalizeRecoveryCode(code))),
  );

  await prisma.$transaction(async (tx) => {
    await tx.recoveryCode.deleteMany({ where: { userId, usedAt: null } });
    await tx.recoveryCode.createMany({
      data: codeHashes.map((codeHash) => ({ userId, codeHash })),
    });
  });

  return codes;
}

// ---------------------------------------------------------------------------
// Redemption
// ---------------------------------------------------------------------------

// Redeem a single recovery code for the user. Returns true on success.
//
// Enumeration / timing safety:
//   * The return is a bare boolean — it never reveals how many codes exist or
//     which one matched. A wrong code and a no-codes-at-all account both return
//     false.
//   * Argon2id verify is constant-time over each candidate hash. We verify the
//     supplied code against EVERY unused row (no short-circuit on the first
//     mismatch) so the work done does not vary with the matching row's
//     position; only an actual match flips the result.
//
// Double-spend safety:
//   * The matching row is consumed with a conditional updateMany guarded on
//     `usedAt: null`. Two concurrent redemptions of the same code race on that
//     guard: exactly one update reports count === 1 (the winner), the other
//     reports 0 and is treated as a failure. The DB row, not the in-memory
//     check, is the arbiter, so this holds across processes.
export async function redeemRecoveryCode(userId: string, code: string): Promise<boolean> {
  const normalized = normalizeRecoveryCode(code);
  if (normalized.length !== CODE_SYMBOLS) {
    // Wrong length can't be a real code. Still do nothing observably different
    // from a verify miss to the caller (returns false either way).
    return false;
  }

  const rows = await prisma.recoveryCode.findMany({
    where: { userId, usedAt: null },
    select: { id: true, codeHash: true },
  });

  // Verify against every row without short-circuiting, so the time spent does
  // not depend on which row (if any) matches.
  let matchedId: string | null = null;
  for (const row of rows) {
    const ok = await verifyClientSecret(normalized, row.codeHash);
    if (ok && matchedId === null) {
      matchedId = row.id;
    }
  }

  if (matchedId === null) return false;

  // Atomic single-use consume: only succeeds if the row is still unused.
  const consumed = await prisma.recoveryCode.updateMany({
    where: { id: matchedId, usedAt: null },
    data: { usedAt: new Date() },
  });

  // count === 0 means another redemption already consumed this exact row
  // between our read and our write — treat as a failed (double-spend) attempt.
  return consumed.count === 1;
}

// Number of unused (still-redeemable) recovery codes the user holds. Drives the
// settings UI ("you have N codes left" / "generate codes"). Never returns the
// codes themselves.
export async function countUnusedCodes(userId: string): Promise<number> {
  return prisma.recoveryCode.count({ where: { userId, usedAt: null } });
}
