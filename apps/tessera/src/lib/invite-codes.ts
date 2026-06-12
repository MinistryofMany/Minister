import { randomBytes } from "node:crypto";

import { Prisma } from "@/generated/prisma";
import { prisma } from "@/lib/prisma";

// Invalid, revoked, expired, and exhausted all collapse into one
// message so the redemption form can't be used as an oracle for which
// codes exist or what state they're in.
export const INVALID_CODE_MESSAGE = "Invalid, expired, or exhausted invite code.";
export const ALREADY_REDEEMED_MESSAGE = "You've already redeemed this code.";

// 32 chars — alphanumerics minus the lookalikes (I/O/0/1). 256 % 32 ===
// 0, so byte-mod indexing has no modulo bias. 12 chars ≈ 60 bits, which
// is plenty for codes that are also use-limited and expirable.
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CODE_LENGTH = 12;
const CODE_GROUP = 4;

export function generateInviteCode(): string {
  const bytes = randomBytes(CODE_LENGTH);
  const chars: string[] = [];
  for (let i = 0; i < CODE_LENGTH; i++) {
    chars.push(CODE_ALPHABET[bytes[i]! % CODE_ALPHABET.length]!);
    if ((i + 1) % CODE_GROUP === 0 && i + 1 < CODE_LENGTH) chars.push("-");
  }
  return chars.join("");
}

// Applied at creation AND redemption so a hand-typed lowercase code
// still matches the stored row.
export function normalizeInviteCode(raw: string): string {
  return raw.trim().toUpperCase();
}

export interface InviteCodeView {
  usesTotal: number;
  usesRemaining: number;
  expiresAt: Date | null;
  revokedAt: Date | null;
}

export type InviteCodeVerdict =
  | { ok: true }
  | { ok: false; message: string };

export function evaluateInviteCode(
  row: InviteCodeView,
  alreadyRedeemed: boolean,
  now: Date,
): InviteCodeVerdict {
  if (row.revokedAt) return { ok: false, message: INVALID_CODE_MESSAGE };
  if (row.expiresAt && row.expiresAt < now) {
    return { ok: false, message: INVALID_CODE_MESSAGE };
  }
  if (row.usesTotal > 0 && row.usesRemaining <= 0) {
    return { ok: false, message: INVALID_CODE_MESSAGE };
  }
  if (alreadyRedeemed) return { ok: false, message: ALREADY_REDEEMED_MESSAGE };
  return { ok: true };
}

export type RedeemResult =
  | { ok: true; inviteCodeId: string; label: string }
  | { ok: false; message: string };

// Sentinel for "the pre-check passed but the conditional decrement hit
// zero" — i.e. we lost a race to the last remaining use.
class CodeExhausted extends Error {}

export async function redeemInviteCode(
  rawCode: string,
  userId: string,
): Promise<RedeemResult> {
  const code = normalizeInviteCode(rawCode);
  if (!code) return { ok: false, message: INVALID_CODE_MESSAGE };

  const row = await prisma.inviteCode.findUnique({
    where: { code },
    include: { redemptions: { where: { userId }, select: { id: true } } },
  });
  if (!row) return { ok: false, message: INVALID_CODE_MESSAGE };

  const verdict = evaluateInviteCode(row, row.redemptions.length > 0, new Date());
  if (!verdict.ok) return verdict;

  try {
    await prisma.$transaction(async (tx) => {
      // usesTotal === 0 means unlimited — nothing to decrement; the
      // unique (inviteCodeId, userId) constraint is still the
      // double-redeem guard.
      if (row.usesTotal > 0) {
        const updated = await tx.inviteCode.updateMany({
          where: { id: row.id, revokedAt: null, usesRemaining: { gt: 0 } },
          data: { usesRemaining: { decrement: 1 } },
        });
        if (updated.count === 0) throw new CodeExhausted();
      }
      await tx.inviteRedemption.create({
        data: { inviteCodeId: row.id, userId },
      });
    });
  } catch (err) {
    if (err instanceof CodeExhausted) {
      return { ok: false, message: INVALID_CODE_MESSAGE };
    }
    // P2002 = unique-constraint violation on (inviteCodeId, userId):
    // a concurrent redemption by the same user. The transaction rolls
    // the decrement back.
    if (
      err instanceof Prisma.PrismaClientKnownRequestError &&
      err.code === "P2002"
    ) {
      return { ok: false, message: ALREADY_REDEEMED_MESSAGE };
    }
    throw err;
  }

  return { ok: true, inviteCodeId: row.id, label: row.label };
}
