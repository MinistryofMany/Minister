import { randomBytes } from "node:crypto";

import { Prisma } from "@/generated/prisma";
import { recoveryWeightFor, RECOVERY_ELIGIBLE_TYPES, RECOVERY_THRESHOLD } from "@/lib/assurance";
import { prisma } from "@/lib/prisma";
import { issueRecoveryTicket } from "@/lib/recovery-ticket";

// Weighted-badge-threshold recovery — the accounting engine (slice 4).
//
// A user who has lost all their authentication factors recovers an account by
// LIVE-RE-PROVING badges they hold until the accumulated recovery weight
// crosses RECOVERY_THRESHOLD. The weight of each badge type is calibrated in
// `@/lib/assurance` so recovery is at least as hard as the front door
// (DESIGNDECISIONS #7): one gov-doc proof (IAL3) clears it alone, low-IAL
// factors are near-worthless in aggregate.
//
// ───────────────────────────────────────────────────────────────────────────
// THE RE-PROOF / NONCE CONTRACT  (read this before calling recordReProof)
// ───────────────────────────────────────────────────────────────────────────
// recordReProof is PURE ACCOUNTING. It does NOT verify any cryptographic
// proof. It trusts that its caller — the per-plugin live re-proof step — has
// ALREADY:
//
//   1. Run the actual plugin verification LIVE (re-done the OAuth dance,
//      clicked a fresh magic link, produced a fresh TLSNotary presentation).
//      A stored `Badge.vcJwt` is NEVER acceptable evidence: replaying a leaked
//      VC must not recover an account (DESIGNDECISIONS #8). This engine never
//      reads or accepts `vcJwt` anywhere.
//
//   2. Bound that verification to THIS attempt's `nonce` (the value returned
//      by startRecoveryAttempt). The nonce is the freshness binder: the OAuth
//      `state`, the magic-link token, or the TLSN submission token MUST be
//      derived from / equal to the attempt nonce so a proof captured for one
//      attempt cannot be replayed into another. recordReProof is given the
//      attemptId, not the nonce, precisely so a caller cannot accidentally
//      record a proof it never bound — it must already hold the attempt it
//      verified against.
//
//   3. Confirmed the proven real-world account is one the TARGET user actually
//      holds a badge for (e.g. the GitHub account id on the fresh OAuth token
//      resolves — via deriveDedupValue → the nullifier ledger — to the entry
//      behind a held oauth-account badge's `nullifierRef`, owner-checked; the
//      raw `accountId` attribute no longer exists post crypto-core Phase 1, and
//      the renameable `handle` must NOT be used as the match key). This engine
//      re-checks badge HOLDING (a non-public badge of `badgeType` exists for the
//      user) but it cannot check that the freshly proven identity matches the
//      badge's specific account — only the plugin step that saw both the live
//      proof and the badge's nullifier binding can.
//
// Given those three caller obligations, recordReProof enforces the accounting
// invariants: attempt liveness, eligibility, non-public badge holding, the
// no-double-count uniqueness, weight computation, the atomic increment, and
// threshold satisfaction.

const NONCE_BYTES = 24;

// Short TTL: a recovery attempt is an active ceremony, not a standing grant.
// Long enough to drive several live re-proofs (each an OAuth/email round
// trip), short enough that a half-finished attempt can't sit around.
export const RECOVERY_ATTEMPT_TTL_MS = 15 * 60 * 1000;

export type RecoveryAttemptStatus = "pending" | "satisfied" | "consumed" | "expired" | "failed";

export interface StartedRecoveryAttempt {
  attemptId: string;
  // The freshness binder. Every live re-proof for this attempt MUST be bound
  // to this nonce (carried as the OAuth state / magic-link token / TLSN
  // submission token). Treat it as a secret capability for THIS attempt.
  nonce: string;
  requiredScore: number;
}

export interface ReProofResult {
  accumulatedScore: number;
  requiredScore: number;
  satisfied: boolean;
}

// Discriminated rejection reasons so callers (and tests) can branch precisely
// rather than string-matching. Every non-throwing failure path is one of
// these; only genuinely unexpected DB errors throw.
export type RecordReProofError =
  | { ok: false; reason: "attempt-not-found" }
  | { ok: false; reason: "attempt-not-pending" }
  | { ok: false; reason: "attempt-expired" }
  | { ok: false; reason: "type-not-eligible" }
  | { ok: false; reason: "badge-not-held" }
  | { ok: false; reason: "already-proven" };

export type RecordReProofOutcome = ({ ok: true } & ReProofResult) | RecordReProofError;

// Context the caller carries through the re-proof. Kept minimal and explicit:
// the only thing recordReProof needs beyond the attempt + type is the
// provenance, which feeds the weight (github/google OAuth outweighs
// discord/steam). `proofRef` is an opaque, NON-SECRET correlation handle the
// caller may pass for the audit trail (e.g. a GitHub account id) — it is never
// trusted as evidence and never stored as a credential.
export interface ReProofContext {
  provenance?: string;
  proofRef?: string;
}

// Create a fresh recovery attempt for a user. The nonce is the per-attempt
// freshness binder; the TTL bounds how long the ceremony stays live. Returns
// the handle the UI drives every live re-proof against.
export async function startRecoveryAttempt(
  userId: string,
  requiredScore: number = RECOVERY_THRESHOLD,
): Promise<StartedRecoveryAttempt> {
  const nonce = randomBytes(NONCE_BYTES).toString("base64url");
  const attempt = await prisma.recoveryAttempt.create({
    data: {
      userId,
      nonce,
      status: "pending",
      requiredScore,
      accumulatedScore: 0,
      expiresAt: new Date(Date.now() + RECOVERY_ATTEMPT_TTL_MS),
    },
    select: { id: true, nonce: true, requiredScore: true },
  });
  return {
    attemptId: attempt.id,
    nonce: attempt.nonce,
    requiredScore: attempt.requiredScore,
  };
}

// THE ACCOUNTING CORE. See the RE-PROOF / NONCE CONTRACT at the top of this
// file: the caller MUST have already run + nonce-bound the live cryptographic
// re-proof before calling this. This function does pure accounting only.
//
// Validates, in order:
//   * the attempt exists, is still `pending`, and has not expired;
//   * `badgeType` is recovery-eligible (a plugin can re-prove it live);
//   * the target user actually HOLDS a NON-PUBLIC badge of this type — a
//     public badge must not count, because an attacker can enumerate public
//     badges and target exactly those (DESIGNDECISIONS #8);
//   * this (attempt, badgeType) pair has not already been proven — the DB
//     unique constraint is the source of truth, so the same type can never
//     double-count even under a race.
//
// On success, in ONE transaction it inserts the RecoveryProof row and
// increments accumulatedScore, flipping the attempt to `satisfied` the instant
// the threshold is met. Returns the updated tally.
export async function recordReProof(
  attemptId: string,
  badgeType: string,
  context: ReProofContext = {},
): Promise<RecordReProofOutcome> {
  const attempt = await prisma.recoveryAttempt.findUnique({
    where: { id: attemptId },
    select: {
      id: true,
      userId: true,
      status: true,
      requiredScore: true,
      accumulatedScore: true,
      expiresAt: true,
    },
  });
  if (!attempt) return { ok: false, reason: "attempt-not-found" };
  if (attempt.status !== "pending") return { ok: false, reason: "attempt-not-pending" };
  if (attempt.expiresAt.getTime() <= Date.now()) {
    return { ok: false, reason: "attempt-expired" };
  }

  // Only types a plugin can RE-PROVE live count. Stored-only / one-shot types
  // (invite-code) are excluded so a leaked VC can never contribute.
  if (!RECOVERY_ELIGIBLE_TYPES.has(badgeType)) {
    return { ok: false, reason: "type-not-eligible" };
  }

  // The user must actually HOLD a non-public badge of this type. We check
  // holding, never the stored VC's validity — the live proof established
  // validity; this just confirms the type is one the account legitimately
  // earned (and is not public, so not enumerable by an attacker).
  const held = await prisma.badge.findFirst({
    where: { userId: attempt.userId, type: badgeType, isPublic: false },
    select: { id: true },
  });
  if (!held) return { ok: false, reason: "badge-not-held" };

  const weight = recoveryWeightFor(badgeType, context.provenance);

  // Atomic: insert the proof and bump the score together. The unique
  // constraint on (attemptId, badgeType) makes the insert the no-double-count
  // gate — a concurrent second proof of the same type hits P2002 and is
  // rejected, even if both reads above saw `pending`. We re-read the attempt
  // INSIDE the transaction to compute satisfaction against a consistent score,
  // and only flip to `satisfied` from `pending` (a guard that never lets two
  // racing transactions both satisfy).
  try {
    const result = await prisma.$transaction(async (tx) => {
      await tx.recoveryProof.create({
        data: { attemptId, badgeType, weight },
      });

      const updated = await tx.recoveryAttempt.update({
        where: { id: attemptId },
        data: { accumulatedScore: { increment: weight } },
        select: { accumulatedScore: true, requiredScore: true, status: true },
      });

      const satisfied = updated.accumulatedScore >= updated.requiredScore;
      if (satisfied && updated.status === "pending") {
        await tx.recoveryAttempt.update({
          where: { id: attemptId },
          data: { status: "satisfied", satisfiedAt: new Date() },
        });
      }

      return {
        accumulatedScore: updated.accumulatedScore,
        requiredScore: updated.requiredScore,
        satisfied,
      };
    });

    return { ok: true, ...result };
  } catch (err) {
    // Unique violation on (attemptId, badgeType) = this type was already
    // proven for this attempt. That's a clean "no double-count" rejection,
    // not an error.
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
      return { ok: false, reason: "already-proven" };
    }
    throw err;
  }
}

export type ConsumeAttemptOutcome =
  | { ok: true; ticket: string; userId: string }
  | { ok: false; reason: "attempt-not-found" | "not-satisfied" | "already-consumed" | "expired" };

// One-shot redemption of a satisfied attempt into a recovery ticket. Atomically
// flips the attempt `satisfied` -> `consumed` (guarding against reuse: a second
// call finds the status already `consumed` and is rejected), then mints the
// single-use recovery ticket the caller hands to signIn("recovery", ...).
//
// The status flip is the reuse guard. We use updateMany with a status filter so
// the flip only lands when the row is still `satisfied`; a count of 0 means a
// concurrent caller already consumed it (or it was never satisfied / expired),
// and we reject without minting a ticket.
export async function consumeSatisfiedAttempt(attemptId: string): Promise<ConsumeAttemptOutcome> {
  const attempt = await prisma.recoveryAttempt.findUnique({
    where: { id: attemptId },
    select: { id: true, userId: true, status: true, expiresAt: true },
  });
  if (!attempt) return { ok: false, reason: "attempt-not-found" };
  if (attempt.status === "consumed") return { ok: false, reason: "already-consumed" };
  if (attempt.status !== "satisfied") return { ok: false, reason: "not-satisfied" };
  // A satisfied-but-expired attempt is dead: the ceremony took too long.
  // Reject rather than grant a stale recovery.
  if (attempt.expiresAt.getTime() <= Date.now()) {
    return { ok: false, reason: "expired" };
  }

  // Atomic claim: only one caller can move satisfied -> consumed. The filter on
  // status is the cross-process one-shot guard — Postgres serializes the
  // conditional update, so exactly one updateMany sees count 1.
  const claimed = await prisma.recoveryAttempt.updateMany({
    where: { id: attemptId, status: "satisfied" },
    data: { status: "consumed", consumedAt: new Date() },
  });
  if (claimed.count !== 1) {
    // Lost the race: another caller consumed it between our read and write.
    return { ok: false, reason: "already-consumed" };
  }

  // Only AFTER we've durably claimed the attempt do we mint the ticket, so a
  // ticket is never issued for an attempt that another caller also consumed.
  const ticket = await issueRecoveryTicket(attempt.userId);
  return { ok: true, ticket, userId: attempt.userId };
}

// Read-only view of an attempt's tally for the UI to render the climbing
// score. Never mutates. Returns null if the attempt is gone.
export async function getAttemptStatus(attemptId: string): Promise<{
  status: RecoveryAttemptStatus;
  accumulatedScore: number;
  requiredScore: number;
  expiresAt: Date;
  provenTypes: string[];
} | null> {
  const attempt = await prisma.recoveryAttempt.findUnique({
    where: { id: attemptId },
    select: {
      status: true,
      accumulatedScore: true,
      requiredScore: true,
      expiresAt: true,
      proofs: { select: { badgeType: true } },
    },
  });
  if (!attempt) return null;
  return {
    status: attempt.status as RecoveryAttemptStatus,
    accumulatedScore: attempt.accumulatedScore,
    requiredScore: attempt.requiredScore,
    expiresAt: attempt.expiresAt,
    provenTypes: attempt.proofs.map((p) => p.badgeType),
  };
}
