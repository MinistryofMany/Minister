import { prisma } from "@/lib/prisma";

import { deriveDedupValue, deriveDisclosedNullifier } from "./encoding";
import type { MinisterGatingNullifier, NullifierService, RegisterDedupResult } from "./index";

// INTERIM Sybil-dedup backend (crypto-core Phase 1).
//
// In-Minister keyed HMAC + a Prisma `NullifierEntry` ledger. Deliberately
// deviates from the ADR's M1 (the real ledger lives in Signet) for the Phase
// 1-3 window ONLY, under a hard users==0 assumption — see schema comment and
// ADR "Interim-window deviation". Same FROZEN interface as the Phase 3 Signet
// backend, written to the §2.6 post-commit rule (no method here may be called
// inside an open prisma.$transaction).

// Duck-typed rather than `instanceof PrismaClientKnownRequestError`: the only
// UNIQUE that can fire in registerDedup is NullifierEntry.value, and matching on
// the `P2002` code keeps this testable without importing the generated client.
function isUniqueViolation(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === "P2002";
}

// Prisma's `Bytes` column is typed `Uint8Array<ArrayBuffer>`; Node's Buffer is
// `Uint8Array<ArrayBufferLike>`. Copy into a plain ArrayBuffer-backed view so
// the types line up (and the value is a standalone, non-pooled buffer).
function toBytes(buf: Buffer): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(buf.length);
  out.set(buf);
  return out;
}

export const interimBackend: NullifierService = {
  async registerDedup({ anchor, badgeType, ownerHandle }): Promise<RegisterDedupResult> {
    const value = toBytes(deriveDedupValue(anchor, badgeType));
    try {
      // Record-first insert: the UNIQUE(value) index IS the dedup comparison.
      const created = await prisma.nullifierEntry.create({
        data: { value, ownerHandle, badgeType },
        select: { id: true },
      });
      return { status: "registered", entryRef: created.id };
    } catch (err) {
      if (!isUniqueViolation(err)) throw err;
      // Someone already holds this credential. Same owner ⇒ idempotent re-issue;
      // different owner ⇒ taken (issuance refused).
      const existing = await prisma.nullifierEntry.findUnique({
        where: { value },
        select: { id: true, ownerHandle: true },
      });
      if (!existing) {
        // The row vanished between the failed insert and this read (a concurrent
        // release). Treat as taken-by-nobody is wrong; the credential is free
        // now, but reporting registered without a row would be a lie. Fail
        // closed by surfacing the race for a retry.
        throw new Error("nullifier: register raced a release; retry");
      }
      if (existing.ownerHandle === ownerHandle) {
        return { status: "already_yours", entryRef: existing.id };
      }
      return { status: "taken" };
    }
  },

  async disclose({ entryRef, ownerHandle, clientId }): Promise<MinisterGatingNullifier> {
    const entry = await prisma.nullifierEntry.findUnique({
      where: { id: entryRef },
      select: { value: true, ownerHandle: true },
    });
    // Fail closed: a missing entry or an owner mismatch must never yield a
    // value (a mis-bound Badge.nullifierRef could otherwise present another
    // user's Sybil nullifier).
    if (!entry) {
      throw new Error(`nullifier: entry ${entryRef} not found`);
    }
    if (entry.ownerHandle !== ownerHandle) {
      throw new Error(`nullifier: owner mismatch for entry ${entryRef}`);
    }
    const value = Buffer.isBuffer(entry.value) ? entry.value : Buffer.from(entry.value);
    return deriveDisclosedNullifier(value, clientId) as MinisterGatingNullifier;
  },

  async entryExistsForOwner({ entryRef, ownerHandle }): Promise<boolean> {
    // Owner-checked existence probe for mint-side re-validation. Returns false
    // (never throws) when the entry is gone (a concurrent release) or is owned
    // by someone else, so the caller can self-heal by re-registering.
    const entry = await prisma.nullifierEntry.findUnique({
      where: { id: entryRef },
      select: { ownerHandle: true },
    });
    return entry !== null && entry.ownerHandle === ownerHandle;
  },

  async release({ entryRef, ownerHandle }): Promise<void> {
    // Owner-checked, idempotent, and ATOMICALLY sibling-guarded: the entry is
    // deleted only if NO Badge row references it, in ONE statement, so the
    // sibling check and the delete share a single snapshot. A caller-side
    // check-then-release (deleteBadge's pre-count, compensateBatch's
    // fresh-registration bookkeeping) is one-shot and cannot guard against a
    // referencing badge that COMMITS between the check and the release — that
    // exact gap was the proven delete-vs-reissue dedup bypass. Composition
    // with the mint-side probe (server/wizard.ts) closes both orderings:
    //   * release statement starts AFTER the sibling badge's INSERT commits →
    //     NOT EXISTS sees the badge → the DELETE no-ops, the entry survives;
    //   * release commits BEFORE the badge INSERT commits → the entry is gone
    //     when the mint-side re-validation probes it → self-heal re-registers.
    // Known residual: a DELETE whose statement-start snapshot predates the
    // badge commit (so NOT EXISTS is true and it deletes the entry) but whose
    // own commit lands after the mint probe already read the entry as present.
    // The window runs through the DELETE's COMMIT — executor time PLUS the WAL
    // fsync, i.e. milliseconds under synchronous_commit=on, NOT microseconds —
    // and it is attacker-stretchable: Badge.nullifierRef being unindexed makes
    // the NOT EXISTS a Badge seq-scan that widens the window as the table
    // grows, and the attacker drives both racing requests (its own delete +
    // re-issue) and can loop them. Accepted for the interim backend ONLY
    // because users == 0 is an ENFORCED deploy gate (scripts/count-users.ts);
    // admitting real users on the interim backend BEFORE the Phase 3 split
    // would make serialization mandatory then — a
    // pg_advisory_xact_lock(hashtext(entryRef)) taken by BOTH the mint (for
    // anchor-bearing badges) and this release, or an FK ON DELETE RESTRICT.
    // Flagged for the Phase 3 split (build plan Phase 3).
    //
    // Cross-table NOT EXISTS instead of an FK RESTRICT: Badge.nullifierRef is
    // deliberately un-FK'd (the ledger moves into Signet in Phase 3 — see the
    // schema comment). This mechanism therefore relies on NullifierEntry and
    // Badge being co-located in Minister's Postgres, which holds for the
    // interim backend ONLY; the signet backend must re-establish equivalent
    // release atomicity on its side of the split.
    //
    // Tagged-template $executeRaw is parameterized ($1..$3) — never build this
    // SQL by string interpolation.
    await prisma.$executeRaw`
      DELETE FROM "NullifierEntry"
      WHERE "id" = ${entryRef}
        AND "ownerHandle" = ${ownerHandle}
        AND NOT EXISTS (SELECT 1 FROM "Badge" WHERE "nullifierRef" = ${entryRef})
    `;
  },

  async reassignOwner({ entryRefs, fromOwnerHandle, toOwnerHandle }): Promise<number> {
    if (entryRefs.length === 0) return 0;
    // Frozen-contract parity with the signet backend (and Signet's own
    // handler, which 400s equal handles): from === to is a no-op reporting 0
    // moved, never a matched-row count dressed up as a move count.
    if (fromOwnerHandle === toOwnerHandle) return 0;
    const res = await prisma.nullifierEntry.updateMany({
      where: { id: { in: entryRefs }, ownerHandle: fromOwnerHandle },
      data: { ownerHandle: toOwnerHandle },
    });
    return res.count;
  },
};
