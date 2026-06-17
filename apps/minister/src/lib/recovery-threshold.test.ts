import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ───────────────────────────────────────────────────────────────────────────
// In-memory Prisma stand-in.
//
// The accounting engine's correctness lives in these invariants:
//   * the (attemptId, badgeType) UNIQUE constraint (no double-count),
//   * the interactive $transaction (insert proof + bump score atomically),
//   * updateMany's conditional count (the consume one-shot guard),
//   * the non-public Badge holding query.
// So the mock models each faithfully rather than returning canned values. A
// duplicate RecoveryProof insert throws a REAL PrismaClientKnownRequestError
// with code P2002 — exactly what the engine's `instanceof` + code check keys
// on. No live DB.
// ───────────────────────────────────────────────────────────────────────────

interface AttemptRow {
  id: string;
  userId: string;
  nonce: string;
  status: string;
  requiredScore: number;
  accumulatedScore: number;
  expiresAt: Date;
  satisfiedAt: Date | null;
  consumedAt: Date | null;
}
interface ProofRow {
  id: string;
  attemptId: string;
  badgeType: string;
  weight: number;
}
interface BadgeRow {
  id: string;
  userId: string;
  type: string;
  isPublic: boolean;
}

// The store + client are built inside vi.hoisted so they exist before the
// hoisted vi.mock("@/lib/prisma") factory runs (vi.mock is lifted to the top
// of the module; a plain top-level const would not yet be initialized).
const { db, client } = vi.hoisted(() => {
  const store = {
    attempts: new Map<string, AttemptRow>(),
    proofs: [] as ProofRow[],
    badges: [] as BadgeRow[],
    seq: 0,
  };

  function nextId(prefix: string): string {
    store.seq += 1;
    return `${prefix}_${store.seq}`;
  }

  function p2002(): never {
    // A real Prisma known-request error so the engine's `instanceof` + code
    // check behaves exactly as it does against the live client.
    const err = new Error("Unique constraint failed") as Error & { code: string; name: string };
    err.name = "PrismaClientKnownRequestError";
    err.code = "P2002";
    throw err;
  }

  function pick<T extends object>(row: T, select?: Record<string, boolean>): Partial<T> {
    if (!select) return row;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(select)) {
      if (select[k]) out[k] = (row as Record<string, unknown>)[k];
    }
    return out as Partial<T>;
  }

  // The Prisma client surface the engine touches. Methods accept the same
  // argument shapes the real client does (where/data/select).
  const prismaClient = {
    nextId,
    recoveryAttempt: {
      create: vi.fn(
        async ({ data, select }: { data: Partial<AttemptRow>; select?: Record<string, boolean> }) => {
          const row: AttemptRow = {
            id: nextId("ra"),
            userId: data.userId!,
            nonce: data.nonce!,
            status: data.status ?? "pending",
            requiredScore: data.requiredScore!,
            accumulatedScore: data.accumulatedScore ?? 0,
            expiresAt: data.expiresAt!,
            satisfiedAt: null,
            consumedAt: null,
          };
          // nonce is @unique — model it.
          for (const existing of store.attempts.values()) {
            if (existing.nonce === row.nonce) p2002();
          }
          store.attempts.set(row.id, row);
          return pick(row, select);
        },
      ),
      findUnique: vi.fn(
        async ({ where, select }: { where: { id: string }; select?: Record<string, boolean> }) => {
          const row = store.attempts.get(where.id);
          if (!row) return null;
          if (select?.proofs) {
            const proofs = store.proofs
              .filter((p) => p.attemptId === row.id)
              .map((p) => ({ badgeType: p.badgeType }));
            return { ...pick(row, select), proofs };
          }
          return pick(row, select);
        },
      ),
      update: vi.fn(
        async ({
          where,
          data,
          select,
        }: {
          where: { id: string };
          data: Record<string, unknown>;
          select?: Record<string, boolean>;
        }) => {
          const row = store.attempts.get(where.id);
          if (!row) p2002();
          const r = row!;
          if (data.accumulatedScore && typeof data.accumulatedScore === "object") {
            const inc = (data.accumulatedScore as { increment: number }).increment;
            r.accumulatedScore += inc;
          }
          if (typeof data.status === "string") r.status = data.status;
          if (data.satisfiedAt instanceof Date) r.satisfiedAt = data.satisfiedAt;
          if (data.consumedAt instanceof Date) r.consumedAt = data.consumedAt;
          return pick(r, select);
        },
      ),
      updateMany: vi.fn(
        async ({
          where,
          data,
        }: {
          where: { id: string; status?: string };
          data: Record<string, unknown>;
        }) => {
          const row = store.attempts.get(where.id);
          if (!row) return { count: 0 };
          if (where.status !== undefined && row.status !== where.status) return { count: 0 };
          if (typeof data.status === "string") row.status = data.status;
          if (data.consumedAt instanceof Date) row.consumedAt = data.consumedAt;
          return { count: 1 };
        },
      ),
    },
    recoveryProof: {
      create: vi.fn(
        async ({ data }: { data: { attemptId: string; badgeType: string; weight: number } }) => {
          // (attemptId, badgeType) is @@unique — the no-double-count gate.
          if (store.proofs.some((p) => p.attemptId === data.attemptId && p.badgeType === data.badgeType)) {
            p2002();
          }
          const row: ProofRow = { id: nextId("rp"), ...data };
          store.proofs.push(row);
          return row;
        },
      ),
    },
    badge: {
      findFirst: vi.fn(
        async ({ where }: { where: { userId: string; type: string; isPublic: boolean } }) => {
          const row = store.badges.find(
            (b) =>
              b.userId === where.userId && b.type === where.type && b.isPublic === where.isPublic,
          );
          return row ? { id: row.id } : null;
        },
      ),
    },
    // Interactive transaction: run the callback against the same client. The
    // in-memory store mutates in place, and a thrown error (e.g. the P2002 from
    // a duplicate proof insert) propagates exactly as Prisma would. The engine
    // writes the proof first (the throwing op) then the increment, so a thrown
    // proof insert means no increment ran.
    $transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => fn(prismaClient)),
  };

  return { db: store, client: prismaClient };
});

vi.mock("@/lib/prisma", () => ({ prisma: client }));

// The engine's no-double-count rejection keys on
// `err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002"`.
// Our in-memory mock throws a plain Error tagged with that name + code, so
// stub the class with an instanceof that recognizes it. recoveryWeightFor /
// RECOVERY_ELIGIBLE_TYPES / RECOVERY_THRESHOLD stay real (the real assurance
// module is imported normally below).
vi.mock("@/generated/prisma", () => ({
  Prisma: {
    PrismaClientKnownRequestError: class {
      static [Symbol.hasInstance](instance: unknown): boolean {
        return (
          typeof instance === "object" &&
          instance !== null &&
          (instance as { name?: string }).name === "PrismaClientKnownRequestError"
        );
      }
    },
  },
}));

// issueRecoveryTicket is the spine (separately tested). Stub it so consume
// tests don't need AUTH_SECRET and we can assert the userId flows through.
vi.mock("@/lib/recovery-ticket", () => ({
  issueRecoveryTicket: vi.fn(async (userId: string) => `ticket-for:${userId}`),
}));

import { RECOVERY_THRESHOLD } from "@/lib/assurance";
import { issueRecoveryTicket } from "@/lib/recovery-ticket";

import {
  consumeSatisfiedAttempt,
  getAttemptStatus,
  recordReProof,
  startRecoveryAttempt,
} from "./recovery-threshold";

// Seed a pending attempt directly into the store, with the user holding the
// given (type, isPublic) badges. Returns the attemptId + nonce.
function seedAttempt(opts: {
  userId?: string;
  requiredScore?: number;
  expiresInMs?: number;
  status?: string;
  accumulatedScore?: number;
  holds?: Array<{ type: string; isPublic?: boolean }>;
}): { attemptId: string; nonce: string; userId: string } {
  const userId = opts.userId ?? "user_1";
  const attemptId = client.nextId("ra");
  const nonce = client.nextId("nonce");
  db.attempts.set(attemptId, {
    id: attemptId,
    userId,
    nonce,
    status: opts.status ?? "pending",
    requiredScore: opts.requiredScore ?? RECOVERY_THRESHOLD,
    accumulatedScore: opts.accumulatedScore ?? 0,
    expiresAt: new Date(Date.now() + (opts.expiresInMs ?? 15 * 60 * 1000)),
    satisfiedAt: opts.status === "satisfied" ? new Date() : null,
    consumedAt: null,
  });
  for (const h of opts.holds ?? []) {
    db.badges.push({
      id: client.nextId("badge"),
      userId,
      type: h.type,
      isPublic: h.isPublic ?? false,
    });
  }
  return { attemptId, nonce, userId };
}

beforeEach(() => {
  db.attempts.clear();
  db.proofs = [];
  db.badges = [];
  db.seq = 0;
  vi.clearAllMocks();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("startRecoveryAttempt", () => {
  it("creates a pending attempt with a fresh nonce and the default threshold", async () => {
    const started = await startRecoveryAttempt("user_1");
    expect(started.requiredScore).toBe(RECOVERY_THRESHOLD);
    expect(started.nonce).toMatch(/.+/);
    const stored = db.attempts.get(started.attemptId)!;
    expect(stored.status).toBe("pending");
    expect(stored.accumulatedScore).toBe(0);
    expect(stored.userId).toBe("user_1");
    expect(stored.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("mints a distinct nonce per attempt", async () => {
    const a = await startRecoveryAttempt("user_1");
    const b = await startRecoveryAttempt("user_1");
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.attemptId).not.toBe(b.attemptId);
  });

  it("honors an explicit requiredScore", async () => {
    const started = await startRecoveryAttempt("user_1", 60);
    expect(started.requiredScore).toBe(60);
    expect(db.attempts.get(started.attemptId)!.requiredScore).toBe(60);
  });
});

describe("recordReProof — weight correctness", () => {
  it("a tlsn-attestation (IAL3) contributes 100 and satisfies alone", async () => {
    const { attemptId } = seedAttempt({ holds: [{ type: "tlsn-attestation" }] });
    const r = await recordReProof(attemptId, "tlsn-attestation");
    expect(r).toEqual({ ok: true, accumulatedScore: 100, requiredScore: 100, satisfied: true });
    expect(db.attempts.get(attemptId)!.status).toBe("satisfied");
    expect(db.attempts.get(attemptId)!.satisfiedAt).toBeInstanceOf(Date);
  });

  it("a github oauth-account contributes 20", async () => {
    const { attemptId } = seedAttempt({ holds: [{ type: "oauth-account" }] });
    const r = await recordReProof(attemptId, "oauth-account", { provenance: "github" });
    expect(r).toMatchObject({ ok: true, accumulatedScore: 20, satisfied: false });
  });

  it("a discord oauth-account contributes only 10 (low provenance)", async () => {
    const { attemptId } = seedAttempt({ holds: [{ type: "oauth-account" }] });
    const r = await recordReProof(attemptId, "oauth-account", { provenance: "discord" });
    expect(r).toMatchObject({ ok: true, accumulatedScore: 10 });
  });

  it("an email-domain contributes 15", async () => {
    const { attemptId } = seedAttempt({ holds: [{ type: "email-domain" }] });
    const r = await recordReProof(attemptId, "email-domain");
    expect(r).toMatchObject({ ok: true, accumulatedScore: 15 });
  });
});

describe("recordReProof — public-badge exclusion (DESIGNDECISIONS #8)", () => {
  it("a public badge of the type does NOT count (badge-not-held)", async () => {
    const { attemptId } = seedAttempt({ holds: [{ type: "oauth-account", isPublic: true }] });
    const r = await recordReProof(attemptId, "oauth-account", { provenance: "github" });
    expect(r).toEqual({ ok: false, reason: "badge-not-held" });
    expect(db.proofs.length).toBe(0);
  });

  it("a non-public badge of the same type DOES count even if a public one also exists", async () => {
    const { attemptId } = seedAttempt({
      holds: [
        { type: "oauth-account", isPublic: true },
        { type: "oauth-account", isPublic: false },
      ],
    });
    const r = await recordReProof(attemptId, "oauth-account", { provenance: "github" });
    expect(r).toMatchObject({ ok: true, accumulatedScore: 20 });
  });
});

describe("recordReProof — eligibility + holding", () => {
  it("rejects an ineligible type (invite-code) even if the user holds it", async () => {
    const { attemptId } = seedAttempt({ holds: [{ type: "invite-code" }] });
    const r = await recordReProof(attemptId, "invite-code");
    expect(r).toEqual({ ok: false, reason: "type-not-eligible" });
    expect(db.proofs.length).toBe(0);
  });

  it("rejects an eligible type the user does NOT hold", async () => {
    const { attemptId } = seedAttempt({ holds: [{ type: "email-domain" }] });
    const r = await recordReProof(attemptId, "oauth-account", { provenance: "github" });
    expect(r).toEqual({ ok: false, reason: "badge-not-held" });
    expect(db.proofs.length).toBe(0);
  });

  it("a held badge of a DIFFERENT user does not satisfy holding for this attempt", async () => {
    const { attemptId } = seedAttempt({ userId: "user_1", holds: [] });
    // Seed a badge for a different user.
    db.badges.push({ id: "b_other", userId: "user_2", type: "email-domain", isPublic: false });
    const r = await recordReProof(attemptId, "email-domain");
    expect(r).toEqual({ ok: false, reason: "badge-not-held" });
  });
});

describe("recordReProof — no double-count (the UNIQUE gate)", () => {
  it("rejects a second proof of the same type for the same attempt", async () => {
    const { attemptId } = seedAttempt({ holds: [{ type: "oauth-account" }] });
    const first = await recordReProof(attemptId, "oauth-account", { provenance: "github" });
    expect(first).toMatchObject({ ok: true, accumulatedScore: 20 });
    const second = await recordReProof(attemptId, "oauth-account", { provenance: "github" });
    expect(second).toEqual({ ok: false, reason: "already-proven" });
    // The score must not have moved on the rejected second proof.
    expect(db.attempts.get(attemptId)!.accumulatedScore).toBe(20);
    expect(db.proofs.length).toBe(1);
  });

  it("DISTINCT eligible types both count toward the threshold", async () => {
    const { attemptId } = seedAttempt({
      holds: [{ type: "email-domain" }, { type: "email-exact" }, { type: "oauth-account" }],
    });
    await recordReProof(attemptId, "email-domain"); // 15
    await recordReProof(attemptId, "email-exact"); // 15
    const r = await recordReProof(attemptId, "oauth-account", { provenance: "github" }); // 20
    expect(r).toMatchObject({ ok: true, accumulatedScore: 50, satisfied: false });
  });
});

describe("recordReProof — attempt liveness", () => {
  it("rejects a nonexistent attempt", async () => {
    const r = await recordReProof("ra_missing", "email-domain");
    expect(r).toEqual({ ok: false, reason: "attempt-not-found" });
  });

  it("rejects an expired attempt (nonce freshness window closed)", async () => {
    const { attemptId } = seedAttempt({ expiresInMs: -1000, holds: [{ type: "email-domain" }] });
    const r = await recordReProof(attemptId, "email-domain");
    expect(r).toEqual({ ok: false, reason: "attempt-expired" });
    expect(db.proofs.length).toBe(0);
  });

  it("rejects an already-satisfied attempt (no further accrual)", async () => {
    const { attemptId } = seedAttempt({ status: "satisfied", holds: [{ type: "email-domain" }] });
    const r = await recordReProof(attemptId, "email-domain");
    expect(r).toEqual({ ok: false, reason: "attempt-not-pending" });
  });

  it("rejects a consumed attempt", async () => {
    const { attemptId } = seedAttempt({ status: "consumed", holds: [{ type: "email-domain" }] });
    const r = await recordReProof(attemptId, "email-domain");
    expect(r).toEqual({ ok: false, reason: "attempt-not-pending" });
  });
});

describe("recordReProof — threshold satisfaction shapes", () => {
  it("one IAL3 proof alone satisfies", async () => {
    const { attemptId } = seedAttempt({ holds: [{ type: "tlsn-attestation" }] });
    const r = await recordReProof(attemptId, "tlsn-attestation");
    expect(r).toMatchObject({ satisfied: true });
  });

  it("several IAL1 proofs are needed: email + 4 distinct-ish fall short, the crossing one satisfies", async () => {
    // Threshold 100. email-domain(15) + email-exact(15) + oauth github(20) = 50.
    // Then an IAL2-grade residency (60) crosses: 110 >= 100.
    const { attemptId } = seedAttempt({
      holds: [
        { type: "email-domain" },
        { type: "email-exact" },
        { type: "oauth-account" },
        { type: "residency-state" },
      ],
    });
    expect(await recordReProof(attemptId, "email-domain")).toMatchObject({ satisfied: false, accumulatedScore: 15 });
    expect(await recordReProof(attemptId, "email-exact")).toMatchObject({ satisfied: false, accumulatedScore: 30 });
    expect(
      await recordReProof(attemptId, "oauth-account", { provenance: "github" }),
    ).toMatchObject({ satisfied: false, accumulatedScore: 50 });
    // residency-state is eligible? It is NOT in RECOVERY_ELIGIBLE_TYPES — only
    // oauth/email/tlsn are re-provable. So it must be rejected, proving that
    // weight alone never lets an un-re-provable type count.
    const res = await recordReProof(attemptId, "residency-state");
    expect(res).toEqual({ ok: false, reason: "type-not-eligible" });
    expect(db.attempts.get(attemptId)!.status).toBe("pending");
  });

  it("exactly reaching the threshold (==) satisfies, not just exceeding", async () => {
    // requiredScore 20, one github oauth = 20 -> satisfied at equality.
    const { attemptId } = seedAttempt({ requiredScore: 20, holds: [{ type: "oauth-account" }] });
    const r = await recordReProof(attemptId, "oauth-account", { provenance: "github" });
    expect(r).toMatchObject({ ok: true, accumulatedScore: 20, satisfied: true });
    expect(db.attempts.get(attemptId)!.status).toBe("satisfied");
  });

  it("an in-progress score below threshold leaves the attempt pending", async () => {
    const { attemptId } = seedAttempt({ requiredScore: 100, holds: [{ type: "oauth-account" }] });
    const r = await recordReProof(attemptId, "oauth-account", { provenance: "github" });
    expect(r).toMatchObject({ satisfied: false });
    expect(db.attempts.get(attemptId)!.status).toBe("pending");
    expect(db.attempts.get(attemptId)!.satisfiedAt).toBeNull();
  });
});

describe("consumeSatisfiedAttempt — one-shot redemption", () => {
  it("mints a ticket for a satisfied, unexpired, unconsumed attempt and marks it consumed", async () => {
    const { attemptId, userId } = seedAttempt({ status: "satisfied", holds: [] });
    const r = await consumeSatisfiedAttempt(attemptId);
    expect(r).toEqual({ ok: true, ticket: `ticket-for:${userId}`, userId });
    expect(issueRecoveryTicket).toHaveBeenCalledWith(userId);
    expect(db.attempts.get(attemptId)!.status).toBe("consumed");
    expect(db.attempts.get(attemptId)!.consumedAt).toBeInstanceOf(Date);
  });

  it("is one-shot: a second consume of the same attempt is rejected and mints no new ticket", async () => {
    const { attemptId } = seedAttempt({ status: "satisfied", holds: [] });
    expect(await consumeSatisfiedAttempt(attemptId)).toMatchObject({ ok: true });
    const second = await consumeSatisfiedAttempt(attemptId);
    expect(second).toEqual({ ok: false, reason: "already-consumed" });
    expect(issueRecoveryTicket).toHaveBeenCalledTimes(1);
  });

  it("rejects an attempt that is not yet satisfied (still pending)", async () => {
    const { attemptId } = seedAttempt({ status: "pending", holds: [] });
    const r = await consumeSatisfiedAttempt(attemptId);
    expect(r).toEqual({ ok: false, reason: "not-satisfied" });
    expect(issueRecoveryTicket).not.toHaveBeenCalled();
  });

  it("rejects a satisfied-but-expired attempt (no stale recovery)", async () => {
    const { attemptId } = seedAttempt({ status: "satisfied", expiresInMs: -1000, holds: [] });
    const r = await consumeSatisfiedAttempt(attemptId);
    expect(r).toEqual({ ok: false, reason: "expired" });
    expect(issueRecoveryTicket).not.toHaveBeenCalled();
  });

  it("rejects a nonexistent attempt", async () => {
    const r = await consumeSatisfiedAttempt("ra_missing");
    expect(r).toEqual({ ok: false, reason: "attempt-not-found" });
  });
});

describe("end-to-end accounting: satisfy then consume", () => {
  it("drives a real attempt from start through satisfaction to a recovery ticket", async () => {
    const started = await startRecoveryAttempt("user_99");
    db.badges.push({ id: "b1", userId: "user_99", type: "tlsn-attestation", isPublic: false });

    const reproof = await recordReProof(started.attemptId, "tlsn-attestation");
    expect(reproof).toMatchObject({ ok: true, satisfied: true, accumulatedScore: 100 });

    const status = await getAttemptStatus(started.attemptId);
    expect(status).toMatchObject({ status: "satisfied", accumulatedScore: 100, provenTypes: ["tlsn-attestation"] });

    const consumed = await consumeSatisfiedAttempt(started.attemptId);
    expect(consumed).toEqual({ ok: true, ticket: "ticket-for:user_99", userId: "user_99" });
  });
});

describe("getAttemptStatus", () => {
  it("returns null for a missing attempt", async () => {
    expect(await getAttemptStatus("nope")).toBeNull();
  });

  it("reflects the proven types and live tally", async () => {
    const { attemptId } = seedAttempt({ holds: [{ type: "email-domain" }, { type: "oauth-account" }] });
    await recordReProof(attemptId, "email-domain");
    await recordReProof(attemptId, "oauth-account", { provenance: "github" });
    const status = await getAttemptStatus(attemptId);
    expect(status!.accumulatedScore).toBe(35);
    expect(status!.provenTypes.sort()).toEqual(["email-domain", "oauth-account"]);
  });
});
