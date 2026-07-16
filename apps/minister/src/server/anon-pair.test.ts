import { beforeEach, describe, expect, it, vi } from "vitest";

// Unit tests for the QR device-pairing relay logic. @/lib/prisma and @/lib/audit
// are mocked. The prisma fake implements the actual `updateMany` WHERE semantics
// (id + userId + state + expiresAt) and `findUnique` against an in-memory row, so
// these tests exercise the REAL conditions — in particular the C2 same-account
// condition on seal, which is the sole barrier against the remote phish.

interface Row {
  id: string;
  userId: string;
  state: string;
  sealedPayload: string | null;
  creatorSecretHash: string;
  expiresAt: Date;
  creatorIp: string | null;
  creatorUa: string | null;
  creatorCountry: string | null;
  creatorCity: string | null;
  sealerIp: string | null;
  sealerUa: string | null;
}

const h = vi.hoisted(() => {
  const rows = new Map<string, Row>();

  function matchesWhere(row: Row, where: Record<string, unknown>): boolean {
    if (where.id !== undefined && row.id !== where.id) return false;
    if (where.userId !== undefined && row.userId !== where.userId) return false;
    if (where.state !== undefined && row.state !== where.state) return false;
    if (where.expiresAt && typeof where.expiresAt === "object") {
      const gt = (where.expiresAt as { gt?: Date }).gt;
      if (gt && !(row.expiresAt > gt)) return false;
    }
    return true;
  }

  const db = {
    anonPairSession: {
      create: vi.fn(async ({ data }: { data: Row }) => {
        rows.set(data.id, { ...data });
        return { ...data };
      }),
      findUnique: vi.fn(async ({ where }: { where: { id: string } }) => {
        const row = rows.get(where.id);
        return row ? { ...row } : null;
      }),
      updateMany: vi.fn(
        async ({
          where,
          data,
        }: {
          where: Record<string, unknown>;
          data: Record<string, unknown>;
        }) => {
          let count = 0;
          for (const row of rows.values()) {
            if (matchesWhere(row, where)) {
              Object.assign(row, data);
              count += 1;
            }
          }
          return { count };
        },
      ),
    },
  };

  return { rows, db, audit: vi.fn((..._args: unknown[]) => Promise.resolve()) };
});

vi.mock("@/lib/prisma", () => ({ prisma: h.db }));
vi.mock("@/lib/audit", () => ({ audit: h.audit }));

import { createHash } from "node:crypto";

import { claimPairSession, sealPairSession } from "@/server/anon-pair";

const hashSecret = (s: string) => createHash("sha256").update(s).digest("hex");

function seedRow(overrides: Partial<Row> = {}): Row {
  const row: Row = {
    id: "sid_A",
    userId: "user_A",
    state: "waiting",
    sealedPayload: null,
    creatorSecretHash: hashSecret("secret_A"),
    expiresAt: new Date(Date.now() + 60_000),
    creatorIp: "1.2.3.4",
    creatorUa: "ua",
    creatorCountry: "US",
    creatorCity: "Cleveland",
    sealerIp: null,
    sealerUa: null,
    ...overrides,
  };
  h.rows.set(row.id, row);
  return row;
}

const PAYLOAD = "x".repeat(86);

beforeEach(() => {
  vi.clearAllMocks();
  h.rows.clear();
});

describe("C2 (SECURITY CONTROL): the seal same-account check blocks cross-user deposit", () => {
  it("a sealer authenticated as account B CANNOT deposit into account A's session", async () => {
    seedRow(); // owned by user_A

    const result = await sealPairSession({
      sessionId: "sid_A",
      sessionUserId: "user_B", // attacker's OWN authenticated session
      payload: PAYLOAD,
      ip: "9.9.9.9",
      ua: "attacker",
    });

    // The atomic update matched zero rows (WHERE userId = user_B), so the payload
    // was NEVER written to account A's row — the load-bearing barrier holds.
    expect(result).toEqual({ ok: false, reason: "cross_account" });
    const row = h.rows.get("sid_A")!;
    expect(row.sealedPayload).toBeNull();
    expect(row.state).toBe("waiting");
    expect(row.sealerIp).toBeNull();
  });

  it("the rightful account's sealer DOES deposit", async () => {
    seedRow();
    const result = await sealPairSession({
      sessionId: "sid_A",
      sessionUserId: "user_A",
      payload: PAYLOAD,
      ip: "1.2.3.4",
      ua: "mine",
    });
    expect(result).toEqual({ ok: true });
    const row = h.rows.get("sid_A")!;
    expect(row.state).toBe("sealed");
    expect(row.sealedPayload).toBe(PAYLOAD);
  });
});

describe("seal failure diagnostics (copy only — the WHERE is the barrier)", () => {
  it("expired waiting session → expired", async () => {
    seedRow({ expiresAt: new Date(Date.now() - 1000) });
    const r = await sealPairSession({
      sessionId: "sid_A",
      sessionUserId: "user_A",
      payload: PAYLOAD,
      ip: null,
      ua: null,
    });
    expect(r).toEqual({ ok: false, reason: "expired" });
  });

  it("already-sealed session → already_used", async () => {
    seedRow({ state: "sealed", sealedPayload: PAYLOAD });
    const r = await sealPairSession({
      sessionId: "sid_A",
      sessionUserId: "user_A",
      payload: PAYLOAD,
      ip: null,
      ua: null,
    });
    expect(r).toEqual({ ok: false, reason: "already_used" });
  });

  it("unknown session → not_found", async () => {
    const r = await sealPairSession({
      sessionId: "sid_missing",
      sessionUserId: "user_A",
      payload: PAYLOAD,
      ip: null,
      ua: null,
    });
    expect(r).toEqual({ ok: false, reason: "not_found" });
  });
});

describe("claim: single-use handoff, NULLs the payload atomically", () => {
  it("returns the payload once, then null (single-use)", async () => {
    seedRow({ state: "sealed", sealedPayload: PAYLOAD });

    const first = await claimPairSession({
      sessionId: "sid_A",
      sessionUserId: "user_A",
      creatorSecret: "secret_A",
    });
    expect(first).toEqual({ ok: true, state: "claimed", payload: PAYLOAD });
    expect(h.rows.get("sid_A")!.sealedPayload).toBeNull();

    const second = await claimPairSession({
      sessionId: "sid_A",
      sessionUserId: "user_A",
      creatorSecret: "secret_A",
    });
    expect(second).toEqual({ ok: true, state: "claimed", payload: null });
  });

  it("a wrong creator secret is rejected", async () => {
    seedRow({ state: "sealed", sealedPayload: PAYLOAD });
    const r = await claimPairSession({
      sessionId: "sid_A",
      sessionUserId: "user_A",
      creatorSecret: "wrong",
    });
    expect(r).toEqual({ ok: false, reason: "bad_secret" });
    expect(h.rows.get("sid_A")!.sealedPayload).toBe(PAYLOAD); // untouched
  });

  it("a claim from a different account is forbidden (defense in depth)", async () => {
    seedRow({ state: "sealed", sealedPayload: PAYLOAD });
    const r = await claimPairSession({
      sessionId: "sid_A",
      sessionUserId: "user_B",
      creatorSecret: "secret_A",
    });
    expect(r).toEqual({ ok: false, reason: "forbidden" });
  });

  it("waiting session → keep polling", async () => {
    seedRow();
    const r = await claimPairSession({
      sessionId: "sid_A",
      sessionUserId: "user_A",
      creatorSecret: "secret_A",
    });
    expect(r).toEqual({ ok: true, state: "waiting" });
  });
});
