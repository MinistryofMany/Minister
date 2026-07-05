import { createHash } from "node:crypto";

import { beforeEach, describe, expect, it, vi } from "vitest";

// In-memory NullifierRpCheck store. Models the @@unique([entryRef, clientId])
// constraint by throwing a real P2002 on a duplicate composite key, so the
// concurrent-first-disclosure race path is exercised against the same failure
// Postgres produces.
const h = vi.hoisted(() => {
  const p2002 = (): Error =>
    Object.assign(new Error("Unique constraint failed"), { code: "P2002" });

  interface Row {
    id: string;
    entryRef: string;
    clientId: string;
    salt: Uint8Array;
    check: Uint8Array;
  }
  const store = { rows: [] as Row[] };
  let seq = 1;

  const findUnique = vi.fn(
    async (args: { where: { entryRef_clientId: { entryRef: string; clientId: string } } }) => {
      const { entryRef, clientId } = args.where.entryRef_clientId;
      const row = store.rows.find((r) => r.entryRef === entryRef && r.clientId === clientId);
      return row ? { salt: row.salt, check: row.check } : null;
    },
  );

  const create = vi.fn(
    async (args: {
      data: { entryRef: string; clientId: string; salt: Uint8Array; check: Uint8Array };
    }) => {
      const { entryRef, clientId } = args.data;
      if (store.rows.some((r) => r.entryRef === entryRef && r.clientId === clientId)) {
        throw p2002();
      }
      const row: Row = { id: `check_${seq++}`, ...args.data };
      store.rows.push(row);
      return row;
    },
  );

  return { store, findUnique, create };
});

vi.mock("@/lib/prisma", () => ({
  prisma: { nullifierRpCheck: { findUnique: h.findUnique, create: h.create } },
}));

import { assertNullifierDriftConsistent } from "./drift-cache";

const digest = (salt: Uint8Array, nrp: string): Buffer =>
  createHash("sha256").update(salt).update(Buffer.from(nrp, "utf8")).digest();

describe("assertNullifierDriftConsistent", () => {
  beforeEach(() => {
    h.store.rows.length = 0;
    h.findUnique.mockClear();
    h.create.mockClear();
  });

  it("records a baseline on first disclosure (no row yet)", async () => {
    await assertNullifierDriftConsistent("ref-1", "client-A", "mnv1:VALUE_ONE");
    expect(h.store.rows).toHaveLength(1);
    const row = h.store.rows[0]!;
    expect(row.entryRef).toBe("ref-1");
    expect(row.clientId).toBe("client-A");
    expect(row.salt).toHaveLength(16);
    // check == SHA-256(salt || utf8(nrp))
    expect(Buffer.from(row.check).equals(digest(row.salt, "mnv1:VALUE_ONE"))).toBe(true);
  });

  it("passes when a later disclosure matches the recorded value", async () => {
    await assertNullifierDriftConsistent("ref-1", "client-A", "mnv1:VALUE_ONE");
    await expect(
      assertNullifierDriftConsistent("ref-1", "client-A", "mnv1:VALUE_ONE"),
    ).resolves.toBeUndefined();
    // No second row inserted — the baseline is reused.
    expect(h.store.rows).toHaveLength(1);
  });

  it("FAILS CLOSED (throws) when Signet drifts the value for the same credential", async () => {
    await assertNullifierDriftConsistent("ref-1", "client-A", "mnv1:VALUE_ONE");
    await expect(
      assertNullifierDriftConsistent("ref-1", "client-A", "mnv1:DIFFERENT_now"),
    ).rejects.toThrow(/drift detected/);
  });

  it("keeps separate baselines per (entryRef, clientId) — different RPs never collide", async () => {
    await assertNullifierDriftConsistent("ref-1", "client-A", "mnv1:AAA");
    await assertNullifierDriftConsistent("ref-1", "client-B", "mnv1:BBB");
    await assertNullifierDriftConsistent("ref-2", "client-A", "mnv1:CCC");
    expect(h.store.rows).toHaveLength(3);
    // Each is independently re-checkable.
    await expect(
      assertNullifierDriftConsistent("ref-1", "client-B", "mnv1:BBB"),
    ).resolves.toBeUndefined();
    await expect(assertNullifierDriftConsistent("ref-1", "client-B", "mnv1:AAA")).rejects.toThrow(
      /drift detected/,
    );
  });

  it("per-row salts mean identical N_rp across rows produce UNRELATED digests (no M1 oracle)", async () => {
    // Same nullifier value at two different (entryRef,clientId) rows. If the
    // cache carried cross-row equality structure, the two `check` bytes would
    // match; the per-row random salt guarantees they (almost surely) do not.
    await assertNullifierDriftConsistent("ref-1", "client-A", "mnv1:SAME_VALUE");
    await assertNullifierDriftConsistent("ref-2", "client-A", "mnv1:SAME_VALUE");
    const [a, b] = h.store.rows;
    expect(Buffer.from(a!.salt).equals(Buffer.from(b!.salt))).toBe(false);
    expect(Buffer.from(a!.check).equals(Buffer.from(b!.check))).toBe(false);
  });

  it("resolves a concurrent first-disclosure race (P2002) by comparing against the winner", async () => {
    // Simulate a racing insert landing between our findUnique and our create:
    // seed the winner row just before create runs, so create throws P2002 and
    // the fallback re-read must accept the matching value.
    const winnerSalt = Buffer.from("0123456789abcdef", "utf8").subarray(0, 16);
    h.create.mockImplementationOnce(async () => {
      h.store.rows.push({
        id: "winner",
        entryRef: "ref-race",
        clientId: "client-A",
        salt: winnerSalt,
        check: digest(winnerSalt, "mnv1:RACE_VALUE"),
      });
      throw Object.assign(new Error("Unique constraint failed"), { code: "P2002" });
    });
    await expect(
      assertNullifierDriftConsistent("ref-race", "client-A", "mnv1:RACE_VALUE"),
    ).resolves.toBeUndefined();
  });

  it("fails closed when a concurrent first-disclosure race disagrees on the value", async () => {
    const winnerSalt = Buffer.from("fedcba9876543210", "utf8").subarray(0, 16);
    h.create.mockImplementationOnce(async () => {
      h.store.rows.push({
        id: "winner",
        entryRef: "ref-race2",
        clientId: "client-A",
        salt: winnerSalt,
        check: digest(winnerSalt, "mnv1:WINNER_VALUE"),
      });
      throw Object.assign(new Error("Unique constraint failed"), { code: "P2002" });
    });
    await expect(
      assertNullifierDriftConsistent("ref-race2", "client-A", "mnv1:LOSER_VALUE"),
    ).rejects.toThrow(/drift detected/);
  });
});
