import { beforeEach, describe, expect, it, vi } from "vitest";

import { Prisma } from "@/generated/prisma";

import { SHARD_SIZE_BITS } from "./constants";

// In-memory prisma double that ENFORCES the three unique constraints the
// allocator relies on, throwing real Prisma P2002 errors (so `instanceof`
// matches) with the right meta.target so the allocator's constraint routing is
// exercised for real. `p2002` is a function declaration (hoisted) so the hoisted
// mock factory can reference it; it uses the real Prisma class at CALL time.

interface ListRow {
  id: string;
  clientId: string;
  shardNo: number;
}
interface EntryRow {
  id: string;
  statusAnchor: string;
  clientId: string;
  listId: string;
  bitIndex: number;
  revokedAt: Date | null;
  revealAfter: Date | null;
}
interface AnchorRevRow {
  statusAnchor: string;
  revokedAt: Date;
}

function p2002(target: string[]): Prisma.PrismaClientKnownRequestError {
  return new Prisma.PrismaClientKnownRequestError("Unique constraint failed", {
    code: "P2002",
    clientVersion: "test",
    meta: { target },
  });
}

const h = vi.hoisted(() => {
  const store = {
    lists: [] as ListRow[],
    entries: [] as EntryRow[],
    anchorRevs: [] as AnchorRevRow[],
    seq: 0,
    updateCalls: 0,
    // When set, the next entry create pushes an anchorRev row (a kick that COMMITS
    // during this allocation) so the post-create reconcile is exercised.
    revokeOnCreate: false,
    // When set, the next entry create throws an anchor-P2002 and a "winner" row
    // for that (anchor, clientId) appears — simulating a concurrent disclosure.
    raceAnchor: null as {
      statusAnchor: string;
      clientId: string;
      listId: string;
      bitIndex: number;
    } | null,
  };

  const prismaMock = {
    statusAnchorRevocation: {
      findUnique: vi.fn(async ({ where }: { where: { statusAnchor: string } }) => {
        const row = store.anchorRevs.find((r) => r.statusAnchor === where.statusAnchor);
        return row ? { revokedAt: row.revokedAt } : null;
      }),
    },
    statusList: {
      create: vi.fn(async ({ data }: { data: { clientId: string; shardNo: number } }) => {
        if (store.lists.some((l) => l.clientId === data.clientId && l.shardNo === data.shardNo)) {
          throw p2002(["clientId", "shardNo"]);
        }
        const row: ListRow = {
          id: `list_${++store.seq}`,
          clientId: data.clientId,
          shardNo: data.shardNo,
        };
        store.lists.push(row);
        return { id: row.id, shardNo: row.shardNo };
      }),
      findFirst: vi.fn(async ({ where }: { where: { clientId: string } }) => {
        const shards = store.lists
          .filter((l) => l.clientId === where.clientId)
          .sort((a, b) => b.shardNo - a.shardNo);
        const top = shards[0];
        return top ? { id: top.id, shardNo: top.shardNo } : null;
      }),
      findUnique: vi.fn(
        async ({
          where,
        }: {
          where: { clientId_shardNo: { clientId: string; shardNo: number } };
        }) => {
          const { clientId, shardNo } = where.clientId_shardNo;
          const row = store.lists.find((l) => l.clientId === clientId && l.shardNo === shardNo);
          return row ? { id: row.id, shardNo: row.shardNo } : null;
        },
      ),
      update: vi.fn(async () => {
        store.updateCalls += 1;
        return {};
      }),
    },
    badgeStatusEntry: {
      findUnique: vi.fn(
        async ({
          where,
        }: {
          where: { statusAnchor_clientId: { statusAnchor: string; clientId: string } };
        }) => {
          const { statusAnchor, clientId } = where.statusAnchor_clientId;
          const row = store.entries.find(
            (e) => e.statusAnchor === statusAnchor && e.clientId === clientId,
          );
          return row ? { listId: row.listId, bitIndex: row.bitIndex } : null;
        },
      ),
      count: vi.fn(async ({ where }: { where: { listId: string } }) => {
        return store.entries.filter((e) => e.listId === where.listId).length;
      }),
      updateMany: vi.fn(
        async ({
          where,
          data,
        }: {
          where: { statusAnchor: string; clientId: string; revokedAt: null };
          data: { revokedAt: Date; revealAfter: Date };
        }) => {
          let count = 0;
          for (const e of store.entries) {
            if (
              e.statusAnchor === where.statusAnchor &&
              e.clientId === where.clientId &&
              e.revokedAt === null
            ) {
              e.revokedAt = data.revokedAt;
              e.revealAfter = data.revealAfter;
              count += 1;
            }
          }
          return { count };
        },
      ),
      create: vi.fn(
        async ({
          data,
        }: {
          data: {
            statusAnchor: string;
            clientId: string;
            listId: string;
            bitIndex: number;
            revokedAt?: Date;
            revealAfter?: Date;
          };
        }) => {
          if (
            store.raceAnchor &&
            store.raceAnchor.statusAnchor === data.statusAnchor &&
            store.raceAnchor.clientId === data.clientId
          ) {
            // A concurrent writer won: materialize its row, then reject ours.
            store.entries.push({
              id: `e_${++store.seq}`,
              ...store.raceAnchor,
              revokedAt: null,
              revealAfter: null,
            });
            store.raceAnchor = null;
            throw p2002(["statusAnchor", "clientId"]);
          }
          if (
            store.entries.some(
              (e) => e.statusAnchor === data.statusAnchor && e.clientId === data.clientId,
            )
          ) {
            throw p2002(["statusAnchor", "clientId"]);
          }
          if (store.entries.some((e) => e.listId === data.listId && e.bitIndex === data.bitIndex)) {
            throw p2002(["listId", "bitIndex"]);
          }
          store.entries.push({
            id: `e_${++store.seq}`,
            statusAnchor: data.statusAnchor,
            clientId: data.clientId,
            listId: data.listId,
            bitIndex: data.bitIndex,
            revokedAt: data.revokedAt ?? null,
            revealAfter: data.revealAfter ?? null,
          });
          // Simulate a kick that COMMITS during this allocation: the tombstone
          // appears AFTER the (clear) entry was created, exercising the reconcile.
          if (store.revokeOnCreate) {
            store.anchorRevs.push({ statusAnchor: data.statusAnchor, revokedAt: new Date() });
            store.revokeOnCreate = false;
          }
          return {};
        },
      ),
    },
  };

  return { store, prismaMock };
});
const store = h.store;

vi.mock("@/lib/prisma", () => ({ prisma: h.prismaMock }));

import { allocateStatusEntry } from "./allocate";

beforeEach(() => {
  store.lists = [];
  store.entries = [];
  store.anchorRevs = [];
  store.seq = 0;
  store.updateCalls = 0;
  store.revokeOnCreate = false;
  store.raceAnchor = null;
  vi.clearAllMocks();
});

describe("allocateStatusEntry", () => {
  it("creates shard 0 and allocates a random in-range index on first disclosure", async () => {
    const alloc = await allocateStatusEntry({ statusAnchor: "gm:m1", clientId: "mc_rp" });
    expect(store.lists).toHaveLength(1);
    expect(store.lists[0]!.shardNo).toBe(0);
    expect(alloc.bitIndex).toBeGreaterThanOrEqual(0);
    expect(alloc.bitIndex).toBeLessThan(SHARD_SIZE_BITS);
  });

  it("is IDEMPOTENT on (anchor, RP): re-disclosure returns the same handle", async () => {
    const first = await allocateStatusEntry({ statusAnchor: "gm:m1", clientId: "mc_rp" });
    const second = await allocateStatusEntry({ statusAnchor: "gm:m1", clientId: "mc_rp" });
    expect(second).toEqual(first);
    expect(store.entries).toHaveLength(1);
  });

  it("NEVER touches the published bitstring (allocation invisibility, auditor #1)", async () => {
    await allocateStatusEntry({ statusAnchor: "gm:m1", clientId: "mc_rp" });
    await allocateStatusEntry({ statusAnchor: "gm:m2", clientId: "mc_rp" });
    expect(store.updateCalls).toBe(0);
  });

  it("gives two facts at one RP DISTINCT indices (no reuse)", async () => {
    const a = await allocateStatusEntry({ statusAnchor: "gm:m1", clientId: "mc_rp" });
    const b = await allocateStatusEntry({ statusAnchor: "gm:m2", clientId: "mc_rp" });
    expect(a.bitIndex).not.toBe(b.bitIndex);
  });

  it("puts the same fact at two RPs on SEPARATE lists (per-RP partition)", async () => {
    const a = await allocateStatusEntry({ statusAnchor: "gm:m1", clientId: "mc_rp1" });
    const b = await allocateStatusEntry({ statusAnchor: "gm:m1", clientId: "mc_rp2" });
    expect(a.listId).not.toBe(b.listId);
  });

  it("rolls to a fresh shard once the current one passes the fill threshold", async () => {
    // Seed shard 0 at ~76% fill for one RP.
    store.lists.push({ id: "list_seed", clientId: "mc_rp", shardNo: 0 });
    const fill = Math.ceil(0.76 * SHARD_SIZE_BITS);
    for (let i = 0; i < fill; i++) {
      store.entries.push({
        id: `e${i}`,
        statusAnchor: `seed${i}`,
        clientId: "mc_rp",
        listId: "list_seed",
        bitIndex: i,
        revokedAt: null,
        revealAfter: null,
      });
    }
    const alloc = await allocateStatusEntry({ statusAnchor: "gm:new", clientId: "mc_rp" });
    expect(alloc.listId).not.toBe("list_seed"); // landed on a new shard
    const rolled = store.lists.find((l) => l.id === alloc.listId)!;
    expect(rolled.shardNo).toBe(1);
  });

  it("resolves a concurrent first-disclosure race to the winner's handle", async () => {
    store.lists.push({ id: "list_seed", clientId: "mc_rp", shardNo: 0 });
    store.raceAnchor = {
      statusAnchor: "gm:race",
      clientId: "mc_rp",
      listId: "list_seed",
      bitIndex: 123,
    };
    const alloc = await allocateStatusEntry({ statusAnchor: "gm:race", clientId: "mc_rp" });
    expect(alloc).toEqual({ listId: "list_seed", bitIndex: 123 });
  });

  it("W1: an ALREADY-revoked anchor allocates a BORN-REVOKED entry (no un-revocable handle)", async () => {
    // The anchor was kicked before this RP ever saw a disclosure. The fresh entry
    // must be born revoked so the publisher sets its bit.
    store.anchorRevs.push({ statusAnchor: "gm:kicked", revokedAt: new Date() });
    const alloc = await allocateStatusEntry({ statusAnchor: "gm:kicked", clientId: "mc_rp" });
    const entry = store.entries.find(
      (e) => e.statusAnchor === "gm:kicked" && e.clientId === "mc_rp",
    )!;
    expect(entry.listId).toBe(alloc.listId);
    expect(entry.revokedAt).not.toBeNull();
    expect(entry.revealAfter).not.toBeNull(); // immediate reveal (no jitter)
  });

  it("W1: a kick COMMITTING mid-allocation is reconciled (the new clear entry is revoked)", async () => {
    // The tombstone is absent at the initial read but appears at create time (the
    // kick committed between our read and our write). The post-create reconcile
    // must catch it and revoke the entry — closing the post-revoke allocation race.
    store.revokeOnCreate = true;
    const alloc = await allocateStatusEntry({ statusAnchor: "gm:racekick", clientId: "mc_rp" });
    const entry = store.entries.find(
      (e) => e.statusAnchor === "gm:racekick" && e.clientId === "mc_rp",
    )!;
    expect(entry.listId).toBe(alloc.listId);
    expect(entry.revokedAt).not.toBeNull();
  });

  it("W1: a NOT-revoked anchor allocates a clear entry (normal case, no false revoke)", async () => {
    const alloc = await allocateStatusEntry({ statusAnchor: "gm:healthy", clientId: "mc_rp" });
    const entry = store.entries.find(
      (e) => e.statusAnchor === "gm:healthy" && e.clientId === "mc_rp",
    )!;
    expect(entry.listId).toBe(alloc.listId);
    expect(entry.revokedAt).toBeNull();
    expect(entry.revealAfter).toBeNull();
  });
});
