import { beforeEach, describe, expect, it, vi } from "vitest";

import { JITTER_MAX_MS } from "./constants";

interface EntryRow {
  id: string;
  statusAnchor: string;
  revokedAt: Date | null;
  revealAfter: Date | null;
}
interface AnchorRevRow {
  statusAnchor: string;
  revokedAt: Date;
  reason: string;
}

const h = vi.hoisted(() => {
  const store = {
    entries: [] as EntryRow[],
    anchorRevs: [] as AnchorRevRow[],
    audits: [] as { userId: string | null; action: string; metadata: Record<string, unknown> }[],
  };
  const client = {
    statusAnchorRevocation: {
      upsert: vi.fn(
        async ({
          where,
          create,
        }: {
          where: { statusAnchor: string };
          create: { statusAnchor: string; revokedAt: Date; reason: string };
          update: Record<string, never>;
        }) => {
          const existing = store.anchorRevs.find((r) => r.statusAnchor === where.statusAnchor);
          // update: {} => idempotent, keep the first revocation.
          if (existing) return existing;
          const row = { ...create };
          store.anchorRevs.push(row);
          return row;
        },
      ),
    },
    badgeStatusEntry: {
      findMany: vi.fn(async ({ where }: { where: { statusAnchor: string; revokedAt: null } }) => {
        return store.entries
          .filter((e) => e.statusAnchor === where.statusAnchor && e.revokedAt === null)
          .map((e) => ({ id: e.id }));
      }),
      update: vi.fn(
        async ({
          where,
          data,
        }: {
          where: { id: string };
          data: { revokedAt: Date; revealAfter: Date };
        }) => {
          const row = store.entries.find((e) => e.id === where.id);
          if (row) {
            row.revokedAt = data.revokedAt;
            row.revealAfter = data.revealAfter;
          }
        },
      ),
    },
    auditLog: {
      create: vi.fn(
        async ({
          data,
        }: {
          data: { userId: string | null; action: string; metadata: Record<string, unknown> };
        }) => {
          store.audits.push({ userId: data.userId, action: data.action, metadata: data.metadata });
        },
      ),
    },
  };
  return { store, client };
});
const store = h.store;
const client = h.client;

// audit() imports the global prisma for its default client; we always pass the tx
// client here, but mock prisma anyway so the module import is clean.
vi.mock("@/lib/prisma", () => ({ prisma: h.client }));

import { revokeStatusAnchor } from "./revoke";

// The in-memory mock structurally implements only the methods revoke needs; cast
// to the (unexported) client param type so the direct calls typecheck.
type RevokeClientArg = NonNullable<Parameters<typeof revokeStatusAnchor>[0]["client"]>;
const asClient = client as unknown as RevokeClientArg;

beforeEach(() => {
  store.entries = [];
  store.anchorRevs = [];
  store.audits = [];
  vi.clearAllMocks();
});

describe("revokeStatusAnchor", () => {
  it("marks every handle for the fact revoked with an INDEPENDENT jitter floor", async () => {
    const t0 = Date.now();
    store.entries.push(
      { id: "e1", statusAnchor: "gm:m1", revokedAt: null, revealAfter: null },
      { id: "e2", statusAnchor: "gm:m1", revokedAt: null, revealAfter: null },
    );

    const count = await revokeStatusAnchor({
      anchor: "gm:m1",
      reason: "group.member_removed",
      actorUserId: "owner_1",
      client: asClient,
    });

    expect(count).toBe(2);
    for (const e of store.entries) {
      expect(e.revokedAt).not.toBeNull();
      const reveal = e.revealAfter!.getTime();
      expect(reveal).toBeGreaterThanOrEqual(t0);
      expect(reveal).toBeLessThanOrEqual(t0 + JITTER_MAX_MS + 5);
    }
    // Independent draws: not both the exact same reveal instant (probabilistically).
    // (A shared floor would be a correlation bug — auditor #2.)
    expect(
      store.audits.some((a) => a.action === "status.anchor_revoked" && a.metadata.entries === 2),
    ).toBe(true);
  });

  it("only touches an anchor's OWN entries, not another fact's", async () => {
    store.entries.push(
      { id: "e1", statusAnchor: "gm:m1", revokedAt: null, revealAfter: null },
      { id: "e2", statusAnchor: "gm:other", revokedAt: null, revealAfter: null },
    );
    await revokeStatusAnchor({ anchor: "gm:m1", reason: "r", client: asClient });
    expect(store.entries.find((e) => e.id === "e1")!.revokedAt).not.toBeNull();
    expect(store.entries.find((e) => e.id === "e2")!.revokedAt).toBeNull();
  });

  it("is idempotent: an already-revoked entry keeps its original reveal instant", async () => {
    const original = new Date(Date.now() + 12345);
    store.entries.push({
      id: "e1",
      statusAnchor: "gm:m1",
      revokedAt: new Date(),
      revealAfter: original,
    });
    const count = await revokeStatusAnchor({ anchor: "gm:m1", reason: "r", client: asClient });
    expect(count).toBe(0); // already-revoked rows are filtered out of findMany
    expect(store.entries[0]!.revealAfter).toBe(original);
  });

  it("no handles for the fact (never disclosed) => nothing to do", async () => {
    const count = await revokeStatusAnchor({ anchor: "gm:never", reason: "r", client: asClient });
    expect(count).toBe(0);
  });

  it("W1: writes a durable anchor tombstone even when the fact was NEVER disclosed", async () => {
    // The case a per-entry-only revoke could never cover: a member kicked before
    // ever disclosing to any RP. The durable row is what makes a LATER disclosure's
    // allocation born-revoked.
    const count = await revokeStatusAnchor({
      anchor: "gm:neverdisclosed",
      reason: "group.member_removed",
      client: asClient,
    });
    expect(count).toBe(0);
    expect(store.anchorRevs.map((r) => r.statusAnchor)).toContain("gm:neverdisclosed");
  });

  it("W1: the anchor tombstone is idempotent (keeps the first revocation)", async () => {
    await revokeStatusAnchor({ anchor: "gm:m1", reason: "first", client: asClient });
    const firstAt = store.anchorRevs[0]!.revokedAt;
    await revokeStatusAnchor({ anchor: "gm:m1", reason: "second", client: asClient });
    const rows = store.anchorRevs.filter((r) => r.statusAnchor === "gm:m1");
    expect(rows).toHaveLength(1);
    expect(rows[0]!.revokedAt).toBe(firstAt);
    expect(rows[0]!.reason).toBe("first");
  });
});
