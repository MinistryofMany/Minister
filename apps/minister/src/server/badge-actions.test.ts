import { beforeEach, describe, expect, it, vi } from "vitest";

// Regression for the issuance-dedup bypass: re-issuing a credential from the
// same account mints a SECOND Badge row pointing at the SAME nullifierRef
// (registerDedup → already_yours). Deleting ONE of the siblings must NOT release
// the shared ledger entry — otherwise a different account could register the
// same credential while this user still holds a live signed sibling badge. The
// entry may only be released once the LAST badge referencing it is gone.

const h = vi.hoisted(() => {
  interface BadgeRow {
    id: string;
    userId: string;
    nullifierRef: string | null;
  }
  const store = {
    badges: [] as BadgeRow[],
    users: [] as { id: string; dedupHandle: string | null }[],
  };
  const badge = {
    findFirst: vi.fn(async (args: { where: { id: string; userId: string } }) => {
      const r = store.badges.find((b) => b.id === args.where.id && b.userId === args.where.userId);
      return r ? { nullifierRef: r.nullifierRef } : null;
    }),
    deleteMany: vi.fn(async (args: { where: { id: string; userId: string } }) => {
      const before = store.badges.length;
      store.badges = store.badges.filter(
        (b) => !(b.id === args.where.id && b.userId === args.where.userId),
      );
      return { count: before - store.badges.length };
    }),
    count: vi.fn(async (args: { where: { nullifierRef: string } }) => {
      return store.badges.filter((b) => b.nullifierRef === args.where.nullifierRef).length;
    }),
  };
  const user = {
    findUnique: vi.fn(async (args: { where: { id: string } }) => {
      const u = store.users.find((r) => r.id === args.where.id);
      return u ? { dedupHandle: u.dedupHandle } : null;
    }),
  };
  return { store, prisma: { badge, user } };
});

vi.mock("@/lib/prisma", () => ({ prisma: h.prisma }));
vi.mock("@/lib/session", () => ({ getCurrentSession: vi.fn() }));
vi.mock("@/lib/audit", () => ({ audit: vi.fn().mockResolvedValue(undefined) }));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));

const release = vi.fn().mockResolvedValue(undefined);
vi.mock("@/lib/nullifier", () => ({
  nullifierService: {
    release: (...args: unknown[]) => release(...args),
  },
  // Passthrough: run the op once so the release spy fires synchronously.
  runPostCommit: (op: () => Promise<unknown>) => op(),
}));

import { getCurrentSession } from "@/lib/session";
import { deleteBadge } from "./badge-actions";

const USER = "cljuser0000000000000000000";

beforeEach(() => {
  h.store.badges = [];
  h.store.users = [{ id: USER, dedupHandle: "owner_handle_A" }];
  release.mockClear();
  vi.mocked(getCurrentSession).mockResolvedValue({
    user: { id: USER },
  } as Awaited<ReturnType<typeof getCurrentSession>>);
});

function badgeId(n: number): string {
  return `clbadge00000000000000000${n}`.slice(0, 25);
}

describe("deleteBadge — sibling nullifierRef guard", () => {
  it("does NOT release the ledger entry while a sibling badge still references it", async () => {
    const b1 = badgeId(1);
    const b2 = badgeId(2);
    // Two badges, both anchored to the SAME ledger entry (a re-issue).
    h.store.badges = [
      { id: b1, userId: USER, nullifierRef: "entry_shared" },
      { id: b2, userId: USER, nullifierRef: "entry_shared" },
    ];

    const first = await deleteBadge({ badgeId: b1 });
    expect(first.ok).toBe(true);
    // Sibling b2 still references entry_shared → entry must NOT be released.
    expect(release).not.toHaveBeenCalled();

    const second = await deleteBadge({ badgeId: b2 });
    expect(second.ok).toBe(true);
    // Last referencing badge gone → NOW the entry is freed.
    expect(release).toHaveBeenCalledTimes(1);
    expect(release).toHaveBeenCalledWith({
      entryRef: "entry_shared",
      ownerHandle: "owner_handle_A",
    });
  });

  it("releases immediately when the deleted badge is the only ref holder", async () => {
    const b1 = badgeId(1);
    h.store.badges = [{ id: b1, userId: USER, nullifierRef: "entry_solo" }];

    const res = await deleteBadge({ badgeId: b1 });
    expect(res.ok).toBe(true);
    expect(release).toHaveBeenCalledTimes(1);
    expect(release).toHaveBeenCalledWith({
      entryRef: "entry_solo",
      ownerHandle: "owner_handle_A",
    });
  });

  it("does nothing to the ledger for a badge with no nullifierRef", async () => {
    const b1 = badgeId(1);
    h.store.badges = [{ id: b1, userId: USER, nullifierRef: null }];

    const res = await deleteBadge({ badgeId: b1 });
    expect(res.ok).toBe(true);
    expect(release).not.toHaveBeenCalled();
  });
});
