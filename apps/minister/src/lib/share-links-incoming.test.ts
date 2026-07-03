import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock the DB seam only. loadIncomingShareLinks is pure query-building +
// mapping; the fake findMany below faithfully applies the WHERE clause the
// function passes, so these tests exercise the real authz scoping.
vi.mock("@/lib/prisma", () => ({
  prisma: { shareLink: { findMany: vi.fn() } },
}));

import { prisma } from "@/lib/prisma";
import { loadIncomingShareLinks } from "./share-links";

const NOW = Date.now();
const FUTURE = new Date(NOW + 7 * 86_400_000);
const PAST = new Date(NOW - 86_400_000);

interface FakeLink {
  token: string;
  ownerId: string;
  badgeIds: string[];
  requiresAccount: boolean;
  expiresAt: Date;
  revokedAt: Date | null;
  // userIds that have a recorded ShareLinkView on this link.
  viewers: string[];
}

const DB: FakeLink[] = [
  {
    token: "tok_alpha",
    ownerId: "user_A",
    badgeIds: ["b1", "b2"],
    requiresAccount: true,
    expiresAt: FUTURE,
    revokedAt: null,
    viewers: ["user_B"], // A shared with B; B opened it
  },
  {
    token: "tok_beta",
    ownerId: "user_A",
    badgeIds: ["b3"],
    requiresAccount: false,
    expiresAt: FUTURE,
    revokedAt: null,
    viewers: [], // A created it; nobody has opened it yet
  },
  {
    token: "tok_gamma",
    ownerId: "user_B",
    badgeIds: ["b4"],
    requiresAccount: false,
    expiresAt: PAST,
    revokedAt: null,
    viewers: ["user_B"], // B's own link, which B also viewed
  },
];

// Faithfully emulate Prisma applying the exact WHERE clause the function
// builds: exclude the caller's own links, and require a view row keyed to the
// caller. Reading these fields also asserts the clause has the right shape —
// if loadIncomingShareLinks dropped either guard, this would throw.
interface FindManyArgs {
  where: { userId: { not: string }; views: { some: { viewerUserId: string } } };
}

beforeEach(() => {
  vi.mocked(prisma.shareLink.findMany).mockImplementation(
    (
      // The vitest mock is typed to Prisma's overloaded signature; we only read
      // the two authz-relevant fields, so narrow via unknown rather than restate
      // the full generated arg type.
      args: unknown,
    ) => {
      const { where } = args as FindManyArgs;
      const notUser = where.userId.not;
      const viewer = where.views.some.viewerUserId;
      const rows = DB.filter((l) => l.ownerId !== notUser && l.viewers.includes(viewer)).map(
        (l) => ({
          token: l.token,
          badgeIds: l.badgeIds,
          requiresAccount: l.requiresAccount,
          expiresAt: l.expiresAt,
          revokedAt: l.revokedAt,
          views: l.viewers.includes(viewer) ? [{ viewedAt: new Date(NOW) }] : [],
        }),
      );
      // The generated PrismaPromise return type carries far more than the
      // selected fields; the fake only needs to resolve the projected rows.
      return Promise.resolve(rows) as unknown as ReturnType<typeof prisma.shareLink.findMany>;
    },
  );
});

describe("loadIncomingShareLinks", () => {
  it("surfaces a link to its actual recipient", async () => {
    const incoming = await loadIncomingShareLinks("user_B");
    expect(incoming.map((l) => l.token)).toEqual(["tok_alpha"]);
    expect(incoming[0]?.badgeCount).toBe(2);
    expect(incoming[0]?.requiresAccount).toBe(true);
    expect(incoming[0]?.status).toBe("active");
  });

  it("does NOT leak a share to a user who never received it", async () => {
    // user_C possesses no view row on any link → sees nothing, even though
    // tok_alpha and tok_beta exist and are active.
    const incoming = await loadIncomingShareLinks("user_C");
    expect(incoming).toEqual([]);
  });

  it("excludes the caller's own links from their incoming list", async () => {
    // user_A owns tok_alpha/tok_beta and has no view row on anyone else's
    // link, so their incoming list is empty (those are the outgoing list).
    const incoming = await loadIncomingShareLinks("user_A");
    expect(incoming).toEqual([]);
  });

  it("passes an authz-scoped WHERE clause (own links excluded, view required)", async () => {
    await loadIncomingShareLinks("user_B");
    const call = vi.mocked(prisma.shareLink.findMany).mock.calls.at(-1);
    const args = call?.[0] as FindManyArgs;
    expect(args.where.userId).toEqual({ not: "user_B" });
    expect(args.where.views).toEqual({ some: { viewerUserId: "user_B" } });
  });
});
