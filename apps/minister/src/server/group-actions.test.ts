import { beforeEach, describe, expect, it, vi } from "vitest";

// Covers the founding gate (bucket floor, owned-group quota, reserved + dup
// slugs, happy path) and the RBAC / admin-coup guards. Prisma, the session, the
// bucket scorer, the group config, and badge issuance are mocked with a small
// in-memory store; the REAL requireGroupRole / role-ranking / reserved-slug logic
// runs against it, so the permission decisions are exercised for real.

interface GroupRow {
  id: string;
  slug: string;
  displayName: string;
  description: string | null;
  ownerUserId: string;
  verified: boolean;
}
interface MembershipRow {
  id: string;
  groupId: string;
  userId: string;
  role: string;
  isPublic: boolean;
  addedBy: string | null;
}

const h = vi.hoisted(() => {
  const store = {
    groups: [] as GroupRow[],
    memberships: [] as MembershipRow[],
    users: [] as { id: string }[],
    issued: [] as { userId: string; badge: { type: string; claims: Record<string, unknown> } }[],
    audits: [] as { userId: string | null; action: string; metadata: Record<string, unknown> }[],
    seq: 0,
  };
  const cfg = {
    actorId: "O",
    bucket: 3,
    groupConfig: { foundingMinBucket: 2, maxOwnedGroups: 3 },
  };

  const nextId = (p: string) => `${p}_${++store.seq}`;

  const membershipByKey = (groupId: string, userId: string) =>
    store.memberships.find((m) => m.groupId === groupId && m.userId === userId);

  const prisma = {
    $transaction: async (fn: (tx: unknown) => Promise<unknown>) => fn(prisma),
    group: {
      findUnique: vi.fn(async (args: { where: { slug?: string; id?: string } }) => {
        const g =
          args.where.slug !== undefined
            ? store.groups.find((x) => x.slug === args.where.slug)
            : store.groups.find((x) => x.id === args.where.id);
        return g ?? null;
      }),
      count: vi.fn(
        async (args: { where: { ownerUserId: string } }) =>
          store.groups.filter((g) => g.ownerUserId === args.where.ownerUserId).length,
      ),
      create: vi.fn(async (args: { data: Omit<GroupRow, "id"> }) => {
        const row: GroupRow = { id: nextId("grp"), ...args.data };
        store.groups.push(row);
        return row;
      }),
      delete: vi.fn(async (args: { where: { id: string } }) => {
        store.groups = store.groups.filter((g) => g.id !== args.where.id);
        // Emulate ON DELETE CASCADE on memberships.
        store.memberships = store.memberships.filter((m) => m.groupId !== args.where.id);
        return {};
      }),
      update: vi.fn(async (args: { where: { id: string }; data: Partial<GroupRow> }) => {
        const g = store.groups.find((x) => x.id === args.where.id);
        if (g) Object.assign(g, args.data);
        return g;
      }),
    },
    groupMembership: {
      findUnique: vi.fn(
        async (args: { where: { groupId_userId: { groupId: string; userId: string } } }) => {
          const { groupId, userId } = args.where.groupId_userId;
          const m = membershipByKey(groupId, userId);
          if (!m) return null;
          const group = store.groups.find((g) => g.id === m.groupId);
          return { ...m, group };
        },
      ),
      create: vi.fn(async (args: { data: Omit<MembershipRow, "id" | "isPublic"> }) => {
        const row: MembershipRow = { id: nextId("mem"), isPublic: false, ...args.data };
        store.memberships.push(row);
        return row;
      }),
      delete: vi.fn(
        async (args: { where: { groupId_userId: { groupId: string; userId: string } } }) => {
          const { groupId, userId } = args.where.groupId_userId;
          store.memberships = store.memberships.filter(
            (m) => !(m.groupId === groupId && m.userId === userId),
          );
          return {};
        },
      ),
      update: vi.fn(
        async (args: {
          where: { groupId_userId: { groupId: string; userId: string } };
          data: { role: string };
        }) => {
          const { groupId, userId } = args.where.groupId_userId;
          const m = membershipByKey(groupId, userId);
          if (m) m.role = args.data.role;
          return m;
        },
      ),
      findMany: vi.fn(async (args: { where: { groupId: string } }) => {
        return store.memberships
          .filter((m) => m.groupId === args.where.groupId)
          .map((m) => ({ id: m.id }));
      }),
    },
    user: {
      findUnique: vi.fn(async (args: { where: { id: string } }) => {
        return store.users.find((u) => u.id === args.where.id) ?? null;
      }),
    },
    auditLog: { create: vi.fn(async () => ({})) },
  };

  return { store, cfg, prisma };
});

vi.mock("@/lib/prisma", () => ({ prisma: h.prisma }));
vi.mock("@/lib/session", () => ({
  requireSession: vi.fn(async () => ({ user: { id: h.cfg.actorId } })),
}));
vi.mock("@/lib/audit", () => ({
  audit: vi.fn(async (userId: string | null, action: string, metadata: Record<string, unknown>) => {
    h.store.audits.push({ userId, action, metadata });
  }),
}));
vi.mock("@/server/issue-badge", () => ({
  issueBadge: vi.fn(
    async (args: { userId: string; badge: { type: string; claims: Record<string, unknown> } }) => {
      h.store.issued.push({ userId: args.userId, badge: args.badge });
      return "badge_id";
    },
  ),
}));
vi.mock("@/lib/status-list", () => ({
  groupMembershipAnchor: (membershipId: string) => `gm:${membershipId}`,
  revokeStatusAnchor: vi.fn(async () => 0),
}));
vi.mock("@/lib/user-sybil-bucket", () => ({
  computeUserSybilBucket: vi.fn(async () => h.cfg.bucket),
}));
vi.mock("@/lib/sybil-config", () => ({
  loadGroupConfig: vi.fn(async () => h.cfg.groupConfig),
}));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));

import {
  addMember,
  createGroup,
  deleteGroup,
  removeMember,
  renameGroup,
  setMemberRole,
} from "./group-actions";

function seedUsers(...ids: string[]) {
  for (const id of ids) h.store.users.push({ id });
}
function seedGroup(id: string, ownerUserId: string, slug = "team") {
  h.store.groups.push({
    id,
    slug,
    displayName: "Team",
    description: null,
    ownerUserId,
    verified: false,
  });
}
function seedMembership(groupId: string, userId: string, role: string) {
  h.store.memberships.push({
    id: `${groupId}:${userId}`,
    groupId,
    userId,
    role,
    isPublic: false,
    addedBy: null,
  });
}

beforeEach(() => {
  h.store.groups = [];
  h.store.memberships = [];
  h.store.users = [];
  h.store.issued = [];
  h.store.audits = [];
  h.store.seq = 0;
  h.cfg.actorId = "O";
  h.cfg.bucket = 3;
  h.cfg.groupConfig = { foundingMinBucket: 2, maxOwnedGroups: 3 };
});

describe("createGroup — founding gate", () => {
  it("blocks when the anti-sybil bucket is below the floor", async () => {
    h.cfg.bucket = 1;
    const res = await createGroup({ slug: "acme", displayName: "Acme" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/stronger account/i);
    expect(h.store.groups).toHaveLength(0);
  });

  it("blocks when the user already owns the max number of groups", async () => {
    seedGroup("g1", "O", "one");
    seedGroup("g2", "O", "two");
    seedGroup("g3", "O", "three");
    const res = await createGroup({ slug: "acme", displayName: "Acme" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/maximum of 3/i);
  });

  it("blocks a reserved slug", async () => {
    const res = await createGroup({ slug: "admin", displayName: "Admin" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/reserved/i);
  });

  it("blocks a duplicate slug", async () => {
    seedGroup("g1", "someone-else", "acme");
    const res = await createGroup({ slug: "acme", displayName: "Acme" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/taken/i);
  });

  it("rejects an invalid slug shape", async () => {
    const res = await createGroup({ slug: "Bad_Slug!", displayName: "Nope" });
    expect(res.ok).toBe(false);
  });

  it("happy path: creates group + owner membership + owner badge + audit", async () => {
    const res = await createGroup({ slug: "acme", displayName: "Acme", description: "hi" });
    expect(res.ok).toBe(true);
    expect(h.store.groups).toHaveLength(1);
    const g = h.store.groups[0]!;
    expect(g.slug).toBe("acme");
    expect(g.ownerUserId).toBe("O");
    expect(g.verified).toBe(false);
    const owner = h.store.memberships.find((m) => m.groupId === g.id && m.userId === "O");
    expect(owner?.role).toBe("owner");
    expect(h.store.issued).toHaveLength(1);
    expect(h.store.issued[0]!.userId).toBe("O");
    expect(h.store.issued[0]!.badge.type).toBe("group-membership");
    expect(h.store.issued[0]!.badge.claims).toMatchObject({ group: "acme", role: "owner" });
    expect(h.store.audits.some((a) => a.action === "group.created")).toBe(true);
  });
});

// Group.id and User.id are cuids in production, and the action input schemas
// enforce `z.string().cuid()`. Use cuid-shaped fixtures so validation passes.
const GID = "cgroup0000000000000000001";
const OWNER = "cowner0000000000000000001";
const ADMIN = "cadmin0000000000000000001";
const ADMIN2 = "cadmin0000000000000000002";
const MEMBER = "cmember000000000000000001";
const OUTSIDER = "coutsider00000000000000001";

describe("RBAC — membership management", () => {
  beforeEach(() => {
    seedUsers(OWNER, ADMIN, ADMIN2, MEMBER, OUTSIDER);
    seedGroup(GID, OWNER);
    seedMembership(GID, OWNER, "owner");
    seedMembership(GID, ADMIN, "admin");
    seedMembership(GID, ADMIN2, "admin");
    seedMembership(GID, MEMBER, "member");
  });

  it("a plain member cannot add members", async () => {
    h.cfg.actorId = MEMBER;
    const res = await addMember({ groupId: GID, targetUserId: OUTSIDER, role: "member" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/permission/i);
    expect(membership(GID, OUTSIDER)).toBeUndefined();
  });

  it("an admin can add a member (as member) and issues their badge", async () => {
    h.cfg.actorId = ADMIN;
    const res = await addMember({ groupId: GID, targetUserId: OUTSIDER, role: "member" });
    expect(res.ok).toBe(true);
    expect(membership(GID, OUTSIDER)?.role).toBe("member");
    expect(
      h.store.issued.some((i) => i.userId === OUTSIDER && i.badge.claims.role === "member"),
    ).toBe(true);
  });

  it("an admin CANNOT grant the admin role (owner-only)", async () => {
    h.cfg.actorId = ADMIN;
    const res = await addMember({ groupId: GID, targetUserId: OUTSIDER, role: "admin" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/owner can grant the admin/i);
    expect(membership(GID, OUTSIDER)).toBeUndefined();
  });

  it("an admin can remove a plain member", async () => {
    h.cfg.actorId = ADMIN;
    const res = await removeMember({ groupId: GID, targetUserId: MEMBER });
    expect(res.ok).toBe(true);
    expect(membership(GID, MEMBER)).toBeUndefined();
  });

  it("an admin CANNOT remove another admin (owner-only)", async () => {
    h.cfg.actorId = ADMIN;
    const res = await removeMember({ groupId: GID, targetUserId: ADMIN2 });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/owner can remove an admin/i);
    expect(membership(GID, ADMIN2)?.role).toBe("admin");
  });

  it("an admin CANNOT remove the owner", async () => {
    h.cfg.actorId = ADMIN;
    const res = await removeMember({ groupId: GID, targetUserId: OWNER });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/owner can't be removed/i);
    expect(membership(GID, OWNER)?.role).toBe("owner");
  });

  it("an admin CANNOT change roles (owner-only)", async () => {
    h.cfg.actorId = ADMIN;
    const res = await setMemberRole({ groupId: GID, targetUserId: MEMBER, role: "admin" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/permission/i);
    expect(membership(GID, MEMBER)?.role).toBe("member");
  });

  it("the owner can promote a member to admin", async () => {
    h.cfg.actorId = OWNER;
    const res = await setMemberRole({ groupId: GID, targetUserId: MEMBER, role: "admin" });
    expect(res.ok).toBe(true);
    expect(membership(GID, MEMBER)?.role).toBe("admin");
    expect(h.store.audits.some((a) => a.action === "group.member_role_changed")).toBe(true);
  });

  it("the owner cannot be demoted via setMemberRole", async () => {
    h.cfg.actorId = OWNER;
    const res = await setMemberRole({ groupId: GID, targetUserId: OWNER, role: "admin" });
    expect(res.ok).toBe(false);
    expect(membership(GID, OWNER)?.role).toBe("owner");
  });

  it("a non-member (no row) is denied — cannot probe via a real role", async () => {
    h.cfg.actorId = OUTSIDER;
    const res = await removeMember({ groupId: GID, targetUserId: MEMBER });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/not a member/i);
  });
});

describe("owner-only lifecycle", () => {
  beforeEach(() => {
    seedUsers(OWNER, ADMIN);
    seedGroup(GID, OWNER);
    seedMembership(GID, OWNER, "owner");
    seedMembership(GID, ADMIN, "admin");
  });

  it("an admin cannot delete the group", async () => {
    h.cfg.actorId = ADMIN;
    const res = await deleteGroup({ groupId: GID });
    expect(res.ok).toBe(false);
    expect(h.store.groups).toHaveLength(1);
  });

  it("the owner can delete the group (cascading memberships)", async () => {
    h.cfg.actorId = OWNER;
    const res = await deleteGroup({ groupId: GID });
    expect(res.ok).toBe(true);
    expect(h.store.groups).toHaveLength(0);
    expect(h.store.memberships).toHaveLength(0);
  });

  it("an admin cannot rename the group", async () => {
    h.cfg.actorId = ADMIN;
    const res = await renameGroup({ groupId: GID, displayName: "New" });
    expect(res.ok).toBe(false);
  });

  it("the owner can rename the group", async () => {
    h.cfg.actorId = OWNER;
    const res = await renameGroup({ groupId: GID, displayName: "New Name" });
    expect(res.ok).toBe(true);
    expect(h.store.groups[0]!.displayName).toBe("New Name");
  });
});

function membership(groupId: string, userId: string): MembershipRow | undefined {
  return h.store.memberships.find((m) => m.groupId === groupId && m.userId === userId);
}
