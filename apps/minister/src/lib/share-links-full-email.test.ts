import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock the DB seam only. loadUserShareLinks is pure query-building + mapping;
// the fakes below faithfully apply the WHERE clauses the function passes, so
// these tests exercise the real full-email detection (owner-scoped, type-scoped,
// and blind to a since-deleted badge id).
vi.mock("@/lib/prisma", () => ({
  prisma: { shareLink: { findMany: vi.fn() }, badge: { findMany: vi.fn() } },
}));

import { prisma } from "@/lib/prisma";
import { disclosesFullEmail, loadUserShareLinks } from "./share-links";

const USER = "user_owner";
const FUTURE = new Date(Date.now() + 7 * 86_400_000);

interface FakeBadge {
  id: string;
  userId: string;
  type: string;
}

// The user owns three badges: a full-email one, a domain-only one, and a
// GitHub link. Only the email-exact badge should ever raise the flag.
const BADGES: FakeBadge[] = [
  { id: "b_email_exact", userId: USER, type: "email-exact" },
  { id: "b_email_domain", userId: USER, type: "email-domain" },
  { id: "b_github", userId: USER, type: "oauth-account" },
];

interface ShareRow {
  id: string;
  token: string;
  badgeIds: string[];
  requiresAccount: boolean;
  createdAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
}

const LINKS: ShareRow[] = [
  {
    id: "sl_full",
    token: "tok_full",
    badgeIds: ["b_email_exact", "b_github"],
    requiresAccount: false,
    createdAt: new Date(),
    expiresAt: FUTURE,
    revokedAt: null,
  },
  {
    id: "sl_domain",
    token: "tok_domain",
    badgeIds: ["b_email_domain"],
    requiresAccount: false,
    createdAt: new Date(),
    expiresAt: FUTURE,
    revokedAt: null,
  },
  {
    // References a badge id that no longer exists — a since-deleted email-exact
    // badge discloses nothing and must NOT raise the flag.
    id: "sl_deleted",
    token: "tok_deleted",
    badgeIds: ["b_deleted"],
    requiresAccount: false,
    createdAt: new Date(),
    expiresAt: FUTURE,
    revokedAt: null,
  },
];

interface ShareFindManyArgs {
  where: { userId: string };
}
interface BadgeFindManyArgs {
  where: { userId: string; id: { in: string[] }; type: { in: string[] } };
}

beforeEach(() => {
  vi.mocked(prisma.shareLink.findMany).mockImplementation((args: unknown) => {
    const { where } = args as ShareFindManyArgs;
    const rows = LINKS.filter((l) => where.userId === USER).map((l) => ({
      ...l,
      _count: { views: 0 },
    }));
    return Promise.resolve(rows) as unknown as ReturnType<typeof prisma.shareLink.findMany>;
  });

  vi.mocked(prisma.badge.findMany).mockImplementation((args: unknown) => {
    const { where } = args as BadgeFindManyArgs;
    const rows = BADGES.filter(
      (b) =>
        b.userId === where.userId && where.id.in.includes(b.id) && where.type.in.includes(b.type),
    ).map((b) => ({ id: b.id }));
    return Promise.resolve(rows) as unknown as ReturnType<typeof prisma.badge.findMany>;
  });
});

describe("disclosesFullEmail", () => {
  it("is true only for the full-email badge type", () => {
    expect(disclosesFullEmail("email-exact")).toBe(true);
    expect(disclosesFullEmail("email-domain")).toBe(false);
    expect(disclosesFullEmail("oauth-account")).toBe(false);
  });
});

describe("loadUserShareLinks — exposesFullEmail", () => {
  it("flags a link carrying an email-exact badge", async () => {
    const links = await loadUserShareLinks(USER);
    const full = links.find((l) => l.id === "sl_full");
    expect(full?.exposesFullEmail).toBe(true);
  });

  it("does NOT flag a domain-only link", async () => {
    const links = await loadUserShareLinks(USER);
    const domain = links.find((l) => l.id === "sl_domain");
    expect(domain?.exposesFullEmail).toBe(false);
  });

  it("does NOT flag a link whose email badge was since deleted", async () => {
    const links = await loadUserShareLinks(USER);
    const deleted = links.find((l) => l.id === "sl_deleted");
    expect(deleted?.exposesFullEmail).toBe(false);
  });

  it("scopes the badge lookup to the owner AND the full-email types", async () => {
    await loadUserShareLinks(USER);
    const call = vi.mocked(prisma.badge.findMany).mock.calls.at(-1);
    const args = call?.[0] as BadgeFindManyArgs;
    expect(args.where.userId).toBe(USER);
    expect(args.where.type.in).toEqual(["email-exact"]);
  });
});
