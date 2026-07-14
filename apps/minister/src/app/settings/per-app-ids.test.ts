import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  db: {
    oidcGrant: { findMany: vi.fn() },
    oidcClient: { findMany: vi.fn() },
  },
  // Deterministic stand-in for the pairwise derivation so the test asserts the
  // mapping (one row per grant, sub sourced from resolveSub) without touching the
  // real HMAC/override path.
  resolveSub: vi.fn((userId: string, clientId: string) =>
    Promise.resolve(`sub:${userId}:${clientId}`),
  ),
}));

vi.mock("@/lib/prisma", () => ({ prisma: h.db }));
vi.mock("@/lib/oidc-subject", () => ({ resolveSub: h.resolveSub }));

import { loadPerAppIds } from "@/app/settings/per-app-ids";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("loadPerAppIds", () => {
  it("returns one {appName, sub} per grant, with sub from resolveSub", async () => {
    h.db.oidcGrant.findMany.mockResolvedValue([{ clientId: "app-a" }, { clientId: "app-b" }]);
    h.db.oidcClient.findMany.mockResolvedValue([
      { clientId: "app-a", name: "App A" },
      { clientId: "app-b", name: "App B" },
    ]);

    const result = await loadPerAppIds("user-1");

    expect(result).toEqual([
      { appName: "App A", sub: "sub:user-1:app-a" },
      { appName: "App B", sub: "sub:user-1:app-b" },
    ]);
    expect(h.resolveSub).toHaveBeenCalledWith("user-1", "app-a");
    expect(h.resolveSub).toHaveBeenCalledWith("user-1", "app-b");
    expect(h.db.oidcGrant.findMany).toHaveBeenCalledWith({
      where: { userId: "user-1" },
      select: { clientId: true },
      orderBy: { createdAt: "asc" },
    });
  });

  it("falls back to the raw clientId when the client row is gone", async () => {
    h.db.oidcGrant.findMany.mockResolvedValue([{ clientId: "orphaned" }]);
    h.db.oidcClient.findMany.mockResolvedValue([]);

    const result = await loadPerAppIds("user-2");

    expect(result).toEqual([{ appName: "orphaned", sub: "sub:user-2:orphaned" }]);
  });

  it("returns an empty list when the user has no grants", async () => {
    h.db.oidcGrant.findMany.mockResolvedValue([]);
    h.db.oidcClient.findMany.mockResolvedValue([]);

    expect(await loadPerAppIds("user-3")).toEqual([]);
    expect(h.resolveSub).not.toHaveBeenCalled();
  });
});
