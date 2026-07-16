import { beforeEach, describe, expect, it, vi } from "vitest";

// Unit tests for the onboarding gate (requireSetupComplete) and the setupComplete
// flag the session loader now surfaces. @/auth can't load under vitest, so it and
// prisma are mocked; next/navigation's redirect is a spy (in these tests we only
// assert whether it fired, not its thrown control flow). React.cache memoizes per
// module instance, so each case re-imports session.ts fresh via resetModules.

const h = vi.hoisted(() => ({
  auth: vi.fn(),
  redirect: vi.fn(),
  db: { user: { findUnique: vi.fn() } },
}));

vi.mock("@/auth", () => ({ auth: h.auth }));
vi.mock("@/lib/prisma", () => ({ prisma: h.db }));
vi.mock("next/navigation", () => ({ redirect: h.redirect }));

async function loadSession() {
  vi.resetModules();
  return import("./session");
}

const USER = { id: "user-1" };

function freshRow(setupCompletedAt: Date | null) {
  return {
    sessionGeneration: 0,
    isAdmin: false,
    isBanned: false,
    mergedIntoUserId: null,
    setupCompletedAt,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  h.auth.mockResolvedValue({ user: USER, sessionGeneration: 0 });
});

describe("requireSetupComplete", () => {
  it("redirects an unfinished user to /welcome", async () => {
    h.db.user.findUnique.mockResolvedValue(freshRow(null));
    const { requireSetupComplete } = await loadSession();
    await requireSetupComplete();
    expect(h.redirect).toHaveBeenCalledWith("/welcome");
  });

  it("does NOT redirect once setup is complete", async () => {
    h.db.user.findUnique.mockResolvedValue(freshRow(new Date()));
    const { requireSetupComplete } = await loadSession();
    await requireSetupComplete();
    expect(h.redirect).not.toHaveBeenCalled();
  });

  it("is a no-op for a signed-out visitor (no redirect loop into /welcome)", async () => {
    h.auth.mockResolvedValue(null);
    const { requireSetupComplete } = await loadSession();
    await requireSetupComplete();
    expect(h.redirect).not.toHaveBeenCalled();
  });
});

describe("getSessionFlags exposes setupComplete", () => {
  it("false when setup is unfinished, true when done", async () => {
    h.db.user.findUnique.mockResolvedValue(freshRow(null));
    const first = await loadSession();
    expect((await first.getSessionFlags())?.setupComplete).toBe(false);

    h.db.user.findUnique.mockResolvedValue(freshRow(new Date()));
    const second = await loadSession();
    expect((await second.getSessionFlags())?.setupComplete).toBe(true);
  });
});
