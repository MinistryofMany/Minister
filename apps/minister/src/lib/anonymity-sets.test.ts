import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the DB client: the unit under test is the distinct-holder
// aggregation + the 60s in-process cache, not Prisma itself. The raw
// query result shape (bigint `holders`, per the pg driver) is simulated
// here; the real `COUNT(DISTINCT userId)` is exercised end-to-end in the
// Playwright suite against a live Postgres.
vi.mock("./prisma", () => ({
  prisma: { $queryRaw: vi.fn() },
}));

import { __clearHolderCountCache, holderCountsByType } from "./anonymity-sets";
import { prisma } from "./prisma";

const queryRaw = vi.mocked(prisma.$queryRaw);

beforeEach(() => {
  __clearHolderCountCache();
  queryRaw.mockReset();
});
afterEach(() => {
  __clearHolderCountCache();
});

describe("holderCountsByType", () => {
  it("returns a distinct-user count per type (bigint normalized to number)", async () => {
    // Mirrors what `COUNT(DISTINCT userId)` returns: a user holding two
    // oauth-account badges still counts once in the holders total, so the
    // aggregation is already collapsed by the SQL — the lib only maps it.
    queryRaw.mockResolvedValueOnce([
      { type: "oauth-account", holders: 3n },
      { type: "age-over-18", holders: 5000n },
      { type: "residency-country", holders: 200n },
    ]);

    const map = await holderCountsByType(0);
    expect(map.get("oauth-account")).toBe(3);
    expect(map.get("age-over-18")).toBe(5000);
    expect(map.get("residency-country")).toBe(200);
    // Values are plain numbers, not bigints.
    expect(typeof map.get("oauth-account")).toBe("number");
    expect(map.has("unknown-type")).toBe(false);
  });

  it("returns an empty map when no badges exist", async () => {
    queryRaw.mockResolvedValueOnce([]);
    const map = await holderCountsByType(0);
    expect(map.size).toBe(0);
  });

  it("serves a cached snapshot within the TTL (single query)", async () => {
    queryRaw.mockResolvedValueOnce([{ type: "a", holders: 1n }]);

    const first = await holderCountsByType(0);
    const second = await holderCountsByType(59_000); // < 60s later
    // Same cached DATA (no re-query), but a fresh defensive copy each call
    // (audit W-1) — distinct instances, equal contents.
    expect(queryRaw).toHaveBeenCalledTimes(1);
    expect(second).toEqual(first);
    expect(second).not.toBe(first);
  });

  it("returns a defensive copy: a caller mutation cannot poison the cache (W-1)", async () => {
    queryRaw.mockResolvedValueOnce([{ type: "a", holders: 1n }]);

    const first = await holderCountsByType(0);
    // A downstream consumer mutates its map (e.g. fills in a 0 for a type
    // it didn't see). This must NOT leak into the 60s-cached snapshot.
    first.set("a", 999);
    first.set("poison", -1);

    const second = await holderCountsByType(59_000); // still within TTL
    expect(queryRaw).toHaveBeenCalledTimes(1); // served from cache
    expect(second.get("a")).toBe(1);
    expect(second.has("poison")).toBe(false);
  });

  it("recomputes after the TTL elapses", async () => {
    queryRaw
      .mockResolvedValueOnce([{ type: "a", holders: 1n }])
      .mockResolvedValueOnce([{ type: "a", holders: 2n }]);

    const first = await holderCountsByType(0);
    expect(first.get("a")).toBe(1);

    // 60_000ms is the TTL boundary; at exactly expiresAt the entry is
    // stale (cache uses `now < expiresAt`), forcing a recompute.
    const second = await holderCountsByType(60_000);
    expect(second.get("a")).toBe(2);
    expect(queryRaw).toHaveBeenCalledTimes(2);
  });
});
