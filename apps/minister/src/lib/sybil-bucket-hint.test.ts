import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the DB client: the unit under test is the BucketStat lookup + the
// fail-soft error handling, not Prisma itself.
vi.mock("./prisma", () => ({
  prisma: { bucketStat: { findUnique: vi.fn() } },
}));

import { loadBucketAnonymityHint } from "./sybil-bucket-hint";
import { prisma } from "./prisma";

const findUnique = vi.mocked(prisma.bucketStat.findUnique);

beforeEach(() => {
  findUnique.mockReset();
});

// Silence the fail-soft console.error in the error-path tests below.
const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
afterEach(() => {
  consoleErrorSpy.mockClear();
});

describe("loadBucketAnonymityHint", () => {
  it("maps a small BucketStat count through anonymityHint", async () => {
    findUnique.mockResolvedValueOnce({ bucket: 4, count: 3, computedAt: new Date() });
    const hint = await loadBucketAnonymityHint(4);
    expect(hint).toEqual({ bucket: "very-small", label: "Few people hold this — least private" });
    expect(findUnique).toHaveBeenCalledWith({ where: { bucket: 4 } });
  });

  it("maps a large BucketStat count through anonymityHint", async () => {
    findUnique.mockResolvedValueOnce({ bucket: 1, count: 5000, computedAt: new Date() });
    const hint = await loadBucketAnonymityHint(1);
    expect(hint).toEqual({
      bucket: "large",
      label: "Very many people hold this — most private",
    });
  });

  it("fails soft to null when the BucketStat row is absent (stats not yet computed)", async () => {
    findUnique.mockResolvedValueOnce(null);
    const hint = await loadBucketAnonymityHint(2);
    expect(hint).toBeNull();
  });

  it("fails soft to null when the read throws", async () => {
    findUnique.mockRejectedValueOnce(new Error("db unreachable"));
    const hint = await loadBucketAnonymityHint(0);
    expect(hint).toBeNull();
    expect(consoleErrorSpy).toHaveBeenCalled();
  });
});
