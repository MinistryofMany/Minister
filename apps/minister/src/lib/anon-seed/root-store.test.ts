import { describe, expect, it } from "vitest";

import { deleteRoot, getRoot, putRoot } from "./root-store";

// These run under vitest's `node` environment, where `indexedDB` is undefined,
// so the store degrades to memory-only: reads/writes no-op, never throw. The
// input-validation trust boundary still holds, which is what these assert. The
// real IndexedDB round-trip is a browser/e2e concern.

const ROOT = new Uint8Array(16).fill(0x11);

describe("root-store input validation (trust boundary)", () => {
  it("rejects a non-Uint8Array root (e.g. a CryptoKey)", async () => {
    await expect(putRoot("u1", {} as unknown as Uint8Array, 1)).rejects.toThrow(TypeError);
  });

  it("rejects a wrong-length root", async () => {
    await expect(putRoot("u1", new Uint8Array(15), 1)).rejects.toThrow(RangeError);
    await expect(putRoot("u1", new Uint8Array(32), 1)).rejects.toThrow(RangeError);
  });

  it.each([0, -1, 1.5, Number.NaN])("rejects a non-positive/non-integer epoch %j", async (bad) => {
    await expect(putRoot("u1", ROOT, bad)).rejects.toThrow(RangeError);
  });

  it("rejects an empty userId on every op", async () => {
    await expect(putRoot("", ROOT, 1)).rejects.toThrow(RangeError);
    await expect(getRoot("")).rejects.toThrow(RangeError);
    await expect(deleteRoot("")).rejects.toThrow(RangeError);
  });
});

describe("root-store degrades to memory-only without IndexedDB", () => {
  it("putRoot / getRoot / deleteRoot resolve without throwing", async () => {
    await expect(putRoot("u1", ROOT, 1)).resolves.toBeUndefined();
    await expect(getRoot("u1")).resolves.toBeNull();
    await expect(deleteRoot("u1")).resolves.toBeUndefined();
  });
});
