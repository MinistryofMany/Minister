import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock @minister/vc's loadIssuer so we can drive its resolution/rejection and
// assert getIssuer's caching behavior without touching KMS or a key file.
const loadIssuer = vi.fn();
vi.mock("@minister/vc", () => ({
  loadIssuer: (...args: unknown[]) => loadIssuer(...args) as unknown,
}));

import { getIssuer } from "./issuer";

describe("getIssuer — cache poisoning on transient boot failure (L2)", () => {
  beforeEach(() => {
    globalThis.__ministerIssuerPromise = undefined;
    loadIssuer.mockReset();
  });
  afterEach(() => {
    globalThis.__ministerIssuerPromise = undefined;
  });

  it("a first-call rejection (transient KMS blip) does NOT poison the second call", async () => {
    const fakeIssuer = { did: "did:web:minister.local" };
    loadIssuer
      .mockRejectedValueOnce(new Error("KMS unreachable at boot"))
      .mockResolvedValueOnce(fakeIssuer);

    // First call fails: KMS was briefly unreachable at load.
    await expect(getIssuer()).rejects.toThrow("KMS unreachable at boot");

    // The rejected promise must NOT be cached — the next call re-attempts the
    // load and succeeds, rather than re-throwing the stale rejection forever.
    await expect(getIssuer()).resolves.toBe(fakeIssuer);
    expect(loadIssuer).toHaveBeenCalledTimes(2);
  });

  it("caches a resolved issuer (loadIssuer runs once across calls)", async () => {
    const fakeIssuer = { did: "did:web:minister.local" };
    loadIssuer.mockResolvedValue(fakeIssuer);

    await expect(getIssuer()).resolves.toBe(fakeIssuer);
    await expect(getIssuer()).resolves.toBe(fakeIssuer);
    expect(loadIssuer).toHaveBeenCalledTimes(1);
  });
});
