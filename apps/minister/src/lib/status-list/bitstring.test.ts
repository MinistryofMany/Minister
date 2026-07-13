import { gunzipSync } from "node:zlib";

import { describe, expect, it } from "vitest";

import { encodeList, getBit, newBitstring, setBit } from "./bitstring";
import { SHARD_SIZE_BITS, SHARD_SIZE_BYTES } from "./constants";

describe("status-list bitstring", () => {
  it("is 1 KiB of zeros at birth", () => {
    const bits = newBitstring();
    expect(bits.length).toBe(SHARD_SIZE_BYTES);
    expect(bits.every((b) => b === 0)).toBe(true);
  });

  it("sets and reads a bit W3C-style (index 0 = MSB of byte 0)", () => {
    const bits = newBitstring();
    expect(setBit(bits, 0)).toBe(true);
    expect(bits[0]).toBe(0x80);
    expect(getBit(bits, 0)).toBe(true);
    expect(getBit(bits, 1)).toBe(false);

    setBit(bits, 7);
    expect(bits[0]).toBe(0x81);
    setBit(bits, 8);
    expect(bits[1]).toBe(0x80);
  });

  it("setBit is monotonic and idempotent (never clears)", () => {
    const bits = newBitstring();
    expect(setBit(bits, 100)).toBe(true);
    expect(setBit(bits, 100)).toBe(false); // already set — reports no change
    expect(getBit(bits, 100)).toBe(true);
  });

  it("rejects out-of-range indices", () => {
    const bits = newBitstring();
    expect(() => setBit(bits, -1)).toThrow();
    expect(() => setBit(bits, SHARD_SIZE_BITS)).toThrow();
    expect(() => getBit(bits, SHARD_SIZE_BITS)).toThrow();
  });

  it("encodeList is multibase base64url of GZIP(bits) and round-trips", () => {
    const bits = newBitstring();
    setBit(bits, 42);
    setBit(bits, 8191);
    const encoded = encodeList(bits);
    expect(encoded[0]).toBe("u");
    const raw = new Uint8Array(gunzipSync(Buffer.from(encoded.slice(1), "base64url")));
    expect(raw.length).toBe(SHARD_SIZE_BYTES);
    expect(getBit(raw, 42)).toBe(true);
    expect(getBit(raw, 8191)).toBe(true);
    expect(getBit(raw, 43)).toBe(false);
  });
});
