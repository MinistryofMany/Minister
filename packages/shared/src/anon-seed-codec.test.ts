import { describe, it, expect } from "vitest";
import {
  ROOT_SEED_BYTES,
  SEED_STRING_LENGTH,
  SeedCodecError,
  generateRootSeed,
  encodeSeedToString,
  decodeStringToSeed,
  parseSeedInput,
} from "./anon-seed-codec";

const hex = (h: string): Uint8Array => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// Golden vectors from spec section 5.4 (base58check string form only; the
// 12-word rendering was retired, decision O-2).
const GOLDEN = [
  { hex: "00000000000000000000000000000000", string: "cfaQY4qf4JZrZUoY4Wn4FeGMa1bq" },
  { hex: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", string: "eSbkZgY3NtfyMHrqDDddh3qUDXYw" },
  { hex: "4d696e6973747279206f66204d616e79", string: "dk8QMNVR47r8d2rxXhHFFHLRTj5y" },
  { hex: "ffffffffffffffffffffffffffffffff", string: "gES9VNd84diwWvnPZs9xn76wnxbF" },
] as const;

describe("golden vectors (spec 5.4)", () => {
  for (const g of GOLDEN) {
    const seed = hex(g.hex);
    it(`encodes ${g.hex} to the canonical string`, () => {
      const s = encodeSeedToString(seed);
      expect(s).toBe(g.string);
      expect(s).toHaveLength(SEED_STRING_LENGTH);
      expect(s[0]).toMatch(/[c-g]/); // spec: first char falls in c..g
    });
    it(`decodes the string of ${g.hex} back to bytes`, () => {
      expect(toHex(decodeStringToSeed(g.string))).toBe(g.hex);
    });
    it(`parser accepts the string form of ${g.hex}`, () => {
      expect(toHex(parseSeedInput(g.string))).toBe(g.hex);
    });
  }
});

describe("round-trip", () => {
  it("round-trips 500 random seeds through the string encoding", () => {
    for (let i = 0; i < 500; i++) {
      const seed = generateRootSeed();
      expect(seed).toHaveLength(ROOT_SEED_BYTES);
      expect(toHex(decodeStringToSeed(encodeSeedToString(seed)))).toBe(toHex(seed));
    }
  });

  it("round-trips edge-case seeds (all-zero, all-0xff, single-bit)", () => {
    const edges = [
      new Uint8Array(16),
      hex("ffffffffffffffffffffffffffffffff"),
      (() => {
        const b = new Uint8Array(16);
        b[0] = 0x80;
        return b;
      })(),
      (() => {
        const b = new Uint8Array(16);
        b[15] = 0x01;
        return b;
      })(),
    ];
    for (const seed of edges) {
      expect(toHex(decodeStringToSeed(encodeSeedToString(seed)))).toBe(toHex(seed));
    }
  });
});

describe("whitespace tolerance (spec 5.3)", () => {
  const g = GOLDEN[2];
  it("tolerates leading/trailing whitespace on the string", () => {
    expect(toHex(parseSeedInput(`  ${g.string}\n`))).toBe(g.hex);
    expect(toHex(decodeStringToSeed(`  ${g.string}\n`))).toBe(g.hex);
  });
});

describe("hard rejects (spec 5.1/5.3, auditor check 4)", () => {
  it("rejects a flipped character (checksum catches)", () => {
    const bad = "dfaQY4qf4JZrZUoY4Wn4FeGMa1bq"; // c->d on golden[0]
    expect(() => decodeStringToSeed(bad)).toThrow(SeedCodecError);
  });

  it("rejects the wrong version byte (0x0b) with a valid checksum", () => {
    // Build a base58check string with version 0x0b so only the version check fires.
    const seed = hex(GOLDEN[0].hex);
    const canonical = encodeSeedToString(seed);
    // sanity: canonical round-trips
    expect(decodeStringToSeed(canonical)).toBeDefined();
    const versioned = new Uint8Array(17);
    versioned[0] = 0x0b;
    versioned.set(seed, 1);
    // encode with the same checksum scheme the codec uses
    // (import lazily to avoid widening the module's public surface)
    return import("@scure/base").then(async ({ createBase58check }) => {
      const { sha256 } = await import("@noble/hashes/sha256");
      const s = createBase58check(sha256).encode(versioned);
      expect(() => decodeStringToSeed(s)).toThrow(/version/);
    });
  });

  it("rejects empty input", () => {
    expect(() => parseSeedInput("   ")).toThrow(SeedCodecError);
  });

  it("rejects non-16-byte seeds on encode", () => {
    expect(() => encodeSeedToString(new Uint8Array(15))).toThrow(SeedCodecError);
    expect(() => encodeSeedToString(new Uint8Array(17))).toThrow(SeedCodecError);
  });

  it("rejects a lone bad-checksum token as a string", () => {
    expect(() => parseSeedInput("zzzzzzzzzzzzzzzzzzzzzzzzzzzz")).toThrow(SeedCodecError);
  });
});
