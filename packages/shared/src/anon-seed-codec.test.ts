import { describe, it, expect } from "vitest";
import {
  ROOT_SEED_BYTES,
  SEED_STRING_LENGTH,
  SEED_WORD_COUNT,
  SeedCodecError,
  generateRootSeed,
  encodeSeedToString,
  decodeStringToSeed,
  encodeSeedToWords,
  decodeWordsToSeed,
  parseSeedInput,
  sampleWordChallengeIndices,
  checkWordChallenge,
} from "./anon-seed-codec";

const hex = (h: string): Uint8Array => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// Golden vectors from spec section 5.4.
const GOLDEN = [
  {
    hex: "00000000000000000000000000000000",
    string: "cfaQY4qf4JZrZUoY4Wn4FeGMa1bq",
    words:
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  },
  {
    hex: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    string: "eSbkZgY3NtfyMHrqDDddh3qUDXYw",
    words: "legal winner thank year wave sausage worth useful legal winner thank yellow",
  },
  {
    hex: "4d696e6973747279206f66204d616e79",
    string: "dk8QMNVR47r8d2rxXhHFFHLRTj5y",
    words: "estate enter olympic tragic elbow develop like under cake help fortune verify",
  },
  {
    hex: "ffffffffffffffffffffffffffffffff",
    string: "gES9VNd84diwWvnPZs9xn76wnxbF",
    words: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
  },
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
    it(`encodes ${g.hex} to the 12 words`, () => {
      expect(encodeSeedToWords(seed).join(" ")).toBe(g.words);
    });
    it(`decodes the words of ${g.hex} back to bytes`, () => {
      expect(toHex(decodeWordsToSeed(g.words))).toBe(g.hex);
    });
    it(`parser accepts both forms of ${g.hex}`, () => {
      expect(toHex(parseSeedInput(g.string))).toBe(g.hex);
      expect(toHex(parseSeedInput(g.words))).toBe(g.hex);
    });
  }
});

describe("round-trip (string and words)", () => {
  it("round-trips 500 random seeds through both encodings", () => {
    for (let i = 0; i < 500; i++) {
      const seed = generateRootSeed();
      expect(seed).toHaveLength(ROOT_SEED_BYTES);
      expect(toHex(decodeStringToSeed(encodeSeedToString(seed)))).toBe(toHex(seed));
      expect(toHex(decodeWordsToSeed(encodeSeedToWords(seed)))).toBe(toHex(seed));
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
      expect(toHex(decodeWordsToSeed(encodeSeedToWords(seed)))).toBe(toHex(seed));
    }
  });
});

describe("cross-encoding equivalence", () => {
  it("string and words of the same bytes decode identically", () => {
    for (let i = 0; i < 200; i++) {
      const seed = generateRootSeed();
      const fromString = decodeStringToSeed(encodeSeedToString(seed));
      const fromWords = decodeWordsToSeed(encodeSeedToWords(seed));
      expect(toHex(fromString)).toBe(toHex(fromWords));
      expect(toHex(fromString)).toBe(toHex(seed));
    }
  });

  it("parser yields identical bytes from either rendering of one seed", () => {
    const seed = generateRootSeed();
    expect(toHex(parseSeedInput(encodeSeedToString(seed)))).toBe(
      toHex(parseSeedInput(encodeSeedToWords(seed).join(" "))),
    );
  });
});

describe("whitespace tolerance (spec 5.3)", () => {
  const g = GOLDEN[2];
  it("tolerates leading/trailing whitespace on the string", () => {
    expect(toHex(parseSeedInput(`  ${g.string}\n`))).toBe(g.hex);
  });
  it("collapses whitespace runs and embedded newlines in words", () => {
    const messy = `  ${g.words.replace(" ", "\n").replace(" ", "   ")}  `;
    expect(toHex(parseSeedInput(messy))).toBe(g.hex);
  });
  it("accepts a word array as well as a string", () => {
    expect(toHex(decodeWordsToSeed(g.words.split(" ")))).toBe(g.hex);
  });
});

describe("hard rejects (spec 5.1/5.3, auditor check 4)", () => {
  it("rejects a flipped character (checksum catches)", () => {
    const bad = "dfaQY4qf4JZrZUoY4Wn4FeGMa1bq"; // c->d on golden[0]
    expect(() => decodeStringToSeed(bad)).toThrow(SeedCodecError);
  });

  it("rejects two swapped words (BIP39 checksum catches)", () => {
    // valid words with an internal swap that breaks the checksum
    const swapped = "legal winner thank year wave sausage worth useful legal winner yellow thank";
    expect(() => decodeWordsToSeed(swapped)).toThrow(SeedCodecError);
  });

  it("rejects an unknown word", () => {
    const bad =
      "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    expect(() => decodeWordsToSeed(bad)).toThrow(SeedCodecError);
  });

  it("rejects 11 and 13 words, and a 24-word mnemonic", () => {
    const w11 = GOLDEN[0].words.split(" ").slice(0, 11).join(" ");
    const w13 = GOLDEN[0].words + " zoo";
    const w24 = Array(24).fill("zoo").join(" ");
    expect(() => decodeWordsToSeed(w11)).toThrow(SeedCodecError);
    expect(() => decodeWordsToSeed(w13)).toThrow(SeedCodecError);
    expect(() => decodeWordsToSeed(w24)).toThrow(SeedCodecError);
    // via the unified parser too
    expect(() => parseSeedInput(w24)).toThrow(SeedCodecError);
  });

  it("rejects the wrong version byte (0x0b) with a valid checksum", () => {
    // Build a base58check string with version 0x0b so only the version check fires.
    const seed = hex(GOLDEN[0].hex);
    const canonical = encodeSeedToString(seed);
    // sanity: canonical round-trips
    expect(decodeStringToSeed(canonical)).toBeDefined();
    // hand-craft 0x0b via the library at test scope
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
    expect(() => encodeSeedToWords(new Uint8Array(17))).toThrow(SeedCodecError);
  });

  it("parser routes a single token to base58check, not words", () => {
    // a lone valid-looking token with a bad checksum must fail as a string
    expect(() => parseSeedInput("zzzzzzzzzzzzzzzzzzzzzzzzzzzz")).toThrow(SeedCodecError);
  });
});

describe("3-word backup quiz (spec 6.3)", () => {
  const words = GOLDEN[1].words.split(" ");

  it("samples 3 distinct in-range indices", () => {
    for (let i = 0; i < 100; i++) {
      const idx = sampleWordChallengeIndices();
      expect(idx).toHaveLength(3);
      expect(new Set(idx).size).toBe(3);
      for (const n of idx) {
        expect(n).toBeGreaterThanOrEqual(1);
        expect(n).toBeLessThanOrEqual(SEED_WORD_COUNT);
      }
      // sorted ascending
      expect([...idx].sort((a, b) => a - b)).toEqual(idx);
    }
  });

  it("accepts correct answers (case/whitespace-insensitive)", () => {
    expect(
      checkWordChallenge(words, [
        { index: 1, answer: "legal" },
        { index: 4, answer: "  YEAR " },
        { index: 12, answer: "Yellow" },
      ]),
    ).toBe(true);
  });

  it("rejects a wrong answer", () => {
    expect(
      checkWordChallenge(words, [
        { index: 1, answer: "legal" },
        { index: 4, answer: "wrong" },
      ]),
    ).toBe(false);
  });

  it("rejects out-of-range, duplicate, and empty responses", () => {
    expect(checkWordChallenge(words, [{ index: 0, answer: "x" }])).toBe(false);
    expect(checkWordChallenge(words, [{ index: 13, answer: "x" }])).toBe(false);
    expect(
      checkWordChallenge(words, [
        { index: 1, answer: "legal" },
        { index: 1, answer: "legal" },
      ]),
    ).toBe(false);
    expect(checkWordChallenge(words, [])).toBe(false);
  });

  it("rejects a challenge against a mis-sized word list", () => {
    expect(checkWordChallenge(words.slice(0, 11), [{ index: 1, answer: "legal" }])).toBe(false);
  });
});
