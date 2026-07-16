import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha256";
import { entropyToMnemonic, mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";

// E4 root-secret codec (anon-identity master spec, section 5). One 16-byte root
// seed renders two ways: a canonical base58check string (what the password
// manager saves and pairing transfers) and 12 BIP39 words (the write-it-down
// aid). Both decode to the identical 16 bytes; the parser accepts either.
//
// Pure encode/decode only. No key derivation, storage, or transport lives here
// (that is the vault module, spec section 7/8). Hand-rolling base58 or the
// wordlist is prohibited; this leans on audited @scure / @noble primitives.

/** The root seed is exactly 128 bits (spec 4). */
export const ROOT_SEED_BYTES = 16;

/** Version byte prepended before base58check (spec 5.1). Avoids Bitcoin's
 * well-known version bytes while keeping the string a fixed 28 chars. */
export const SEED_VERSION_BYTE = 0x0a;

/** A 12-word BIP39 mnemonic (128-bit ENT + 4-bit checksum, spec 5.2). */
export const SEED_WORD_COUNT = 12;

/** Fixed length of the canonical base58check string for any 16-byte payload. */
export const SEED_STRING_LENGTH = 28;

// Classic base58check: base58 of `data || first4(sha256(sha256(data)))`.
// createBase58check applies the passed hash twice, matching spec 5.1.
const base58check = createBase58check(sha256);

/** Thrown for any malformed codec input. Message names both accepted forms so
 * a recovery UI can surface it directly. */
export class SeedCodecError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SeedCodecError";
  }
}

function assertSeedBytes(seed: Uint8Array): void {
  if (seed.length !== ROOT_SEED_BYTES) {
    throw new SeedCodecError(
      `root seed must be exactly ${ROOT_SEED_BYTES} bytes, got ${seed.length}`,
    );
  }
}

/** Generate a fresh 16-byte root seed from the platform CSPRNG (spec 4). */
export function generateRootSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(ROOT_SEED_BYTES));
}

/** 16 bytes -> canonical 28-char base58check string (spec 5.1). */
export function encodeSeedToString(seed: Uint8Array): string {
  assertSeedBytes(seed);
  const versioned = new Uint8Array(ROOT_SEED_BYTES + 1);
  versioned[0] = SEED_VERSION_BYTE;
  versioned.set(seed, 1);
  return base58check.encode(versioned);
}

/** Canonical base58check string -> 16 bytes (spec 5.1). Case-sensitive, no
 * normalization beyond an outer trim. Bad checksum or wrong version hard-reject. */
export function decodeStringToSeed(input: string): Uint8Array {
  const trimmed = input.trim();
  let versioned: Uint8Array;
  try {
    // base58check.decode verifies and strips the 4-byte checksum.
    versioned = base58check.decode(trimmed);
  } catch {
    throw new SeedCodecError(
      "invalid Private Identity string: not valid base58check (checksum failed or bad characters)",
    );
  }
  if (versioned.length !== ROOT_SEED_BYTES + 1) {
    throw new SeedCodecError(
      `invalid Private Identity string: expected ${ROOT_SEED_BYTES + 1} decoded bytes, got ${versioned.length}`,
    );
  }
  if (versioned[0] !== SEED_VERSION_BYTE) {
    throw new SeedCodecError(
      `invalid Private Identity string: wrong version byte 0x${versioned[0]!.toString(16).padStart(2, "0")} (expected 0x0a)`,
    );
  }
  return versioned.slice(1);
}

/** 16 bytes -> 12 BIP39 English words (spec 5.2). */
export function encodeSeedToWords(seed: Uint8Array): string[] {
  assertSeedBytes(seed);
  return entropyToMnemonic(seed, wordlist).split(" ");
}

/** 12 BIP39 words -> 16 bytes (spec 5.2). Accepts a string or a word array;
 * validates word membership and the BIP39 checksum, hard-rejects otherwise. */
export function decodeWordsToSeed(input: string | readonly string[]): Uint8Array {
  const words = (Array.isArray(input) ? input.join(" ") : (input as string))
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 0);
  if (words.length !== SEED_WORD_COUNT) {
    throw new SeedCodecError(
      `invalid Private Identity words: expected ${SEED_WORD_COUNT} words, got ${words.length}`,
    );
  }
  let entropy: Uint8Array;
  try {
    // mnemonicToEntropy throws on an unknown word or a bad BIP39 checksum.
    entropy = mnemonicToEntropy(words.join(" "), wordlist);
  } catch {
    throw new SeedCodecError("invalid Private Identity words: unknown word or failed checksum");
  }
  if (entropy.length !== ROOT_SEED_BYTES) {
    // 12 words is always 128-bit entropy; defensive only.
    throw new SeedCodecError(
      `invalid Private Identity words: decoded ${entropy.length} bytes, expected ${ROOT_SEED_BYTES}`,
    );
  }
  return entropy;
}

/**
 * Recovery parser (spec 5.3): accept either encoding and return the 16 bytes.
 * Whitespace with 2+ tokens is treated as words; otherwise as the base58check
 * string. Never silently truncates, pads, or "fixes" input.
 */
export function parseSeedInput(input: string): Uint8Array {
  // Collapse internal whitespace runs to single spaces, trim the ends.
  const normalized = input.trim().replace(/\s+/g, " ");
  if (normalized.length === 0) {
    throw new SeedCodecError(
      "empty input: enter your Private Identity as the 28-character string or the 12 words",
    );
  }
  if (normalized.includes(" ")) {
    return decodeWordsToSeed(normalized);
  }
  return decodeStringToSeed(normalized);
}

/**
 * Sample `count` distinct 1-based word indices in `1..total` via rejection
 * sampling on the CSPRNG (no modulo bias, spec 6.3). Used to build the backup
 * quiz ("type word #3, #7, #11").
 */
export function sampleWordChallengeIndices(count = 3, total = SEED_WORD_COUNT): number[] {
  if (count < 0 || count > total) {
    throw new SeedCodecError(`cannot sample ${count} distinct indices from ${total}`);
  }
  const chosen = new Set<number>();
  // Rejection sampling: draw a byte, discard the biased tail, map to 0..total-1.
  const limit = Math.floor(256 / total) * total;
  const buf = new Uint8Array(1);
  while (chosen.size < count) {
    crypto.getRandomValues(buf);
    const b = buf[0]!;
    if (b >= limit) continue;
    chosen.add((b % total) + 1);
  }
  return [...chosen].sort((a, b) => a - b);
}

/** One answer in the backup quiz: the 1-based word position and what the user typed. */
export interface WordChallengeResponse {
  index: number;
  answer: string;
}

/**
 * Verify a backup quiz (spec 6.3): every response's answer, lowercased and
 * trimmed, must equal the word at that 1-based index. Comparison is entirely
 * client-side and is a UX forcing function, never a security control (spec's
 * honesty note): a caller may not build any security property on the result.
 * Returns false (never throws) for out-of-range or duplicate indices.
 */
export function checkWordChallenge(
  words: readonly string[],
  responses: readonly WordChallengeResponse[],
): boolean {
  if (words.length !== SEED_WORD_COUNT) return false;
  if (responses.length === 0) return false;
  const seen = new Set<number>();
  for (const { index, answer } of responses) {
    if (!Number.isInteger(index) || index < 1 || index > SEED_WORD_COUNT) {
      return false;
    }
    if (seen.has(index)) return false;
    seen.add(index);
    if (answer.trim().toLowerCase() !== words[index - 1]) return false;
  }
  return true;
}
