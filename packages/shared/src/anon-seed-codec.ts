import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha256";

// E4 root-secret codec (anon-identity master spec, section 5). One 16-byte root
// seed renders as a canonical base58check string (what the password manager
// saves and pairing transfers). The 12-word BIP-39 aid is retired: the fixed
// 28-char string is the ONLY backup format (decision O-2, 2026-07-16), so the
// codec no longer carries a mnemonic path or the @scure/bip39 dependency.
//
// Pure encode/decode only. No key derivation, storage, or transport lives here
// (that is the vault module, spec section 7/8). Hand-rolling base58 is
// prohibited; this leans on the audited @scure / @noble primitives.

/** The root seed is exactly 128 bits (spec 4). */
export const ROOT_SEED_BYTES = 16;

/** Version byte prepended before base58check (spec 5.1). Avoids Bitcoin's
 * well-known version bytes while keeping the string a fixed 28 chars. */
export const SEED_VERSION_BYTE = 0x0a;

/** Fixed length of the canonical base58check string for any 16-byte payload. */
export const SEED_STRING_LENGTH = 28;

// Classic base58check: base58 of `data || first4(sha256(sha256(data)))`.
// createBase58check applies the passed hash twice, matching spec 5.1.
const base58check = createBase58check(sha256);

/** Thrown for any malformed codec input. */
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

/**
 * Recovery parser (spec 5.3): the base58check string is now the only accepted
 * form, so this is a thin alias over decodeStringToSeed. Kept as a named entry
 * point so callers (the vault) need not change. Never silently truncates, pads,
 * or "fixes" input.
 */
export function parseSeedInput(input: string): Uint8Array {
  if (input.trim().length === 0) {
    throw new SeedCodecError("empty input: enter your Private Identity as the 28-character string");
  }
  return decodeStringToSeed(input);
}
