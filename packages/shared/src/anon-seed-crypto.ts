import { ROOT_SEED_BYTES } from "./anon-seed-codec";

// Anon-identity crypto core (anon-identity master spec, sections 7.1, 7.3, 7.5,
// 8.1): per-app HKDF derivation, the PRF wrap, and the memory-only vault seam.
//
// WebCrypto only (spec 8.1 — no userland hash implementations at ministry.id):
// this module is exactly what a v2 seed.ministry.id key-holder iframe would
// host, so it stays dependency-free and platform-primitive. Pure functions, no
// network, no I/O beyond the platform CSPRNG (the fresh wrap IV). Nothing here
// may transmit — or accept from a server round-trip — the seed, a per-app
// secret, the KEK, or a PRF output (governing invariant, spec 2).

/** Per-app secret length (spec 8.1). */
export const PER_APP_SECRET_BYTES = 32;
/** WebAuthn PRF extension output length (spec 7.1). */
export const PRF_OUTPUT_BYTES = 32;
/** AES-GCM IV length, fresh per wrap (spec 7.1). */
export const WRAP_IV_BYTES = 12;
/** AES-256-GCM output for a 16-byte seed: 16 ciphertext + 16 tag (spec 7.1). */
export const WRAP_CIPHERTEXT_BYTES = ROOT_SEED_BYTES + 16;

/** `OidcClient.anonAppId` shape (spec 8.1): lowercase slug, immutable. */
export const ANON_APP_ID_PATTERN = /^[a-z0-9-]{3,32}$/;

// Exact domain-separation strings (identity plan, "The derivation tree"; frozen
// vectors in anon-seed-golden-vectors.json). Never edit without a version bump:
// changing any of these silently forks every derived identity.
//
// L1 info is per-app AND per-epoch: "ministry/v1/rp/" + app_id + "/" + epoch.
// The epoch (Ministry's AnonSeedEnrollment.enrollmentEpoch) lets a global re-key
// bump every app's branch at once without a schema change; app_id excludes "/"
// (ANON_APP_ID_PATTERN), so the app/epoch segment boundary is unambiguous.
const APP_HKDF_SALT = "ministry/anon/v1";
const APP_HKDF_INFO_PREFIX = "ministry/v1/rp/";
const WRAP_KEK_SALT = "minister/anon-seed/wrap/v1";
const WRAP_KEK_INFO = "minister/anon-seed/wrap/v1:aes-256-gcm";
const WRAP_AAD_PREFIX = "minister/anon-seed/blob/v1:";

const utf8 = new TextEncoder();

/** Thrown for any invalid input or failed unwrap. Fail closed, never partial. */
export class AnonSeedCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnonSeedCryptoError";
  }
}

function assertLength(name: string, bytes: Uint8Array, expected: number): void {
  if (bytes.length !== expected) {
    throw new AnonSeedCryptoError(`${name} must be exactly ${expected} bytes, got ${bytes.length}`);
  }
}

// WebCrypto's BufferSource type requires ArrayBuffer-backed views. Re-view in
// place when the input already is one (the normal case); copy only for a
// SharedArrayBuffer-backed input, which WebCrypto would reject outright.
function abBytes(u: Uint8Array): Uint8Array<ArrayBuffer> {
  return u.buffer instanceof ArrayBuffer ? (u as Uint8Array<ArrayBuffer>) : new Uint8Array(u);
}

async function hkdfSha256(
  ikm: Uint8Array,
  salt: string,
  info: string,
  length: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey("raw", abBytes(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: utf8.encode(salt), info: utf8.encode(info) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

/**
 * L1 per-app secret (identity plan, "The derivation tree"):
 * `HKDF-SHA-256(ikm = root, salt = "ministry/anon/v1",
 *  info = "ministry/v1/rp/" + anonAppId + "/" + epoch, L = 32)`.
 * Secrets for different apps are HKDF-independent, so no coalition of apps can
 * link a user across apps from the secrets alone. `epoch` is the enrollment
 * epoch (>= 1, validated the same way as the wrap-AAD counters): bumping it
 * re-keys the whole branch, which is how global re-key propagates.
 */
export async function deriveAppSecret(
  seed: Uint8Array,
  anonAppId: string,
  epoch: number,
): Promise<Uint8Array<ArrayBuffer>> {
  assertLength("root seed", seed, ROOT_SEED_BYTES);
  if (!ANON_APP_ID_PATTERN.test(anonAppId)) {
    throw new AnonSeedCryptoError("anonAppId must be a lowercase slug matching ^[a-z0-9-]{3,32}$");
  }
  assertAadCounter("epoch", epoch);
  return hkdfSha256(
    seed,
    APP_HKDF_SALT,
    `${APP_HKDF_INFO_PREFIX}${anonAppId}/${epoch}`,
    PER_APP_SECRET_BYTES,
  );
}

/**
 * KEK for the PRF wrap (spec 7.1): `HKDF-SHA-256(ikm = prfOutput,
 * salt = "minister/anon-seed/wrap/v1",
 * info = "minister/anon-seed/wrap/v1:aes-256-gcm", L = 32)`.
 * The PRF output exists only inside the browser during a WebAuthn assertion;
 * the KEK inherits that scope and must never be persisted or transmitted.
 */
export async function deriveWrapKek(prfOutput: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  assertLength("PRF output", prfOutput, PRF_OUTPUT_BYTES);
  return hkdfSha256(prfOutput, WRAP_KEK_SALT, WRAP_KEK_INFO, 32);
}

/** The AAD tuple every wrapped blob is bound to (spec 7.1, invariant I12). */
export interface SeedWrapAad {
  userId: string;
  /** The base64url WebAuthn credential id as stored server-side. */
  credentialId: string;
  wrapVersion: number;
  /** Current epoch from enrollment state; bumps on every reset (anti-rollback). */
  enrollmentEpoch: number;
}

function assertAadPart(name: string, value: string): void {
  if (value.length === 0 || value.includes(":")) {
    // ":" is the AAD field separator; allowing it would make the encoding
    // ambiguous and the binding forgeable across field boundaries.
    throw new AnonSeedCryptoError(`${name} must be a non-empty string without ":"`);
  }
}

function assertAadCounter(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new AnonSeedCryptoError(`${name} must be an integer >= 1, got ${value}`);
  }
}

/**
 * `utf8("minister/anon-seed/blob/v1:" + userId + ":" + credentialId + ":" +
 * wrapVersion + ":" + enrollmentEpoch)` (spec 7.1). Binding the full tuple
 * means a blob cannot be replayed across users, credentials, wrap formats, or
 * enrollment epochs.
 */
export function buildWrapAad(aad: SeedWrapAad): Uint8Array<ArrayBuffer> {
  assertAadPart("userId", aad.userId);
  assertAadPart("credentialId", aad.credentialId);
  assertAadCounter("wrapVersion", aad.wrapVersion);
  assertAadCounter("enrollmentEpoch", aad.enrollmentEpoch);
  return utf8.encode(
    `${WRAP_AAD_PREFIX}${aad.userId}:${aad.credentialId}:${aad.wrapVersion}:${aad.enrollmentEpoch}`,
  );
}

/** A PRF-wrapped seed blob: what `putSeedBlob` uploads and Ministry stores. */
export interface WrappedSeed {
  /** AES-256-GCM output including the 16-byte tag: exactly 32 bytes. */
  ciphertext: Uint8Array;
  /** Fresh random 12-byte IV, generated per wrap. */
  iv: Uint8Array;
}

/**
 * Wrap the root seed under the PRF-derived KEK (spec 7.1). AES-256-GCM with a
 * fresh CSPRNG IV per call and the full AAD tuple bound in. The returned blob
 * is safe to store server-side: without the PRF output it is undecryptable.
 */
export async function wrapSeed(
  seed: Uint8Array,
  prfOutput: Uint8Array,
  aad: SeedWrapAad,
): Promise<WrappedSeed> {
  assertLength("root seed", seed, ROOT_SEED_BYTES);
  const aadBytes = buildWrapAad(aad);
  const kekBytes = await deriveWrapKek(prfOutput);
  const kek = await crypto.subtle.importKey("raw", kekBytes, "AES-GCM", false, ["encrypt"]);
  kekBytes.fill(0); // best-effort zeroization; the CryptoKey is non-extractable
  const iv = crypto.getRandomValues(new Uint8Array(WRAP_IV_BYTES));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aadBytes, tagLength: 128 },
      kek,
      abBytes(seed),
    ),
  );
  if (ciphertext.length !== WRAP_CIPHERTEXT_BYTES) {
    throw new AnonSeedCryptoError(
      `wrap produced ${ciphertext.length} bytes, expected ${WRAP_CIPHERTEXT_BYTES}`,
    );
  }
  return { ciphertext, iv };
}

/**
 * Unwrap a blob back to the 16 seed bytes. Fails closed on any GCM tag or AAD
 * mismatch (wrong PRF output, tampered blob, replay across users/credentials,
 * or a stale pre-reset enrollment epoch — the I12 anti-rollback property).
 * Never returns partial or wrong plaintext.
 */
export async function unwrapSeed(
  blob: WrappedSeed,
  prfOutput: Uint8Array,
  aad: SeedWrapAad,
): Promise<Uint8Array<ArrayBuffer>> {
  assertLength("blob iv", blob.iv, WRAP_IV_BYTES);
  assertLength("blob ciphertext", blob.ciphertext, WRAP_CIPHERTEXT_BYTES);
  const aadBytes = buildWrapAad(aad);
  const kekBytes = await deriveWrapKek(prfOutput);
  const kek = await crypto.subtle.importKey("raw", kekBytes, "AES-GCM", false, ["decrypt"]);
  kekBytes.fill(0);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: abBytes(blob.iv), additionalData: aadBytes, tagLength: 128 },
      kek,
      abBytes(blob.ciphertext),
    );
  } catch {
    throw new AnonSeedCryptoError(
      "seed unwrap failed: authentication failed (wrong passkey, tampered blob, or stale enrollment epoch)",
    );
  }
  const seed = new Uint8Array(plaintext);
  if (seed.length !== ROOT_SEED_BYTES) {
    seed.fill(0);
    throw new AnonSeedCryptoError(
      `unwrap produced ${seed.length} bytes, expected ${ROOT_SEED_BYTES}`,
    );
  }
  return seed;
}

/**
 * The memory-only seed holder behind the vault seam (spec 7.3/7.5). The seed
 * lives only in this closure: copied in on unlock, zeroized on lock, never
 * readable from outside — callers get per-app secrets, never the seed.
 * `deriveAppSecret` matches the 7.5 seam signature exactly, so the v2
 * seed.ministry.id iframe can swap in behind the same interface.
 * Enrollment-ACTIVE gating is the app vault's job (it owns server state);
 * this module stays pure.
 */
export interface MemoryVault {
  /** Load a seed (copied; caller keeps ownership of its buffer). Replaces and zeroizes any prior seed. */
  unlock(seed: Uint8Array): void;
  isUnlocked(): boolean;
  /** The spec 7.5 seam: per-app secret out, seed never. Rejects while locked. */
  deriveAppSecret(anonAppId: string, epoch: number): Promise<Uint8Array>;
  /** Zeroize (best effort) and drop the seed. */
  lock(): void;
}

export function createMemoryVault(): MemoryVault {
  let seed: Uint8Array | null = null;
  return {
    unlock(input: Uint8Array): void {
      assertLength("root seed", input, ROOT_SEED_BYTES);
      seed?.fill(0);
      seed = new Uint8Array(input);
    },
    isUnlocked(): boolean {
      return seed !== null;
    },
    async deriveAppSecret(anonAppId: string, epoch: number): Promise<Uint8Array> {
      if (seed === null) {
        throw new AnonSeedCryptoError("vault is locked: unlock a seed before deriving");
      }
      return deriveAppSecret(seed, anonAppId, epoch);
    },
    lock(): void {
      seed?.fill(0);
      seed = null;
    },
  };
}
