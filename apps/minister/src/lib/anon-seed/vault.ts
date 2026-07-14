// Client-side vault for the anonymous-identity root seed (anon-identity master
// spec §7). This module — plus the enrollment/backup/unlock components under
// src/components/anon-seed/ that it explicitly owns — is the ONLY place seed
// bytes may live (invariant I4). Everything else calls deriveAppSecret and
// receives a per-app secret, never the seed.
//
// GOVERNING INVARIANT (spec §2): nothing here may transmit the seed, a per-app
// secret, a PRF output, or the KEK to any server. The only seed-derived bytes
// that leave this module for a server are the PRF-wrapped AES-256-GCM blob
// handed to putSeedBlob, which Ministry cannot decrypt. The dedicated PRF
// WebAuthn assertion is consumed entirely inside this module and is never
// serialized or transported (spec §7.1 invariant-critical note): it must never
// ride the Auth.js login ceremony, whose assertion IS posted to the server.
//
// Seed material never touches script-readable browser storage of any kind
// (spec §7.3, global rule). The only storage use below is the boolean
// memory-only PREFERENCE — no key material.

import {
  AnonSeedCryptoError,
  deriveAppSecret as deriveAppSecretFromSeed,
  encodeSeedToString,
  parseSeedInput,
  PER_APP_SECRET_BYTES,
  PRF_OUTPUT_BYTES,
  ROOT_SEED_BYTES,
  unwrapSeed,
  wrapSeed,
} from "@minister/shared";

import {
  getAnonPasskeyCredentialIds,
  getAnonSeedState,
  getSeedBlobs,
  putSeedBlob,
} from "@/server/anon-seed-actions";

/** Fragment prefix for per-app-secret delivery (spec §8.2 grammar). */
export const ANON_FRAGMENT_PREFIX = "#minister_anon=v1.";

/** The fixed PRF evaluation input (spec §7.1 step 3). */
const PRF_EVAL_INPUT = new TextEncoder().encode("minister/anon-seed/prf/v1");

/** PasswordCredential id for the L2 password-manager entry (spec §7.2). */
export const PM_CREDENTIAL_ID = "anonymous-writing-key";

// Preference key prefix (per-user, multi-account check 15). Value "1" only —
// a stored CHOICE, never key material.
const MEMORY_ONLY_PREF_PREFIX = "minister.anon.memory-only.";

// ---------------------------------------------------------------------------
// Module state: the in-memory seed (L3 is exactly this and nothing more).
// Keyed by userId so two Ministry accounts in one browsing session can never
// cross seeds (spec §12 check 15). Page navigation or tab close drops it.
// ---------------------------------------------------------------------------

let seed: Uint8Array | null = null;
let seedUserId: string | null = null;
// I3: no derivation before enrollment is ACTIVE. Set only by the owned
// enrollment/unlock paths after the server confirms ACTIVE state.
let active = false;

/** Load a seed into the vault (copied; the caller should zeroize its own
 * buffer). Only the owned enrollment/unlock components may call this. */
export function unlockVault(userId: string, input: Uint8Array, opts: { active: boolean }): void {
  if (input.length !== ROOT_SEED_BYTES) {
    throw new AnonSeedCryptoError(`root seed must be ${ROOT_SEED_BYTES} bytes`);
  }
  seed?.fill(0);
  seed = new Uint8Array(input);
  seedUserId = userId;
  active = opts.active;
}

/** Flip the vault to ACTIVE after the server confirms the backup (spec §6.3
 * step 3). No-op if the vault holds another user's seed. */
export function markVaultActive(userId: string): void {
  if (seed !== null && seedUserId === userId) active = true;
}

/** Zeroize (best effort) and drop the seed. */
export function lockVault(): void {
  seed?.fill(0);
  seed = null;
  seedUserId = null;
  active = false;
}

/** True when THIS user's seed is loaded and enrollment is ACTIVE — i.e. the
 * consent flow can deliver an anonymous identity right now. */
export function isVaultReady(userId: string): boolean {
  return seed !== null && seedUserId === userId && active;
}

// ---------------------------------------------------------------------------
// The seam (spec §7.5): one derivation entry point. The v2 seed.ministry.id
// key-holder iframe replaces only the implementation behind this signature.
// ---------------------------------------------------------------------------

/**
 * Derive the 32-byte per-app secret for `anonAppId` (spec §8.1). `userId` is
 * the multi-account guard: it must match the user whose seed unlocked the
 * vault. Refuses while locked or before enrollment is ACTIVE (I3). Callers
 * get the per-app secret only — the seed never crosses this boundary (I4).
 */
export async function deriveAppSecret(anonAppId: string, userId: string): Promise<Uint8Array> {
  if (seed === null || seedUserId !== userId) {
    throw new AnonSeedCryptoError("vault is locked");
  }
  if (!active) {
    throw new AnonSeedCryptoError("enrollment is not active"); // I3
  }
  return deriveAppSecretFromSeed(seed, anonAppId);
}

/** `"#minister_anon=v1." + base64url(secret)` (spec §8.2 step 3). */
export function buildAnonFragment(perAppSecret: Uint8Array): string {
  if (perAppSecret.length !== PER_APP_SECRET_BYTES) {
    throw new AnonSeedCryptoError(
      `per-app secret must be ${PER_APP_SECRET_BYTES} bytes, got ${perAppSecret.length}`,
    );
  }
  return ANON_FRAGMENT_PREFIX + toBase64Url(perAppSecret);
}

/**
 * The redirect target for the consent client's final hop (spec §8.2): the
 * success URL plus the per-app-secret fragment. Fail-open for login,
 * fail-closed for identity (spec §8.3): ANY failure — locked vault, inactive
 * enrollment, bad app id — returns the plain URL unchanged, never a made-up
 * secret. Never throws.
 */
export async function buildAnonRedirect(
  redirectTo: string,
  anonAppId: string,
  userId: string,
): Promise<string> {
  try {
    const secret = await deriveAppSecret(anonAppId, userId);
    const target = redirectTo + buildAnonFragment(secret);
    secret.fill(0);
    return target;
  } catch {
    return redirectTo;
  }
}

// ---------------------------------------------------------------------------
// L0 / L2 entry: parse a typed or autofilled key (string or 12 words).
// ---------------------------------------------------------------------------

/** Unlock from a typed/autofilled key in either codec form (spec §5.3, §7.4).
 * Throws SeedCodecError on malformed input; the vault stays locked. Only used
 * for ACTIVE enrollments (the unlock UI renders only then). */
export function unlockWithSeedInput(userId: string, input: string): void {
  const parsed = parseSeedInput(input);
  unlockVault(userId, parsed, { active: true });
  parsed.fill(0);
}

// ---------------------------------------------------------------------------
// L1: PRF passkey — wrap on enroll, unwrap on unlock (spec §7.1).
// ---------------------------------------------------------------------------

// lib.dom types PublicKeyCredential.getClientCapabilities as always present;
// older engines lack it at runtime, so feature-detect before calling.
type PkcStatic = typeof PublicKeyCredential & {
  getClientCapabilities?: () => Promise<Record<string, boolean>>;
};

/** Coarse PRF availability: true/false from getClientCapabilities where the
 * API exists, null when unknown (probe at click time instead). */
export async function prfCapabilityHint(): Promise<boolean | null> {
  if (typeof PublicKeyCredential === "undefined") return null;
  const pkc = PublicKeyCredential as PkcStatic;
  if (typeof pkc.getClientCapabilities !== "function") return null;
  try {
    const caps = await pkc.getClientCapabilities();
    return caps["extension:prf"] ?? null;
  } catch {
    return null;
  }
}

type PrfAssertOutcome =
  | { kind: "ok"; credentialId: string; prfOutput: Uint8Array }
  | { kind: "cancelled" }
  | { kind: "prf-unsupported" };

// The dedicated PRF assertion (spec §7.1). The challenge is local-only random:
// this assertion is never sent to or verified by any server — it exists solely
// to make the authenticator emit the PRF output inside this browser. The
// response object never leaves this function; only the credential id string
// and the PRF bytes (consumed locally) are read from it.
async function prfAssert(credentialIds: string[]): Promise<PrfAssertOutcome> {
  let cred: Credential | null;
  try {
    cred = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: credentialIds.map((id) => ({
          type: "public-key" as const,
          id: fromBase64Url(id),
        })),
        userVerification: "required",
        extensions: { prf: { eval: { first: PRF_EVAL_INPUT } } },
      },
    });
  } catch {
    // NotAllowedError (user cancelled / timed out) and everything else: the
    // layer degrades explicitly (I5), never silently to a different secret.
    return { kind: "cancelled" };
  }
  if (!cred || typeof (cred as PublicKeyCredential).getClientExtensionResults !== "function") {
    return { kind: "cancelled" };
  }
  const pk = cred as PublicKeyCredential;
  const first = pk.getClientExtensionResults().prf?.results?.first;
  if (!first) return { kind: "prf-unsupported" };
  const prfOutput = bufferSourceToU8(first);
  if (prfOutput.length !== PRF_OUTPUT_BYTES) {
    prfOutput.fill(0);
    return { kind: "prf-unsupported" };
  }
  return { kind: "ok", credentialId: pk.id, prfOutput };
}

export type PasskeyEnrollResult =
  | { ok: true; credentialId: string }
  | {
      ok: false;
      reason:
        "vault-locked" | "not-active" | "no-passkeys" | "prf-unsupported" | "cancelled" | "server";
      message: string;
    };

/**
 * Wrap the loaded seed under a PRF-derived KEK and store the ciphertext blob
 * with Ministry (spec §7.1 steps 1-6). Requires the vault unlocked for this
 * user and ACTIVE enrollment (I3). The PRF output and KEK never leave this
 * browser; only ciphertext + IV + the public credential id are uploaded.
 */
export async function enrollPasskeyBlob(userId: string): Promise<PasskeyEnrollResult> {
  if (seed === null || seedUserId !== userId) {
    return { ok: false, reason: "vault-locked", message: "Unlock your key first." };
  }
  const state = await getAnonSeedState();
  if (!state.ok) return { ok: false, reason: "server", message: state.error };
  if (state.state.status !== "active") {
    return {
      ok: false,
      reason: "not-active",
      message: "Finish backing up your key before storing it.",
    };
  }
  const creds = await getAnonPasskeyCredentialIds();
  if (!creds.ok) return { ok: false, reason: "server", message: creds.error };
  if (creds.credentialIds.length === 0) {
    return {
      ok: false,
      reason: "no-passkeys",
      message: "You have no passkeys yet. Add one under Settings → Credentials first.",
    };
  }
  const assertion = await prfAssert(creds.credentialIds);
  if (assertion.kind === "cancelled") {
    return { ok: false, reason: "cancelled", message: "Passkey prompt was cancelled." };
  }
  if (assertion.kind === "prf-unsupported") {
    return {
      ok: false,
      reason: "prf-unsupported",
      message:
        "This passkey can't protect your key on this device. Use the password manager instead.",
    };
  }
  const wrapped = await wrapSeed(seed, assertion.prfOutput, {
    userId,
    credentialId: assertion.credentialId,
    wrapVersion: 1,
    enrollmentEpoch: state.state.enrollmentEpoch,
  });
  assertion.prfOutput.fill(0);
  const put = await putSeedBlob({
    credentialId: assertion.credentialId,
    ciphertext: toBase64Url(wrapped.ciphertext),
    iv: toBase64Url(wrapped.iv),
    wrapVersion: 1,
  });
  if (!put.ok) return { ok: false, reason: "server", message: put.error };
  return { ok: true, credentialId: assertion.credentialId };
}

export type PasskeyUnlockResult =
  | { ok: true }
  | {
      ok: false;
      reason: "no-blobs" | "prf-unsupported" | "cancelled" | "mismatch" | "server";
      message: string;
    };

/**
 * L1 unlock (spec §7.1): fetch this user's wrapped blobs, run the dedicated
 * PRF assertion, unwrap client-side, load the vault. A GCM/AAD failure —
 * wrong passkey, tampered blob, or a stale pre-reset epoch (I12) — is a hard,
 * explicit error that the UI degrades to L2/L0 (I5).
 */
export async function unlockWithPasskey(userId: string): Promise<PasskeyUnlockResult> {
  const res = await getSeedBlobs();
  if (!res.ok) return { ok: false, reason: "server", message: res.error };
  if (res.blobs.length === 0) {
    return { ok: false, reason: "no-blobs", message: "No passkey-protected copy on file." };
  }
  const assertion = await prfAssert(res.blobs.map((b) => b.credentialId));
  if (assertion.kind === "cancelled") {
    return { ok: false, reason: "cancelled", message: "Passkey prompt was cancelled." };
  }
  if (assertion.kind === "prf-unsupported") {
    return {
      ok: false,
      reason: "prf-unsupported",
      message: "This passkey can't unlock your key on this device.",
    };
  }
  const blob = res.blobs.find((b) => b.credentialId === assertion.credentialId);
  if (!blob) {
    assertion.prfOutput.fill(0);
    return { ok: false, reason: "mismatch", message: "That passkey has no stored copy." };
  }
  try {
    const unwrapped = await unwrapSeed(
      { ciphertext: fromBase64Url(blob.ciphertext), iv: fromBase64Url(blob.iv) },
      assertion.prfOutput,
      {
        userId,
        credentialId: blob.credentialId,
        wrapVersion: blob.wrapVersion,
        enrollmentEpoch: blob.enrollmentEpoch,
      },
    );
    unlockVault(userId, unwrapped, { active: true });
    unwrapped.fill(0);
  } catch {
    return {
      ok: false,
      reason: "mismatch",
      message: "This passkey cannot unlock your key on this device. Enter it manually instead.",
    };
  } finally {
    assertion.prfOutput.fill(0);
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// L2: browser password manager (spec §7.2). Preferred path only — no form.
// The no-PasswordCredential fallback (a network-incapable method="dialog"
// form) lives in the owned pm-save component, not here.
// ---------------------------------------------------------------------------

// PasswordCredential is not in this lib.dom version; minimal local types.
interface PasswordCredentialLike extends Credential {
  readonly password: string;
}
interface PasswordCredentialCtor {
  new (init: { id: string; name?: string; password: string }): Credential;
}
type CredentialsContainerCompat = CredentialsContainer & {
  get(options: {
    password: true;
    mediation: CredentialMediationRequirement;
  }): Promise<Credential | null>;
};

/** True when the Credential Management password API exists (Chromium). */
export function passwordCredentialSupported(): boolean {
  return typeof window !== "undefined" && "PasswordCredential" in window;
}

export type PmSaveResult = "stored" | "unsupported" | "failed";

/**
 * Save the canonical key string to the browser password manager via
 * `navigator.credentials.store()` — the no-form path (spec §7.2, I11): the
 * seed never enters a form control and no request can carry it.
 */
export async function savePasswordToManager(userId: string): Promise<PmSaveResult> {
  if (seed === null || seedUserId !== userId) return "failed";
  if (!passwordCredentialSupported()) return "unsupported";
  const ctor = (window as unknown as { PasswordCredential: PasswordCredentialCtor })
    .PasswordCredential;
  try {
    await navigator.credentials.store(
      new ctor({
        id: PM_CREDENTIAL_ID,
        name: "Ministry anonymous key",
        password: encodeSeedToString(seed),
      }),
    );
    return "stored";
  } catch {
    return "failed";
  }
}

export type PmAutofillResult = "unlocked" | "unsupported" | "none";

/**
 * Chromium retrieval of the saved key. `mediation: "required"` is mandatory
 * (spec §7.2, checklist 10): a zero-click read would let injected JS take the
 * seed with no user gesture. Throws SeedCodecError if the stored value is not
 * a valid key (surfaced, never silently ignored).
 */
export async function autofillFromPasswordManager(userId: string): Promise<PmAutofillResult> {
  if (!passwordCredentialSupported()) return "unsupported";
  const container = navigator.credentials as CredentialsContainerCompat;
  let cred: Credential | null;
  try {
    cred = await container.get({ password: true, mediation: "required" });
  } catch {
    return "none";
  }
  if (!cred || cred.type !== "password") return "none";
  const password = (cred as PasswordCredentialLike).password;
  if (typeof password !== "string") return "none";
  unlockWithSeedInput(userId, password);
  return "unlocked";
}

/**
 * The canonical key string for the OWNED backup/save components only (the two
 * permitted string surfaces, spec §12 check 14): the pm-save dialog fallback
 * and nothing else. Grep rule: no other caller may exist.
 */
export function getSeedBackupString(userId: string): string | null {
  if (seed === null || seedUserId !== userId) return null;
  return encodeSeedToString(seed);
}

// ---------------------------------------------------------------------------
// L3: memory-only preference (spec §7.3). The seed itself is already
// memory-only above; this flag only suppresses the L1/L2 storage offers.
// ---------------------------------------------------------------------------

export function getMemoryOnlyPref(userId: string): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(MEMORY_ONLY_PREF_PREFIX + userId) === "1";
  } catch {
    return false;
  }
}

export function setMemoryOnlyPref(userId: string, value: boolean): void {
  if (typeof window === "undefined") return;
  try {
    if (value) window.localStorage.setItem(MEMORY_ONLY_PREF_PREFIX + userId, "1");
    else window.localStorage.removeItem(MEMORY_ONLY_PREF_PREFIX + userId);
  } catch {
    // Storage unavailable (private mode): the preference just doesn't stick.
  }
}

// ---------------------------------------------------------------------------
// Encoding helpers (base64url, unpadded — the fragment grammar and the blob
// transport shape both use it).
// ---------------------------------------------------------------------------

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bufferSourceToU8(src: BufferSource): Uint8Array {
  if (src instanceof ArrayBuffer) return new Uint8Array(src.slice(0));
  const view = src as ArrayBufferView;
  return new Uint8Array(view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength));
}
