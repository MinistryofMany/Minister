import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { sha256 } from "@noble/hashes/sha256";

// QR device-pairing wire protocol (identity plan, "QR pairing"). This module is
// the SINGLE source of the on-the-wire framing so the two devices — the one that
// DISPLAYS the QR (needs the root) and the one that SCANS it (holds the root) —
// encode and decode byte-for-byte identically. Pure functions only: HPKE
// seal/open, the QR payload codec, the AAD construction with its separator
// guard, and the forcing-function pairing code. No network, no storage, no
// session lookup lives here — the caller supplies userId and sessionId, and it
// is a REQUIREMENT (audit C2) that each side supply them from its OWN
// authenticated session / OWN state, never from the relay response.
//
// Scan direction is forced by the cryptography: the QR carries the DISPLAYING
// device's ephemeral X25519 public key, and the SCANNING device (which holds the
// root) seals TO that key. The public key IS the channel authenticator — only
// the holder of the matching private key can open. It says nothing about WHO
// that holder is; distinguishing "my other device" from "an attacker's screen"
// is the server's same-account check on seal (C2), never this module.

/** Ciphersuite identifier prefix of the QR payload. ASCII, deliberately NOT a
 * URL: a phone camera app offers nothing to tap, which is the single
 * highest-leverage anti-phishing mitigation. */
export const PAIR_QR_PREFIX = "MP1.";

/** HPKE `info` (RFC 9180 key schedule). Binds the ciphertext to this protocol
 * version so a blob from another Ministry HPKE use can never open here. */
export const PAIR_HPKE_INFO = "ministry/pair/v1";

/** AAD prefix. The full AAD is
 * `PAIR_AAD_PREFIX + userId + "|" + sessionId + "|" + epoch`; the "|" separator
 * is guarded (S2) so a field cannot straddle a boundary. */
export const PAIR_AAD_PREFIX = "ministry/pair/v1|";

/** The AAD field separator. Mirrors `anon-seed-crypto`'s `assertAadPart` (which
 * guards ":"): any field containing it is rejected so the binding cannot be
 * forged across field boundaries. */
const PAIR_AAD_SEPARATOR = "|";

/** Session id: 16 random bytes → 22 unpadded base64url chars. */
export const PAIR_SESSION_ID_BYTES = 16;
export const PAIR_SESSION_ID_B64_LEN = 22;

/** Recipient X25519 public key: 32 bytes → 43 unpadded base64url chars. */
export const PAIR_PUBLIC_KEY_BYTES = 32;
export const PAIR_PUBLIC_KEY_B64_LEN = 43;

/** The 16-byte root, exactly. */
export const PAIR_ROOT_BYTES = 16;

/** Relay body = enc(32) || ct(32) = 64 bytes → 86 unpadded base64url chars.
 * enc is the X25519 encapsulated key (Nenc = 32); ct is AES-256-GCM over the
 * 16-byte root = 16 ciphertext + 16 tag = 32. */
export const PAIR_ENC_BYTES = 32;
export const PAIR_CT_BYTES = PAIR_ROOT_BYTES + 16;
export const PAIR_RELAY_BODY_BYTES = PAIR_ENC_BYTES + PAIR_CT_BYTES;
export const PAIR_RELAY_BODY_B64_LEN = 86;

/** Length of the on-screen pairing code (S1): a typing forcing function, not a
 * "do these match?" check — a phished victim computes the ATTACKER's code and it
 * matches, so it can never be an assurance gadget. */
export const PAIR_CODE_LENGTH = 4;

/** Domain-separated input for the pairing code hash. */
const PAIR_CODE_INFO = "ministry/pair/code/v1";

// RFC 4648 base32 alphabet: 32 = 2^5, so mapping 5 bits per char is unbiased.
// Uppercase-only and read aloud off a screen, which is all the code is for.
const PAIR_CODE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

const utf8 = new TextEncoder();

/** Thrown for any malformed input or failed HPKE open. Fail closed, never
 * partial: a tampered relay body throws here rather than yielding a wrong root. */
export class PairProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PairProtocolError";
  }
}

// --- base64url (unpadded) -------------------------------------------------

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Decode a base64url field asserting the EXACT decoded byte length, and reject
 * non-canonical encodings (atob is lenient) by re-encoding and comparing. */
function decodeExact(value: string, expectedBytes: number, field: string): Uint8Array {
  if (!BASE64URL_RE.test(value)) {
    throw new PairProtocolError(`${field} must be base64url`);
  }
  const bytes = fromBase64Url(value);
  if (bytes.length !== expectedBytes || toBase64Url(bytes) !== value) {
    throw new PairProtocolError(`${field} must be base64url of exactly ${expectedBytes} bytes`);
  }
  return bytes;
}

// --- AAD ------------------------------------------------------------------

function assertAadField(name: string, value: string): void {
  if (value.length === 0 || value.includes(PAIR_AAD_SEPARATOR)) {
    // "|" is the AAD field separator (S2); allowing it would make the encoding
    // ambiguous and the binding forgeable across field boundaries.
    throw new PairProtocolError(
      `${name} must be a non-empty string without "${PAIR_AAD_SEPARATOR}"`,
    );
  }
}

/**
 * `utf8("ministry/pair/v1|" + userId + "|" + sessionId + "|" + epoch)`. All
 * three fields are separator-guarded (S2). REQUIREMENT (C2): the caller MUST
 * pass `userId` from its own authenticated session and `sessionId` from its own
 * state (the QR it generated, or the QR it optically scanned) — NEVER a value
 * the relay reported.
 *
 * `epoch` is the enrollment epoch, supplied by each side from ITS OWN state
 * (W1): the sealer passes the epoch its stored root belongs to, the receiver
 * passes its own current server epoch. On a healthy pairing both equal the
 * current epoch and GCM succeeds; a STALE sealer (still holding a pre-re-key
 * root) supplies a different epoch, the AAD differs, and the open fails closed —
 * so the receiver rejects the out-of-date key rather than silently stamping a
 * soft-bricked identity.
 */
export function buildPairAad(userId: string, sessionId: string, epoch: number): Uint8Array {
  const epochStr = String(epoch);
  assertAadField("userId", userId);
  assertAadField("sessionId", sessionId);
  assertAadField("epoch", epochStr);
  return utf8.encode(
    `${PAIR_AAD_PREFIX}${userId}${PAIR_AAD_SEPARATOR}${sessionId}${PAIR_AAD_SEPARATOR}${epochStr}`,
  );
}

// --- session id + QR codec ------------------------------------------------

/** A fresh 16-byte session id → 22-char base64url, from the platform CSPRNG. */
export function generateSessionId(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(PAIR_SESSION_ID_BYTES)));
}

/** Validate a session id string is exactly 22 base64url chars (16 bytes). */
export function isValidSessionId(sessionId: string): boolean {
  if (sessionId.length !== PAIR_SESSION_ID_B64_LEN) return false;
  try {
    decodeExact(sessionId, PAIR_SESSION_ID_BYTES, "sessionId");
    return true;
  } catch {
    return false;
  }
}

/** `MP1.<sessionId:22>.<pk:43>` — ~70 ASCII chars, no user id, no expiry, no
 * signature (the public key IS the authenticator), no URL. */
export function encodePairQr(sessionId: string, publicKey: Uint8Array): string {
  if (!isValidSessionId(sessionId)) {
    throw new PairProtocolError("sessionId must be 22 base64url chars");
  }
  if (publicKey.length !== PAIR_PUBLIC_KEY_BYTES) {
    throw new PairProtocolError(`publicKey must be ${PAIR_PUBLIC_KEY_BYTES} bytes`);
  }
  return `${PAIR_QR_PREFIX}${sessionId}.${toBase64Url(publicKey)}`;
}

/** Strictly parse a scanned QR. Returns null for ANYTHING that is not exactly a
 * well-formed `MP1.` payload — a foreign QR, a URL, a truncated capture, or a
 * wrong-length field — so a wrong scan degrades to "not a Ministry code", never
 * to a partial/garbage seal target. */
export function parsePairQr(text: string): { sessionId: string; publicKey: Uint8Array } | null {
  if (!text.startsWith(PAIR_QR_PREFIX)) return null;
  const rest = text.slice(PAIR_QR_PREFIX.length);
  const parts = rest.split(".");
  if (parts.length !== 2) return null;
  const [sessionId, pk] = parts;
  if (
    sessionId === undefined ||
    pk === undefined ||
    sessionId.length !== PAIR_SESSION_ID_B64_LEN ||
    pk.length !== PAIR_PUBLIC_KEY_B64_LEN
  ) {
    return null;
  }
  try {
    decodeExact(sessionId, PAIR_SESSION_ID_BYTES, "sessionId");
    const publicKey = decodeExact(pk, PAIR_PUBLIC_KEY_BYTES, "publicKey");
    return { sessionId, publicKey };
  } catch {
    return null;
  }
}

// --- relay body codec -----------------------------------------------------

/** 64-byte relay body (enc||ct) → 86-char base64url. */
export function encodeRelayBody(body: Uint8Array): string {
  if (body.length !== PAIR_RELAY_BODY_BYTES) {
    throw new PairProtocolError(`relay body must be ${PAIR_RELAY_BODY_BYTES} bytes`);
  }
  return toBase64Url(body);
}

/** 86-char base64url → 64-byte relay body. Hard-rejects any other shape. */
export function decodeRelayBody(value: string): Uint8Array {
  return decodeExact(value, PAIR_RELAY_BODY_BYTES, "relay body");
}

// --- HPKE -----------------------------------------------------------------

let suiteSingleton: CipherSuite | null = null;

/**
 * RFC 9180 mode_base, single-shot. DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
 * AES-256-GCM. AES-256 (not the RFC A.1 128-bit AEAD) to match the rest of the
 * repo, which is uniformly AES-256-GCM (audit S5).
 */
function pairSuite(): CipherSuite {
  if (suiteSingleton === null) {
    suiteSingleton = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
  }
  return suiteSingleton;
}

/** A fresh ephemeral X25519 recipient key pair for the DISPLAYING device. The
 * private key stays in the returned `CryptoKeyPair` (memory-only, never
 * serialized, never uploaded); only the serialized public key rides the QR. */
export async function generateRecipientKeyPair(): Promise<{
  keyPair: CryptoKeyPair;
  publicKey: Uint8Array;
}> {
  const suite = pairSuite();
  const keyPair = await suite.kem.generateKeyPair();
  const publicKey = new Uint8Array(await suite.kem.serializePublicKey(keyPair.publicKey));
  if (publicKey.length !== PAIR_PUBLIC_KEY_BYTES) {
    throw new PairProtocolError("unexpected X25519 public key length");
  }
  return { keyPair, publicKey };
}

/**
 * SCANNING side: HPKE-seal the 16 root bytes to the DISPLAYING device's
 * scanned public key. Returns the 64-byte relay body `enc || ct`. The AAD binds
 * userId + sessionId + epoch (C2/W1): the caller passes userId from its OWN
 * session, sessionId from the QR it OPTICALLY scanned, and `epoch` as the
 * enrollment epoch of the root it holds — never from the relay.
 */
export async function sealRoot(params: {
  recipientPublicKey: Uint8Array;
  root: Uint8Array;
  userId: string;
  sessionId: string;
  epoch: number;
}): Promise<Uint8Array> {
  if (params.recipientPublicKey.length !== PAIR_PUBLIC_KEY_BYTES) {
    throw new PairProtocolError(`recipientPublicKey must be ${PAIR_PUBLIC_KEY_BYTES} bytes`);
  }
  if (params.root.length !== PAIR_ROOT_BYTES) {
    throw new PairProtocolError(`root must be exactly ${PAIR_ROOT_BYTES} bytes`);
  }
  const suite = pairSuite();
  const aad = buildPairAad(params.userId, params.sessionId, params.epoch);
  const pkR = await suite.kem.deserializePublicKey(params.recipientPublicKey);
  const { enc, ct } = await suite.seal(
    { recipientPublicKey: pkR, info: utf8.encode(PAIR_HPKE_INFO) },
    params.root,
    aad,
  );
  const encBytes = new Uint8Array(enc);
  const ctBytes = new Uint8Array(ct);
  if (encBytes.length !== PAIR_ENC_BYTES || ctBytes.length !== PAIR_CT_BYTES) {
    throw new PairProtocolError("unexpected HPKE output length");
  }
  const body = new Uint8Array(PAIR_RELAY_BODY_BYTES);
  body.set(encBytes, 0);
  body.set(ctBytes, PAIR_ENC_BYTES);
  return body;
}

/**
 * DISPLAYING side: HPKE-open a relay body back to the 16 root bytes with the
 * memory-only recipient key pair. Throws (never returns a wrong root) on any GCM
 * tag or AAD mismatch — a relay that delivered a tampered or substituted payload
 * hard-errors here. The caller passes userId from its OWN session, sessionId
 * from its OWN generated state, and `epoch` as its OWN current server epoch
 * (C2/W1), so a mismatch means the payload was not sealed for this exact
 * (user, session, epoch) — including a stale sealer holding a pre-re-key root.
 */
export async function openRoot(params: {
  recipientKeyPair: CryptoKeyPair;
  relayBody: Uint8Array;
  userId: string;
  sessionId: string;
  epoch: number;
}): Promise<Uint8Array> {
  if (params.relayBody.length !== PAIR_RELAY_BODY_BYTES) {
    throw new PairProtocolError(`relay body must be ${PAIR_RELAY_BODY_BYTES} bytes`);
  }
  const suite = pairSuite();
  const aad = buildPairAad(params.userId, params.sessionId, params.epoch);
  const enc = params.relayBody.slice(0, PAIR_ENC_BYTES);
  const ct = params.relayBody.slice(PAIR_ENC_BYTES);
  let ptBuf: ArrayBuffer;
  try {
    ptBuf = await suite.open(
      { recipientKey: params.recipientKeyPair, enc, info: utf8.encode(PAIR_HPKE_INFO) },
      ct,
      aad,
    );
  } catch {
    throw new PairProtocolError(
      "pairing open failed: authentication failed (tampered payload, wrong key, or wrong account/session)",
    );
  }
  const root = new Uint8Array(ptBuf);
  if (root.length !== PAIR_ROOT_BYTES) {
    root.fill(0);
    throw new PairProtocolError(`opened ${root.length} bytes, expected ${PAIR_ROOT_BYTES}`);
  }
  return root;
}

// --- pairing code (S1) ----------------------------------------------------

/**
 * `f(sessionId, pk)` — both taken from the QR, so the DISPLAY device and the
 * SCAN device compute the SAME code from the same optical input. It is rendered
 * ONLY as a typing forcing function ("type these 4 characters to continue"),
 * NEVER as "check these match on both screens": a phished victim computes the
 * attacker's code and it matches, so a "do they match?" UI is a false-assurance
 * gadget in the one attack that matters (S1).
 */
export function derivePairCode(sessionId: string, publicKey: Uint8Array): string {
  if (!isValidSessionId(sessionId)) {
    throw new PairProtocolError("sessionId must be 22 base64url chars");
  }
  if (publicKey.length !== PAIR_PUBLIC_KEY_BYTES) {
    throw new PairProtocolError(`publicKey must be ${PAIR_PUBLIC_KEY_BYTES} bytes`);
  }
  const sessionIdBytes = fromBase64Url(sessionId);
  const input = new Uint8Array(PAIR_CODE_INFO.length + sessionIdBytes.length + publicKey.length);
  input.set(utf8.encode(PAIR_CODE_INFO), 0);
  input.set(sessionIdBytes, PAIR_CODE_INFO.length);
  input.set(publicKey, PAIR_CODE_INFO.length + sessionIdBytes.length);
  const digest = sha256(input);
  let code = "";
  for (let i = 0; i < PAIR_CODE_LENGTH; i++) {
    // One digest byte per char, low 5 bits → one base32 symbol. 32 = 2^5, so
    // this mapping is unbiased.
    code += PAIR_CODE_ALPHABET[digest[i]! & 0x1f];
  }
  return code;
}

/** Case-insensitive, whitespace-trimmed check of a typed pairing code against
 * the code derived from the scanned QR. NOT a security control (S1) — a forcing
 * function to make the user actually read the other device's screen. */
export function checkPairCode(sessionId: string, publicKey: Uint8Array, typed: string): boolean {
  const expected = derivePairCode(sessionId, publicKey);
  return typed.trim().toUpperCase() === expected;
}
