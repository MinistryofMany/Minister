import { createHash, randomBytes } from "node:crypto";

import type { IssuedBadge } from "@minister/plugin-sdk";
import {
  createMessage,
  readCleartextMessage,
  readKey,
  readSignature,
  verify as pgpVerify,
} from "openpgp";
import { parseKey, parseSignature, type Key } from "sshpk";

// Pure, network-free helpers for the public-key proof-of-control flow, kept out
// of index.ts so key parsing, challenge building, and the PGP + SSH signature
// checks are unit-testable without a wizard. Nothing here reaches the network or
// a database; the only inputs are the user-pasted key + signature and the
// server-held challenge.
//
// The fingerprint is the Sybil anchor AND the disclosed claim (revealsAnchor),
// so it appears in the badge on purpose. Everything else the user pastes (the
// full key, any embedded user id/email) is used only to run the check and, for
// PGP, to confirm which key is being proven — none of it is persisted.

// The SSH signature namespace we bind every SSHSIG to. `ssh-keygen -Y sign -n
// <namespace>` stamps this into the signed blob, and we require the exact value
// back, so a signature the user made for some OTHER tool/namespace can never be
// replayed here. (Matches OpenSSH's `PROTOCOL.sshsig` "namespace" field.)
export const SSH_NAMESPACE = "pubkey-proof@ministry.id";

const CHALLENGE_TTL_MS = 15 * 60_000;

export type KeyKind = "pgp" | "ssh";

// A single-use, session-bound challenge: a human statement, the domain, a
// 128-bit nonce, and an expiry. Stored server-side; it is what the signature is
// checked against, so what the user signs is exactly what we verify.
export interface KeyChallenge {
  message: string;
  nonce: string;
  expiresAt: string; // ISO 8601
}

export function buildKeyChallenge(kind: KeyKind, now: Date = new Date()): KeyChallenge {
  const nonce = randomBytes(16).toString("hex"); // 128 bits
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + CHALLENGE_TTL_MS).toISOString();
  const kindLabel = kind === "pgp" ? "PGP" : "SSH";
  const message = [
    `ministry.id wants you to prove you control this ${kindLabel} key.`,
    ``,
    `Nonce: ${nonce}`,
    `Issued at: ${issuedAt}`,
    `Expires at: ${expiresAt}`,
    ``,
    `Signing this proves you hold the key. It grants no access, moves nothing, and only proves control to ministry.id.`,
    ``,
    `Only sign this if you started this yourself on ministry.id.`,
  ].join("\n");
  return { message, nonce, expiresAt };
}

export function isChallengeExpired(expiresAt: string, now: Date = new Date()): boolean {
  const t = Date.parse(expiresAt);
  return !Number.isFinite(t) || now.getTime() > t;
}

// What the user pasted, classified. `null` when it is neither an ASCII-armored
// PGP public key nor a single-line SSH public key.
export function detectKeyKind(input: string): KeyKind | null {
  const trimmed = input.trim();
  if (trimmed.includes("BEGIN PGP PUBLIC KEY BLOCK")) return "pgp";
  if (/^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))\s+/u.test(trimmed)) return "ssh";
  return null;
}

// -----------------------------------------------------------------------------
// PGP
// -----------------------------------------------------------------------------

export interface ParsedPgpKey {
  // Lowercase hex, canonical OpenPGP v4/v6 primary-key fingerprint.
  fingerprint: string;
  // Short, stable algorithm descriptor for the badge claim.
  algorithm: string;
  // Primary user id (name/email) for the confirmation step. Display only — it is
  // NOT persisted into the badge, so a PGP key's email never lands in a VC.
  userId: string | null;
}

// Map openpgp's internal algorithm names to a short, public descriptor.
function pgpAlgorithm(info: { algorithm?: string; bits?: number; curve?: string }): string {
  const alg = info.algorithm ?? "";
  if (alg.startsWith("eddsa")) return info.curve?.startsWith("ed25519") ? "ed25519" : "eddsa";
  if (alg.startsWith("ecdsa"))
    return info.curve ? `ecdsa-${info.curve.replace(/Legacy$/u, "")}` : "ecdsa";
  if (alg.startsWith("rsa")) return info.bits ? `rsa-${info.bits}` : "rsa";
  if (alg.startsWith("dsa")) return "dsa";
  return alg || "unknown";
}

// Parse an ASCII-armored PGP public key. Returns its fingerprint/algorithm/uid,
// or null for anything malformed. Never throws.
export async function parsePgpPublicKey(armored: string): Promise<ParsedPgpKey | null> {
  try {
    const key = await readKey({ armoredKey: armored.trim() });
    // Reject a pasted PRIVATE key outright — the user should only ever share the
    // public half, and we must never accept (or hold) a secret key.
    if (key.isPrivate()) return null;
    const fingerprint = key.getFingerprint().toLowerCase();
    if (!/^[0-9a-f]{40}$|^[0-9a-f]{64}$/u.test(fingerprint)) return null;
    const algorithm = pgpAlgorithm(key.getAlgorithmInfo());
    let userId: string | null = null;
    try {
      const primary = await key.getPrimaryUser();
      userId = primary.user.userID?.userID ?? null;
    } catch {
      userId = null;
    }
    return { fingerprint, algorithm, userId };
  } catch {
    return null;
  }
}

// Verify a PGP signature over the EXACT challenge, made by the PRESENTED key.
//
// Binding to the presented key: `verificationKeys` is ONLY the pasted key, so
// openpgp resolves the signature's issuer key id against that key alone — a
// signature from any other key fails to resolve and is rejected.
//
// Binding to the exact challenge:
//   - clearsigned  -> the signature covers the embedded cleartext; we verify it
//     and require the (canonicalized) cleartext to equal our stored challenge.
//   - detached     -> we build the message from OUR stored challenge and verify
//     the detached signature against it (trying text + binary encodings so both
//     `gpg --clearsign` and `gpg --detach-sign` outputs work).
//
// Never throws — a malformed key/signature is a failed proof, not a server error.
export async function verifyPgpSignature(
  publicKeyArmored: string,
  challenge: string,
  signatureInput: string,
): Promise<boolean> {
  const input = signatureInput.trim();
  if (input.length === 0) return false;

  let key;
  try {
    key = await readKey({ armoredKey: publicKeyArmored.trim() });
  } catch {
    return false;
  }
  // Defense-in-depth: a public-key proof must verify against a PUBLIC key.
  // STEP_FORM already rejects a private-key paste, but re-check here so a future
  // direct caller can't slip a private key past the verifier.
  if (key.isPrivate()) return false;

  // Clearsigned message: the cleartext is inside the block.
  if (input.includes("BEGIN PGP SIGNED MESSAGE")) {
    try {
      const msg = await readCleartextMessage({ cleartextMessage: input });
      const result = await pgpVerify({ message: msg, verificationKeys: key });
      const sig = result.signatures[0];
      if (!sig) return false;
      await sig.verified; // rejects on a bad signature or a non-matching key
      return canonicalizeText(msg.getText()) === canonicalizeText(challenge);
    } catch {
      return false;
    }
  }

  // Detached armored signature over the challenge. Try text-mode (what
  // `--clearsign` and `--textmode` produce) and binary over the exact bytes,
  // with and without a trailing newline (some tools append one). Every candidate
  // is our stored challenge, so this widens tolerance without weakening the bind.
  let sigObj;
  try {
    sigObj = await readSignature({ armoredSignature: input });
  } catch {
    return false;
  }
  const bytes = new TextEncoder().encode(challenge);
  const bytesNl = new TextEncoder().encode(`${challenge}\n`);
  let candidates;
  try {
    candidates = [
      await createMessage({ text: challenge }),
      await createMessage({ binary: bytes }),
      await createMessage({ binary: bytesNl }),
    ];
  } catch {
    return false;
  }
  for (const message of candidates) {
    try {
      const result = await pgpVerify({ message, signature: sigObj, verificationKeys: key });
      const sig = result.signatures[0];
      if (!sig) continue;
      await sig.verified;
      return true;
    } catch {
      // Wrong encoding for this candidate (or key mismatch) — try the next.
    }
  }
  return false;
}

// Canonicalize text the way OpenPGP hashes cleartext: normalize line endings and
// strip trailing whitespace per line, then trim the framing newline. This makes
// the challenge comparison robust to the CRLF/whitespace mangling clients apply
// without loosening the match on the high-entropy nonce itself.
function canonicalizeText(s: string): string {
  return s
    .replace(/\r\n/gu, "\n")
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/u, ""))
    .join("\n")
    .trim();
}

// -----------------------------------------------------------------------------
// SSH (SSHSIG, per OpenSSH PROTOCOL.sshsig)
// -----------------------------------------------------------------------------

export interface ParsedSshKey {
  // `SHA256:…`, the canonical modern OpenSSH fingerprint.
  fingerprint: string;
  algorithm: string;
}

const SSH_ALLOWED_TYPES = new Set(["ed25519", "rsa", "ecdsa"]);

// Parse a single-line SSH public key (ssh-ed25519 / ssh-rsa / ecdsa-sha2-*),
// returning its fingerprint + algorithm, or null. Never throws. DSA is refused.
export function parseSshPublicKey(line: string): ParsedSshKey | null {
  let key: Key;
  try {
    key = parseKey(line.trim(), "ssh");
  } catch {
    return null;
  }
  if (!SSH_ALLOWED_TYPES.has(key.type)) return null;
  try {
    const fingerprint = key.fingerprint("sha256").toString();
    const algorithm = sshAlgorithm(key);
    return { fingerprint, algorithm };
  } catch {
    return null;
  }
}

function sshAlgorithm(key: Key): string {
  if (key.type === "ecdsa") return key.curve ? `ecdsa-${key.curve}` : "ecdsa";
  if (key.type === "rsa") return `rsa-${key.size}`;
  return key.type; // ed25519
}

const SSHSIG_MAGIC = Buffer.from("SSHSIG");

// The inner-signature hash for a given SSHSIG inner signature algorithm. This is
// NOT the SSHSIG message-hash (that field pre-hashes the message); it is the hash
// the signature primitive itself uses over the signed blob. Legacy `ssh-rsa`
// (SHA-1) is deliberately absent -> unsupported -> rejected.
const SSH_INNER_HASH: Record<string, string> = {
  "ssh-ed25519": "sha512",
  "rsa-sha2-256": "sha256",
  "rsa-sha2-512": "sha512",
  "ecdsa-sha2-nistp256": "sha256",
  "ecdsa-sha2-nistp384": "sha384",
  "ecdsa-sha2-nistp521": "sha512",
};

function readSshString(buf: Buffer, offset: number): { data: Buffer; next: number } | null {
  if (offset + 4 > buf.length) return null;
  const len = buf.readUInt32BE(offset);
  const start = offset + 4;
  const end = start + len;
  if (end > buf.length) return null;
  return { data: buf.subarray(start, end), next: end };
}

function sshString(data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  return Buffer.concat([len, data]);
}

function unarmorSshSig(armored: string): Buffer | null {
  const lines = armored.split(/\r?\n/u);
  const begin = lines.indexOf("-----BEGIN SSH SIGNATURE-----");
  const end = lines.indexOf("-----END SSH SIGNATURE-----");
  if (begin === -1 || end === -1 || end <= begin) return null;
  const b64 = lines
    .slice(begin + 1, end)
    .join("")
    .trim();
  if (!/^[A-Za-z0-9+/=]+$/u.test(b64)) return null;
  try {
    return Buffer.from(b64, "base64");
  } catch {
    return null;
  }
}

// Verify an armored SSHSIG over the EXACT challenge, made by the PRESENTED key,
// under OUR namespace. Reconstructs the signed blob per PROTOCOL.sshsig and
// checks the inner signature with sshpk (which routes to node:crypto). Binds:
//   - namespace  -> must equal SSH_NAMESPACE (else a foreign-namespace signature
//     could be replayed);
//   - key        -> the SSHSIG's embedded public key must byte-equal the pasted
//     key's wire encoding, and that same key verifies the signature;
//   - message    -> H(challenge) under the stated hash goes into the blob, so a
//     signature over any other message fails.
// Never throws. Tries the challenge with and without a trailing newline because
// signing a saved file often appends one.
export function verifySshSignature(
  publicKeyLine: string,
  challenge: string,
  armoredSignature: string,
): boolean {
  const blob = unarmorSshSig(armoredSignature);
  if (!blob) return false;

  // Fixed header: "SSHSIG" magic + uint32 version (1).
  if (blob.length < 10 || !blob.subarray(0, 6).equals(SSHSIG_MAGIC)) return false;
  if (blob.readUInt32BE(6) !== 1) return false;

  let cursor = 10;
  const publicKeyField = readSshString(blob, cursor);
  if (!publicKeyField) return false;
  cursor = publicKeyField.next;
  const namespaceField = readSshString(blob, cursor);
  if (!namespaceField) return false;
  cursor = namespaceField.next;
  const reservedField = readSshString(blob, cursor);
  if (!reservedField) return false;
  cursor = reservedField.next;
  const hashAlgField = readSshString(blob, cursor);
  if (!hashAlgField) return false;
  cursor = hashAlgField.next;
  const signatureField = readSshString(blob, cursor);
  if (!signatureField) return false;
  cursor = signatureField.next;
  // Reject trailing garbage after the documented fields.
  if (cursor !== blob.length) return false;

  const namespace = namespaceField.data.toString("utf8");
  if (namespace !== SSH_NAMESPACE) return false;

  const hashAlg = hashAlgField.data.toString("utf8");
  if (hashAlg !== "sha256" && hashAlg !== "sha512") return false;

  let key: Key;
  try {
    key = parseKey(publicKeyLine.trim(), "ssh");
  } catch {
    return false;
  }
  if (!SSH_ALLOWED_TYPES.has(key.type)) return false;

  // Bind to the presented key: the SSHSIG-embedded key must be exactly the pasted
  // key. Comparing the raw SSH wire encoding is stricter than a fingerprint match.
  let presentedWire: Buffer;
  try {
    presentedWire = key.toBuffer("rfc4253");
  } catch {
    return false;
  }
  if (!publicKeyField.data.equals(presentedWire)) return false;

  // Inner signature: string(algorithm) + string(raw signature).
  const innerType = readSshString(signatureField.data, 0);
  if (!innerType) return false;
  const innerAlg = innerType.data.toString("utf8");
  const innerHash = SSH_INNER_HASH[innerAlg];
  if (!innerHash) return false;

  let sig;
  try {
    sig = parseSignature(signatureField.data, key.type, "ssh");
  } catch {
    return false;
  }

  for (const candidate of [challenge, `${challenge}\n`]) {
    const messageHash = createHash(hashAlg).update(Buffer.from(candidate, "utf8")).digest();
    const signed = Buffer.concat([
      SSHSIG_MAGIC,
      sshString(Buffer.from(SSH_NAMESPACE, "utf8")),
      sshString(Buffer.alloc(0)),
      sshString(Buffer.from(hashAlg, "utf8")),
      sshString(messageHash),
    ]);
    try {
      const verifier = key.createVerify(innerHash);
      verifier.update(signed);
      if (verifier.verify(sig)) return true;
    } catch {
      // Try the newline variant before giving up.
    }
  }
  return false;
}

// -----------------------------------------------------------------------------
// Badge
// -----------------------------------------------------------------------------

// Build the `public-key` badge. The fingerprint is BOTH the Sybil anchor and the
// disclosed claim (naming the key is the whole point), so it rides the claim and
// the badge opts out of the runtime anchor-leak guard via `revealsAnchor` — the
// same discipline as `domain-control`. The runtime still nullifies the anchor so
// one key issues at most one badge.
export function buildPublicKeyBadge(
  kind: KeyKind,
  fingerprint: string,
  algorithm: string,
): IssuedBadge {
  const claims = { kind, fingerprint, algorithm };
  return {
    type: "public-key",
    attributes: { ...claims },
    claims,
    sybilAnchor: fingerprint,
    revealsAnchor: true,
  };
}
