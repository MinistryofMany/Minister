import { createHmac, hkdfSync } from "node:crypto";

// Length-prefixed / structured encoding for the Sybil-dedup nullifier
// construction. NEVER bare-concatenate attacker-influenceable, variable-length
// fields (an anchor is an email or a github id): `a‖b` collides `("x","yz")`
// with `("xy","z")`. `LP(x)` prevents that by prefixing the exact byte length.
//
// LP(x) = 2-byte big-endian length of x's bytes, followed by x's bytes.
// Fields are capped so the 2-byte length can always hold them.
const MAX_FIELD_BYTES = 0xffff;

// §2.1 frozen per-field byte caps. The LP structure alone prevents collisions,
// but the frozen spec bounds each input field individually and the Phase 3
// Signet backend WILL enforce these — so the interim backend must reject the
// SAME inputs, or a long anchor that passes here would only fail at the backend
// flip. Enforced at the call sites below (not inside lp/lpStr, which also encode
// fixed-length internal fields like the stored 32-byte HMAC value).
const MAX_ANCHOR_BYTES = 512;
const MAX_BADGE_TYPE_BYTES = 64;
const MAX_CLIENT_ID_BYTES = 256;

function capField(value: string, maxBytes: number, field: string): void {
  const len = Buffer.byteLength(value, "utf8");
  if (len > maxBytes) {
    throw new Error(`nullifier field ${field} too long: ${len} > ${maxBytes} bytes`);
  }
}

// Length-prefix an already-binary field (e.g. a stored HMAC value).
export function lp(bytes: Buffer): Buffer {
  if (bytes.length > MAX_FIELD_BYTES) {
    throw new Error(`nullifier LP field too long: ${bytes.length} bytes`);
  }
  const prefix = Buffer.allocUnsafe(2);
  prefix.writeUInt16BE(bytes.length, 0);
  return Buffer.concat([prefix, bytes]);
}

// Length-prefix a UTF-8 string field.
export function lpStr(value: string): Buffer {
  return lp(Buffer.from(value, "utf8"));
}

// The interim dedup key, derived from the live pairwise secret with a distinct
// HKDF info so it can never collide with the pairwise-sub HMAC space. This is a
// SEPARATE root domain from the pairwise families (which HMAC the raw secret
// directly): k_int is HKDF-expanded, so even a `pairwiseSub` and a `value` over
// identical bytes derive under different keys.
//
// k_int = HKDF-SHA256(ikm=OIDC_PAIRWISE_SECRET, salt="", info="minister/v1/nullifier-interim", L=32)
const HKDF_INFO = "minister/v1/nullifier-interim";
const K_INT_BYTES = 32;

function interimKey(): Buffer {
  // Read the secret directly (like oidc-tokens.pairwiseSub) rather than via
  // env.ts, so tests can inject a fixed secret through process.env. Fail fast:
  // deriving under an absent key would silently produce a wrong, poisoned ledger.
  const secret = process.env.OIDC_PAIRWISE_SECRET;
  if (!secret) {
    throw new Error("OIDC_PAIRWISE_SECRET must be set (nullifier interim backend)");
  }
  // Node returns an ArrayBuffer; wrap it as a Buffer without copying.
  return Buffer.from(
    hkdfSync("sha256", Buffer.from(secret, "utf8"), Buffer.alloc(0), HKDF_INFO, K_INT_BYTES),
  );
}

// Stage-1 dedup value: deterministic per (anchor, badgeType), UNIQUE-indexed in
// the ledger. value = HMAC(k_int, LP("dedup") || LP(anchor) || LP(badgeType)).
// Returned as raw bytes (stored as Prisma Bytes) so the UNIQUE comparison is
// exact byte equality with no encoding ambiguity.
export function deriveDedupValue(anchor: string, badgeType: string): Buffer {
  capField(anchor, MAX_ANCHOR_BYTES, "anchor");
  capField(badgeType, MAX_BADGE_TYPE_BYTES, "badge_type");
  const msg = Buffer.concat([lpStr("dedup"), lpStr(anchor), lpStr(badgeType)]);
  return createHmac("sha256", interimKey()).update(msg).digest();
}

// Stage-2 per-RP disclosed nullifier, derived from the STORED dedup `value`
// (never the discarded anchor) plus the clientId:
//   "mnv1:" + base64url(HMAC(k_int, LP("rp") || LP(value) || LP(clientId)))
// The "mnv1:" prefix versions the disclosed value forever. Deterministic per
// (value, clientId): same credential ⇒ same per-RP nullifier, across accounts
// and across account delete/re-create.
export function deriveDisclosedNullifier(value: Buffer, clientId: string): string {
  capField(clientId, MAX_CLIENT_ID_BYTES, "clientId");
  const msg = Buffer.concat([lpStr("rp"), lp(value), lpStr(clientId)]);
  const mac = createHmac("sha256", interimKey()).update(msg).digest("base64url");
  return `mnv1:${mac}`;
}
