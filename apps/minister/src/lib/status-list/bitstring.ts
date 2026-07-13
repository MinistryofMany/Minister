import { gzipSync } from "node:zlib";

import { SHARD_SIZE_BITS, SHARD_SIZE_BYTES } from "./constants";

// W3C Bitstring Status List v1.0 bit encoding. The bit at index `i` is the
// (i mod 8)-th bit FROM THE LEFT (most-significant-first) of byte `i >> 3`:
//   byte    = i >> 3
//   mask    = 0x80 >> (i & 7)
// This MUST match the SDK's decode (minister-client/src/status-list.ts) exactly,
// or a revoked bit set here reads clear there. Pinned by tests on both sides.

export function newBitstring(): Uint8Array {
  return new Uint8Array(SHARD_SIZE_BYTES);
}

function assertIndex(index: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= SHARD_SIZE_BITS) {
    throw new Error(`bit index ${index} out of range [0, ${SHARD_SIZE_BITS})`);
  }
}

export function getBit(bits: Uint8Array, index: number): boolean {
  assertIndex(index);
  const byte = bits[index >> 3] ?? 0;
  return (byte & (0x80 >> (index & 7))) !== 0;
}

// Returns true if the bit changed (was clear, now set). Never clears a bit —
// `revocation` status is monotonic (§5.6).
export function setBit(bits: Uint8Array, index: number): boolean {
  assertIndex(index);
  const byteIdx = index >> 3;
  const mask = 0x80 >> (index & 7);
  const prev = bits[byteIdx] ?? 0;
  if ((prev & mask) !== 0) return false;
  bits[byteIdx] = prev | mask;
  return true;
}

// W3C multibase base64url ("u" prefix, no padding) of GZIP(bits) — the
// `encodedList` value the credential carries. The SDK inverts this.
export function encodeList(bits: Uint8Array): string {
  const gz = gzipSync(bits);
  return `u${gz.toString("base64url")}`;
}
