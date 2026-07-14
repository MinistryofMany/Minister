import assert from "node:assert/strict";
import { test } from "node:test";

import { bytesToBase64, hexToBase64, hexToBytes } from "./encoding.ts";

test("hexToBytes parses lowercase, uppercase, and 0x-prefixed", () => {
  assert.deepEqual([...hexToBytes("00ff10")], [0x00, 0xff, 0x10]);
  assert.deepEqual([...hexToBytes("00FF10")], [0x00, 0xff, 0x10]);
  assert.deepEqual([...hexToBytes("0x00ff10")], [0x00, 0xff, 0x10]);
  assert.deepEqual([...hexToBytes("")], []);
});

test("hexToBytes rejects odd length and non-hex", () => {
  assert.throws(() => hexToBytes("abc"), /odd length/);
  assert.throws(() => hexToBytes("zz"), /invalid hex/);
});

test("bytesToBase64 matches known vectors", () => {
  assert.equal(bytesToBase64(new Uint8Array([])), "");
  // "Man" -> TWFu is the canonical base64 example.
  assert.equal(bytesToBase64(new Uint8Array([0x4d, 0x61, 0x6e])), "TWFu");
  assert.equal(bytesToBase64(new Uint8Array([0x00])), "AA==");
});

test("bytesToBase64 handles large buffers without arg-count overflow", () => {
  const big = new Uint8Array(200_000).fill(0x41); // 'A'
  const b64 = bytesToBase64(big);
  // Round-trips back to the same bytes via Node's Buffer.
  assert.equal(Buffer.from(b64, "base64").length, big.length);
});

test("hexToBase64 composes the two over the same bytes", () => {
  // hex of "Man" -> base64 "TWFu"
  assert.equal(hexToBase64("4d616e"), "TWFu");
  // A round-trip against Node's Buffer for a random-ish payload.
  const hex = "deadbeef0102030405";
  const expected = Buffer.from(hex, "hex").toString("base64");
  assert.equal(hexToBase64(hex), expected);
});
