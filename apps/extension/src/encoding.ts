// Encoding helpers for the TLSNotary prover output.
//
// tlsn-js hands us a presentation as a HEX string (`Presentation.serialize()`
// returns `arrayToHex(wasmPresentation.serialize())`, and the wasm serializer
// is `bincode::serialize`). The Minister tlsn-verifier sidecar, on the other
// hand, expects `base64(bincode(Presentation))`. So the only transform the
// extension owes is hex -> base64 over the exact same bytes.

/** Parses a hex string (optionally `0x`-prefixed) into bytes. Throws on
 *  odd length or non-hex characters, so a malformed prover output fails loudly
 *  rather than silently corrupting the presentation. */
export function hexToBytes(hex: string): Uint8Array {
  let h = hex.trim();
  if (h.startsWith("0x") || h.startsWith("0X")) {
    h = h.slice(2);
  }
  if (h.length % 2 !== 0) {
    throw new Error(`hex string has odd length (${h.length})`);
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`invalid hex at byte ${i}: ${h.slice(i * 2, i * 2 + 2)}`);
    }
    out[i] = byte;
  }
  return out;
}

/** base64 (standard, with padding) of the given bytes. */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000; // avoid arg-count limits on String.fromCharCode
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/** hex(bincode(Presentation)) -> base64(bincode(Presentation)), the exact
 *  format the tlsn-verifier sidecar deserializes. */
export function hexToBase64(hex: string): string {
  return bytesToBase64(hexToBytes(hex));
}
