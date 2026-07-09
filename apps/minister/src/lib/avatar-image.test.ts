import { describe, expect, it } from "vitest";

import { MAX_AVATAR_BYTES, sniffAvatarType, validateAvatarBytes } from "@/lib/avatar-image";

// Build a byte array from a leading signature plus padding, so each fixture is
// a realistic length without hand-typing hundreds of bytes.
function withSig(sig: number[], totalLen = 64): Uint8Array {
  const out = new Uint8Array(Math.max(totalLen, sig.length));
  out.set(sig, 0);
  return out;
}

const PNG = withSig([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const JPEG = withSig([0xff, 0xd8, 0xff, 0xe0]);
// "RIFF" + 4 size bytes + "WEBP" ...
const WEBP = withSig([0x52, 0x49, 0x46, 0x46, 0x24, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50]);
// A minimal SVG document — the format we must REJECT (it can carry script).
const SVG = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"></svg>');

describe("sniffAvatarType", () => {
  it("recognizes PNG by its 8-byte signature", () => {
    expect(sniffAvatarType(PNG)).toBe("image/png");
  });

  it("recognizes JPEG by FF D8 FF", () => {
    expect(sniffAvatarType(JPEG)).toBe("image/jpeg");
  });

  it("recognizes WebP by the RIFF....WEBP container", () => {
    expect(sniffAvatarType(WEBP)).toBe("image/webp");
  });

  it("rejects SVG", () => {
    expect(sniffAvatarType(SVG)).toBeNull();
  });

  it("rejects a RIFF container that is not WEBP (e.g. a WAV)", () => {
    // "RIFF" + size + "WAVE"
    const wav = withSig([0x52, 0x49, 0x46, 0x46, 0x24, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45]);
    expect(sniffAvatarType(wav)).toBeNull();
  });

  it("rejects arbitrary/unknown bytes", () => {
    expect(sniffAvatarType(new Uint8Array([0x00, 0x01, 0x02, 0x03]))).toBeNull();
  });

  it("does not read past a truncated buffer", () => {
    expect(sniffAvatarType(new Uint8Array([0x89, 0x50]))).toBeNull();
  });
});

describe("validateAvatarBytes", () => {
  it("accepts a PNG with a matching declared type", () => {
    expect(validateAvatarBytes(PNG, "image/png")).toEqual({ ok: true, contentType: "image/png" });
  });

  it("accepts a JPEG with a matching declared type", () => {
    expect(validateAvatarBytes(JPEG, "image/jpeg")).toEqual({
      ok: true,
      contentType: "image/jpeg",
    });
  });

  it("accepts a WebP with a matching declared type", () => {
    expect(validateAvatarBytes(WEBP, "image/webp")).toEqual({
      ok: true,
      contentType: "image/webp",
    });
  });

  it("stores the SNIFFED type even when the declared type is blank", () => {
    expect(validateAvatarBytes(PNG, "")).toEqual({ ok: true, contentType: "image/png" });
  });

  it("rejects when the declared allowed type contradicts the real bytes", () => {
    // Bytes are JPEG, browser claims PNG — a spoofed MIME.
    const result = validateAvatarBytes(JPEG, "image/png");
    expect(result.ok).toBe(false);
  });

  it("rejects SVG even when it declares an allowed type", () => {
    const result = validateAvatarBytes(SVG, "image/png");
    expect(result.ok).toBe(false);
  });

  it("rejects an empty file", () => {
    expect(validateAvatarBytes(new Uint8Array(0), "image/png").ok).toBe(false);
  });

  it("rejects a file over the size cap", () => {
    const big = new Uint8Array(MAX_AVATAR_BYTES + 1);
    big.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 0); // valid PNG magic
    const result = validateAvatarBytes(big, "image/png");
    expect(result.ok).toBe(false);
  });

  it("accepts a file exactly at the size cap", () => {
    const atCap = new Uint8Array(MAX_AVATAR_BYTES);
    atCap.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 0);
    expect(validateAvatarBytes(atCap, "image/png")).toEqual({
      ok: true,
      contentType: "image/png",
    });
  });
});
