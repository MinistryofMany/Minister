import { describe, expect, it } from "vitest";

import { avatarDataUri, generateAvatarSvg } from "@/lib/avatar";

describe("generateAvatarSvg", () => {
  it("is deterministic — the same seed yields byte-identical SVG", () => {
    const a = generateAvatarSvg("user_abc123");
    const b = generateAvatarSvg("user_abc123");
    expect(a).toBe(b);
  });

  it("produces different SVG for different seeds", () => {
    const a = generateAvatarSvg("user_abc123");
    const b = generateAvatarSvg("user_xyz789");
    expect(a).not.toBe(b);
  });

  it("emits a well-formed self-contained SVG with the xmlns", () => {
    const svg = generateAvatarSvg("seed");
    expect(svg.startsWith("<svg")).toBe(true);
    expect(svg.endsWith("</svg>")).toBe(true);
    expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
  });

  it("respects the size argument in the viewBox and dimensions", () => {
    const svg = generateAvatarSvg("seed", 48);
    expect(svg).toContain('viewBox="0 0 48 48"');
    expect(svg).toContain('width="48"');
  });

  it("contains no external references (no href/url to a remote resource)", () => {
    const svg = generateAvatarSvg("seed");
    expect(svg).not.toContain("http://www.gravatar.com");
    expect(svg).not.toContain("xlink:href");
    // The only url(...) is the internal clip-path reference.
    expect(svg).not.toContain("url(http");
  });

  it("does not vary with unrelated global state (two seeds interleaved stay stable)", () => {
    const a1 = generateAvatarSvg("a");
    generateAvatarSvg("b");
    const a2 = generateAvatarSvg("a");
    expect(a1).toBe(a2);
  });
});

describe("avatarDataUri", () => {
  it("wraps the SVG as a url-encoded data URI", () => {
    const uri = avatarDataUri("seed");
    expect(uri.startsWith("data:image/svg+xml,")).toBe(true);
    expect(decodeURIComponent(uri.slice("data:image/svg+xml,".length))).toBe(
      generateAvatarSvg("seed"),
    );
  });

  it("is deterministic for a given seed", () => {
    expect(avatarDataUri("seed")).toBe(avatarDataUri("seed"));
  });
});
