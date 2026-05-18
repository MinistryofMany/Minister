import { describe, expect, it } from "vitest";

import {
  DEFAULT_SHARE_TTL_DAYS,
  MAX_SHARE_TTL_DAYS,
  generateShareToken,
} from "./share-links";

describe("generateShareToken", () => {
  it("returns a URL-safe base64 string of ≥128 bits of entropy", () => {
    // 32 bytes → 43 base64url chars (no padding), >= 256 bits.
    const t = generateShareToken();
    expect(t).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(t.length).toBeGreaterThanOrEqual(43);
  });

  it("returns unique tokens", () => {
    const tokens = new Set(Array.from({ length: 50 }, () => generateShareToken()));
    expect(tokens.size).toBe(50);
  });
});

describe("constants", () => {
  it("defaults TTL to 7 days and caps at 90", () => {
    expect(DEFAULT_SHARE_TTL_DAYS).toBe(7);
    expect(MAX_SHARE_TTL_DAYS).toBe(90);
    expect(DEFAULT_SHARE_TTL_DAYS).toBeLessThanOrEqual(MAX_SHARE_TTL_DAYS);
  });
});
