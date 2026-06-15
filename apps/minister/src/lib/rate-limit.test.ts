import { describe, expect, it } from "vitest";

import { clientIpFrom, createRateLimiter } from "./rate-limit";

const T0 = 1_750_000_000_000;

describe("createRateLimiter", () => {
  it("allows up to max hits inside the window", () => {
    const rl = createRateLimiter({ windowMs: 60_000, max: 3 });
    expect(rl.check("a", T0).allowed).toBe(true);
    expect(rl.check("a", T0 + 1000).allowed).toBe(true);
    expect(rl.check("a", T0 + 2000).allowed).toBe(true);
    expect(rl.check("a", T0 + 3000).allowed).toBe(false);
  });

  it("reports retry-after as the time until the oldest hit expires", () => {
    const rl = createRateLimiter({ windowMs: 60_000, max: 1 });
    rl.check("a", T0);
    const verdict = rl.check("a", T0 + 10_000);
    expect(verdict.allowed).toBe(false);
    expect(verdict.retryAfterSeconds).toBe(50);
  });

  it("slides: hits age out of the window", () => {
    const rl = createRateLimiter({ windowMs: 60_000, max: 2 });
    rl.check("a", T0);
    rl.check("a", T0 + 1000);
    expect(rl.check("a", T0 + 2000).allowed).toBe(false);
    // Both T0 and T0+1000 have aged out by T0+61_500 — two slots free.
    expect(rl.check("a", T0 + 61_000).allowed).toBe(true);
    expect(rl.check("a", T0 + 61_500).allowed).toBe(true);
    expect(rl.check("a", T0 + 62_000).allowed).toBe(false);
  });

  it("tracks keys independently", () => {
    const rl = createRateLimiter({ windowMs: 60_000, max: 1 });
    expect(rl.check("a", T0).allowed).toBe(true);
    expect(rl.check("b", T0).allowed).toBe(true);
    expect(rl.check("a", T0 + 1).allowed).toBe(false);
    expect(rl.check("b", T0 + 1).allowed).toBe(false);
  });

  it("a denied attempt does not consume a slot", () => {
    const rl = createRateLimiter({ windowMs: 60_000, max: 1 });
    rl.check("a", T0);
    // Hammering while limited shouldn't extend the lockout.
    for (let i = 1; i <= 100; i++) rl.check("a", T0 + i * 100);
    expect(rl.check("a", T0 + 60_001).allowed).toBe(true);
  });
});

describe("clientIpFrom", () => {
  function headersOf(map: Record<string, string>) {
    return {
      get: (name: string) => map[name.toLowerCase()] ?? null,
    };
  }

  it("takes the first hop of x-forwarded-for", () => {
    expect(clientIpFrom(headersOf({ "x-forwarded-for": "1.2.3.4, 10.0.0.1" }))).toBe("1.2.3.4");
  });

  it("falls back to x-real-ip", () => {
    expect(clientIpFrom(headersOf({ "x-real-ip": "5.6.7.8" }))).toBe("5.6.7.8");
  });

  it("falls back to a fixed bucket when no headers are present", () => {
    expect(clientIpFrom(headersOf({}))).toBe("unknown");
  });
});
