import { afterEach, beforeEach, describe, expect, it } from "vitest";

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

  // clientIpFrom reads process.env at call time, so each test owns the two
  // knobs and restores them afterward.
  const ENV_KEYS = ["MINISTER_CLIENT_IP_HEADER", "MINISTER_TRUSTED_PROXY_HOPS"] as const;
  let saved: Record<(typeof ENV_KEYS)[number], string | undefined>;

  beforeEach(() => {
    saved = {
      MINISTER_CLIENT_IP_HEADER: process.env.MINISTER_CLIENT_IP_HEADER,
      MINISTER_TRUSTED_PROXY_HOPS: process.env.MINISTER_TRUSTED_PROXY_HOPS,
    };
    for (const key of ENV_KEYS) delete process.env[key];
  });

  afterEach(() => {
    for (const key of ENV_KEYS) {
      const value = saved[key];
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it("uses the default CF-Connecting-IP header when present", () => {
    // Default config (no env set) trusts cf-connecting-ip, even if the
    // client also smuggled an XFF.
    expect(
      clientIpFrom(headersOf({ "cf-connecting-ip": "203.0.113.7", "x-forwarded-for": "1.2.3.4" })),
    ).toBe("203.0.113.7");
  });

  it("trims the trusted header value", () => {
    expect(clientIpFrom(headersOf({ "cf-connecting-ip": "  203.0.113.7  " }))).toBe("203.0.113.7");
  });

  it("honors a configured custom trusted header name", () => {
    process.env.MINISTER_CLIENT_IP_HEADER = "x-real-ip";
    expect(
      clientIpFrom(headersOf({ "x-real-ip": "5.6.7.8", "cf-connecting-ip": "203.0.113.7" })),
    ).toBe("5.6.7.8");
  });

  it("IGNORES a client-supplied XFF when no trusted header and hops=0", () => {
    process.env.MINISTER_CLIENT_IP_HEADER = "";
    // hops defaults to 0 -> XFF is wholly untrusted -> fail-safe bucket.
    expect(clientIpFrom(headersOf({ "x-forwarded-for": "1.2.3.4, 10.0.0.1" }))).toBe("unknown");
  });

  it("ignores XFF when the trusted header is configured but absent and hops=0", () => {
    // Default header trust is on, but the header itself is missing; with no
    // hops the forgeable XFF must not be used.
    expect(clientIpFrom(headersOf({ "x-forwarded-for": "1.2.3.4" }))).toBe("unknown");
  });

  it("hop-counting picks the entry inserted by the outermost trusted proxy (from the right)", () => {
    process.env.MINISTER_CLIENT_IP_HEADER = "";
    process.env.MINISTER_TRUSTED_PROXY_HOPS = "1";
    // [client-forged, real-client, our-proxy] — one trusted hop trusts the
    // rightmost entry (length - 1 = index 2).
    expect(clientIpFrom(headersOf({ "x-forwarded-for": "9.9.9.9, 203.0.113.7, 10.0.0.1" }))).toBe(
      "10.0.0.1",
    );
  });

  it("hop index math: 2 trusted hops trust the second-from-right entry", () => {
    process.env.MINISTER_CLIENT_IP_HEADER = "";
    process.env.MINISTER_TRUSTED_PROXY_HOPS = "2";
    // [forged, real-client, outer-proxy, inner-proxy]; 2 hops -> index
    // length-2 = 2 -> the outer proxy's entry, which is the real client IP
    // as seen by the first hop we control.
    expect(
      clientIpFrom(
        headersOf({ "x-forwarded-for": "9.9.9.9, 203.0.113.7, 198.51.100.5, 10.0.0.1" }),
      ),
    ).toBe("198.51.100.5");
  });

  it("hop index math: a single-entry XFF with one hop trusts that entry", () => {
    process.env.MINISTER_CLIENT_IP_HEADER = "";
    process.env.MINISTER_TRUSTED_PROXY_HOPS = "1";
    expect(clientIpFrom(headersOf({ "x-forwarded-for": "203.0.113.7" }))).toBe("203.0.113.7");
  });

  it("clamps an over-large hop count to the leftmost present entry", () => {
    process.env.MINISTER_CLIENT_IP_HEADER = "";
    process.env.MINISTER_TRUSTED_PROXY_HOPS = "9";
    expect(clientIpFrom(headersOf({ "x-forwarded-for": "203.0.113.7, 10.0.0.1" }))).toBe(
      "203.0.113.7",
    );
  });

  it("trusted header wins over hop counting when both are configured", () => {
    process.env.MINISTER_TRUSTED_PROXY_HOPS = "1";
    expect(
      clientIpFrom(
        headersOf({ "cf-connecting-ip": "203.0.113.7", "x-forwarded-for": "1.2.3.4, 10.0.0.1" }),
      ),
    ).toBe("203.0.113.7");
  });

  it("fails safe to a fixed 'unknown' bucket when nothing trustworthy is present", () => {
    process.env.MINISTER_CLIENT_IP_HEADER = "";
    process.env.MINISTER_TRUSTED_PROXY_HOPS = "2";
    expect(clientIpFrom(headersOf({}))).toBe("unknown");
  });

  it("treats a non-numeric hop count as 0 (untrusted)", () => {
    process.env.MINISTER_CLIENT_IP_HEADER = "";
    process.env.MINISTER_TRUSTED_PROXY_HOPS = "not-a-number";
    expect(clientIpFrom(headersOf({ "x-forwarded-for": "1.2.3.4" }))).toBe("unknown");
  });
});
