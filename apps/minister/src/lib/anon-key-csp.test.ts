import { describe, expect, it } from "vitest";

import { anonKeyCspResponse, buildAnonKeyCsp, isAnonKeyPath } from "@/lib/anon-key-csp";

describe("isAnonKeyPath", () => {
  it("matches the anon-key route and its subpaths", () => {
    expect(isAnonKeyPath("/settings/private-identity")).toBe(true);
    expect(isAnonKeyPath("/settings/private-identity/recover")).toBe(true);
  });

  it("does not match sibling settings routes or prefix look-alikes", () => {
    expect(isAnonKeyPath("/settings")).toBe(false);
    expect(isAnonKeyPath("/settings/profile")).toBe(false);
    expect(isAnonKeyPath("/settings/private-identities")).toBe(false);
  });
});

describe("buildAnonKeyCsp", () => {
  it("locks script to nonce + strict-dynamic and forbids objects/framing in prod", () => {
    const csp = buildAnonKeyCsp("abc123", false);
    expect(csp).toContain("script-src 'self' 'nonce-abc123' 'strict-dynamic'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    // No eval in the shipped policy — that is the XSS execution vector.
    expect(csp).not.toContain("unsafe-eval");
  });

  it("relaxes eval only in dev for Next HMR", () => {
    expect(buildAnonKeyCsp("abc123", true)).toContain("'unsafe-eval'");
  });
});

describe("anonKeyCspResponse", () => {
  it("sets the CSP header on the anon-key route with a nonce", () => {
    const res = anonKeyCspResponse("/settings/private-identity", new Headers(), false);
    expect(res).not.toBeNull();
    const csp = res!.headers.get("content-security-policy");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("'strict-dynamic'");
    // A nonce must be present so Next can stamp its own inline bootstrap scripts.
    expect(csp).toMatch(/'nonce-[a-f0-9]+'/);
  });

  it("returns null (no header) for out-of-scope routes", () => {
    expect(anonKeyCspResponse("/settings/profile", new Headers(), false)).toBeNull();
  });
});
