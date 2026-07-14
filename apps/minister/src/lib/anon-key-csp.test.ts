import { describe, expect, it } from "vitest";

import { anonKeyCspResponse, buildAnonKeyCsp, isStrictCspPath } from "@/lib/anon-key-csp";

describe("isStrictCspPath", () => {
  it("matches the anon-key route and its subpaths", () => {
    expect(isStrictCspPath("/settings/private-identity")).toBe(true);
    expect(isStrictCspPath("/settings/private-identity/recover")).toBe(true);
  });

  it("matches the OIDC authorize consent route", () => {
    expect(isStrictCspPath("/oidc/authorize")).toBe(true);
  });

  it("does not match sibling settings routes or prefix look-alikes", () => {
    expect(isStrictCspPath("/settings")).toBe(false);
    expect(isStrictCspPath("/settings/profile")).toBe(false);
    expect(isStrictCspPath("/settings/private-identities")).toBe(false);
    expect(isStrictCspPath("/oidc/token")).toBe(false);
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

  it("sets the CSP header + nonce on /oidc/authorize and forwards it to Next", () => {
    const requestHeaders = new Headers();
    const res = anonKeyCspResponse("/oidc/authorize", requestHeaders, false);
    expect(res).not.toBeNull();
    // Nonce must ride the outgoing response header so the consent page is locked.
    const csp = res!.headers.get("content-security-policy");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("'strict-dynamic'");
    expect(csp).toMatch(/'nonce-[a-f0-9]+'/);
    // style-src must keep 'unsafe-inline' — the consent form and Next/Tailwind
    // inline critical CSS would white-screen otherwise.
    expect(csp).toContain("style-src 'self' 'unsafe-inline'");
  });

  it("returns null (no header) for out-of-scope routes", () => {
    expect(anonKeyCspResponse("/settings/profile", new Headers(), false)).toBeNull();
    expect(anonKeyCspResponse("/oidc/token", new Headers(), false)).toBeNull();
  });
});
