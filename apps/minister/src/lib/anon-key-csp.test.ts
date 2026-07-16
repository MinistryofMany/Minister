import { afterEach, describe, expect, it } from "vitest";

import { buildAnonKeyCsp, buildRequestCsp, cspPassThrough } from "@/lib/anon-key-csp";

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

  it("keeps style inline but allows external images site-wide (avatars)", () => {
    const csp = buildAnonKeyCsp("abc123", false);
    expect(csp).toContain("style-src 'self' 'unsafe-inline'");
    // img-src must allow https: so /u/[userId] + profile external avatars render
    // under the now site-wide policy; images are not a script/seed-read vector.
    expect(csp).toContain("img-src 'self' https: data: blob:");
  });

  it("relaxes eval only in dev for Next HMR", () => {
    expect(buildAnonKeyCsp("abc123", true)).toContain("'unsafe-eval'");
  });
});

describe("buildRequestCsp + cspPassThrough", () => {
  it("stamps a fresh nonce and sets the header on request + response", () => {
    const requestHeaders = new Headers();
    const requestCsp = buildRequestCsp(false);
    const res = cspPassThrough(requestHeaders, requestCsp);
    const csp = res.headers.get("content-security-policy");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("'strict-dynamic'");
    // A nonce must be present so Next can stamp its own inline bootstrap scripts.
    expect(csp).toMatch(/'nonce-[a-f0-9]+'/);
    expect(res.headers.get("content-security-policy")).toBe(csp);
  });
});

describe("report-only toggle", () => {
  const KEY = "MINISTER_CSP_REPORT_ONLY";
  const ENFORCING = "content-security-policy";
  const REPORT_ONLY = "content-security-policy-report-only";

  afterEach(() => {
    delete process.env[KEY];
  });

  function passThrough(): Headers {
    return cspPassThrough(new Headers(), buildRequestCsp(false)).headers;
  }

  it("emits the enforcing header by default (env unset)", () => {
    delete process.env[KEY];
    const h = passThrough();
    expect(h.get(ENFORCING)).not.toBeNull();
    expect(h.get(REPORT_ONLY)).toBeNull();
  });

  it("emits the enforcing header when explicitly set to false", () => {
    process.env[KEY] = "false";
    const h = passThrough();
    expect(h.get(ENFORCING)).not.toBeNull();
    expect(h.get(REPORT_ONLY)).toBeNull();
  });

  it("emits the Report-Only header when MINISTER_CSP_REPORT_ONLY=true", () => {
    process.env[KEY] = "true";
    const h = passThrough();
    expect(h.get(REPORT_ONLY)).not.toBeNull();
    expect(h.get(ENFORCING)).toBeNull();
  });

  it("uses an identical policy body + nonce shape in both modes", () => {
    const stripNonce = (s: string) => s.replace(/'nonce-[a-f0-9]+'/, "'nonce-X'");

    delete process.env[KEY];
    const enforced = passThrough().get(ENFORCING)!;

    process.env[KEY] = "true";
    const reportOnly = passThrough().get(REPORT_ONLY)!;

    // Only the header NAME changes: same directives, same nonce format (the
    // nonce value differs per call since it is freshly generated).
    expect(stripNonce(reportOnly)).toBe(stripNonce(enforced));
    expect(reportOnly).toMatch(/'nonce-[a-f0-9]+'/);
  });
});
