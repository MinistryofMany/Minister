import { afterEach, describe, expect, it } from "vitest";

import { decideRequest } from "./middleware-gate";

const ORIGIN = "https://ministry.id";
const base = { origin: ORIGIN, requestHeaders: new Headers(), isDev: false };

afterEach(() => {
  delete process.env.MINISTER_CSP_REPORT_ONLY;
});

describe("middleware decideRequest (C3: CSP merged into the auth branch)", () => {
  it("unauthenticated /admin STILL redirects after the site-wide widening", () => {
    const res = decideRequest({ ...base, pathname: "/admin", search: "", isAuthed: false });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`${ORIGIN}/?from=%2Fadmin`);
    // The redirect still carries the strict CSP (merged, never dropped).
    expect(res.headers.get("content-security-policy")).toContain("script-src");
  });

  it("unauthenticated nested /settings/security redirects, preserving the query", () => {
    const res = decideRequest({
      ...base,
      pathname: "/settings/security",
      search: "?tab=x",
      isAuthed: false,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`${ORIGIN}/?from=%2Fsettings%2Fsecurity%3Ftab%3Dx`);
  });

  it("unauthenticated /oidc/authorize redirects (consent needs a user)", () => {
    const res = decideRequest({
      ...base,
      pathname: "/oidc/authorize",
      search: "?client_id=abc",
      isAuthed: false,
    });
    expect(res.status).toBe(302);
  });

  it("authenticated /admin passes through with the CSP (no redirect)", () => {
    const res = decideRequest({ ...base, pathname: "/admin", search: "", isAuthed: true });
    expect(res.status).not.toBe(302);
    expect(res.headers.get("content-security-policy")).toContain("'strict-dynamic'");
  });

  it("a public route (/u/[id]) is not gated but still gets the site-wide CSP", () => {
    const res = decideRequest({ ...base, pathname: "/u/abc", search: "", isAuthed: false });
    expect(res.status).not.toBe(302);
    expect(res.headers.get("content-security-policy")).toContain("default-src 'self'");
  });

  it("report-only mode changes only the header name", () => {
    process.env.MINISTER_CSP_REPORT_ONLY = "true";
    const res = decideRequest({ ...base, pathname: "/", search: "", isAuthed: false });
    expect(res.headers.get("content-security-policy-report-only")).toContain("script-src");
    expect(res.headers.get("content-security-policy")).toBeNull();
  });
});
