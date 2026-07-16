import { NextResponse } from "next/server";

import { buildRequestCsp, cspPassThrough } from "@/lib/anon-key-csp";

// The middleware's pure decision, factored out of middleware.ts so it is
// unit-testable WITHOUT importing the NextAuth wrapper (next-auth mis-resolves
// `next/server` under vitest). No next-auth import lives here — only next/server
// and the CSP helpers, both edge-safe.

// Routes the middleware AUTH-gates (a logged-in user is required to view them).
// The matcher covers the whole origin (so the strict CSP is site-wide), so the
// gate can no longer be expressed as the matcher — it lives here. /, /u/[userId],
// /.well-known/*, and everything else stay public but still receive the CSP.
// /oidc/authorize requires auth (a user must be present to consent);
// /oidc/token and /oidc/userinfo authenticate via client_secret / bearer token
// themselves, so they are NOT gated.
export function isProtectedPath(pathname: string): boolean {
  const prefixes = ["/profile", "/settings", "/badges", "/shares", "/admin"];
  if (prefixes.some((p) => pathname === p || pathname.startsWith(`${p}/`))) return true;
  return pathname === "/oidc/authorize";
}

/**
 * CRITICAL (C3): the CSP is MERGED into the auth branch — an unauthenticated
 * protected route still returns the redirect (carrying the CSP header), never a
 * CSP pass-through BEFORE the gate. A pass-through-first would have turned every
 * gated route public the moment the matcher widened to the origin. Every path
 * returns a response carrying the strict CSP.
 */
export function decideRequest(input: {
  pathname: string;
  search: string;
  origin: string;
  isAuthed: boolean;
  requestHeaders: Headers;
  isDev: boolean;
}): NextResponse {
  const { pathname, search, origin, isAuthed, requestHeaders, isDev } = input;
  const requestCsp = buildRequestCsp(isDev);

  if (isProtectedPath(pathname) && !isAuthed) {
    const url = new URL("/", origin);
    // Preserve full path INCLUDING query string. This matters for
    // /oidc/authorize?client_id=...&state=... — losing the query would
    // orphan the OIDC request mid-flow.
    url.searchParams.set("from", pathname + search);
    const res = NextResponse.redirect(url, 302);
    res.headers.set(requestCsp.headerName, requestCsp.csp);
    return res;
  }

  return cspPassThrough(requestHeaders, requestCsp);
}
