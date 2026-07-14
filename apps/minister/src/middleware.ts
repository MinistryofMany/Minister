import NextAuth from "next-auth";

import { anonKeyCspResponse } from "@/lib/anon-key-csp";
import { authConfig } from "@/auth.config";
import { clientIpFrom, signInEmailLimiter } from "@/lib/rate-limit";

// Runs on the Edge Runtime — must NOT touch Prisma or anything that
// imports Node-only deps. We instantiate NextAuth with the edge-safe
// authConfig only; it gives us `auth()` which verifies the JWT cookie
// using AUTH_SECRET and nothing else.
const { auth } = NextAuth(authConfig);

export default auth((req) => {
  const { pathname } = req.nextUrl;

  // /api/auth/* stays public (it IS the sign-in machinery), but the
  // magic-link trigger is rate limited — the abuse case is spamming an
  // arbitrary inbox with verification emails.
  if (pathname.startsWith("/api/auth/")) {
    if (req.method === "POST" && pathname.startsWith("/api/auth/signin")) {
      const verdict = signInEmailLimiter.check(clientIpFrom(req.headers));
      if (!verdict.allowed) {
        return Response.json(
          { error: "too_many_requests" },
          {
            status: 429,
            headers: { "Retry-After": String(verdict.retryAfterSeconds) },
          },
        );
      }
    }
    return;
  }

  if (!req.auth) {
    const url = new URL("/", req.nextUrl);
    // Preserve full path INCLUDING query string. This matters for
    // /oidc/authorize?client_id=...&state=... — losing the query
    // would orphan the OIDC request mid-flow.
    url.searchParams.set("from", req.nextUrl.pathname + req.nextUrl.search);
    return Response.redirect(url);
  }

  // Strict CSP for the anon-key dogfood route only (user is authed by here).
  // Blocks inline/third-party script — the at-use XSS that would read the
  // client-side seed this page holds in memory. Nonce-based so Next 15 still
  // hydrates. Scoped here, NOT globally and NOT on /oidc/authorize.
  const csp = anonKeyCspResponse(pathname, req.headers, process.env.NODE_ENV !== "production");
  if (csp) return csp;
});

// Routes the middleware gates. /, /u/[userId], /.well-known/* and
// Next.js internals stay public — anything not listed here is
// reachable without auth by default. /oidc/authorize requires auth
// (we need a logged-in user to consent); /oidc/token and
// /oidc/userinfo authenticate via client_secret / bearer token
// themselves, so they're NOT in the matcher. /api/auth/* is matched
// only for rate limiting — the handler above never auth-gates it.
export const config = {
  matcher: [
    "/profile/:path*",
    "/settings/:path*",
    "/badges/:path*",
    "/shares/:path*",
    "/admin/:path*",
    "/oidc/authorize",
    "/api/auth/:path*",
  ],
};
