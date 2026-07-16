import NextAuth from "next-auth";

import { authConfig } from "@/auth.config";
import { decideRequest } from "@/lib/middleware-gate";
import { clientIpFrom, signInEmailLimiter } from "@/lib/rate-limit";

// Runs on the Edge Runtime — must NOT touch Prisma or anything that
// imports Node-only deps. We instantiate NextAuth with the edge-safe
// authConfig only; it gives us `auth()` which verifies the JWT cookie
// using AUTH_SECRET and nothing else. The routing/CSP decision lives in
// @/lib/middleware-gate (edge-safe, unit-tested without the NextAuth wrapper).
const { auth } = NextAuth(authConfig);

export default auth((req) => {
  const { pathname } = req.nextUrl;

  // /api/auth/* stays public (it IS the sign-in machinery), but the
  // magic-link trigger is rate limited — the abuse case is spamming an
  // arbitrary inbox with verification emails. It returns JSON/redirects, not
  // seed-bearing HTML, so it needs no CSP.
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

  return decideRequest({
    pathname,
    search: req.nextUrl.search,
    origin: req.nextUrl.origin,
    isAuthed: Boolean(req.auth),
    requestHeaders: req.headers,
    isDev: process.env.NODE_ENV !== "production",
  });
});

// Site-wide matcher: the whole origin except Next's static assets and the
// favicon (the strict CSP is a precondition of the on-device root store, so it
// must cover every route that can run script, not just the two old seed pages).
// /api/auth/* still matches — it is handled (rate limit only) above.
export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
