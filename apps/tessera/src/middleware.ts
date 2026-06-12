import NextAuth from "next-auth";

import { authConfig } from "@/auth.config";

// Runs on the Edge Runtime — must NOT touch Prisma or anything that
// imports Node-only deps. We instantiate NextAuth with the edge-safe
// authConfig only; it gives us `auth()` which verifies the JWT cookie
// using AUTH_SECRET and nothing else.
const { auth } = NextAuth(authConfig);

export default auth((req) => {
  if (!req.auth) {
    const url = new URL("/", req.nextUrl);
    // Preserve full path INCLUDING query string. This matters for
    // /oidc/authorize?client_id=...&state=... — losing the query
    // would orphan the OIDC request mid-flow.
    url.searchParams.set(
      "from",
      req.nextUrl.pathname + req.nextUrl.search,
    );
    return Response.redirect(url);
  }
});

// Routes the middleware gates. /, /u/[userId], /.well-known/*,
// /api/auth/* and Next.js internals stay public — anything not listed
// here is reachable without auth by default. /oidc/authorize requires
// auth (we need a logged-in user to consent); /oidc/token and
// /oidc/userinfo authenticate via client_secret / bearer token
// themselves, so they're NOT in the matcher.
export const config = {
  matcher: [
    "/profile/:path*",
    "/settings/:path*",
    "/badges/:path*",
    "/shares/:path*",
    "/admin/:path*",
    "/oidc/authorize",
  ],
};
