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
    // Preserve the path the user was after so we can bounce them back
    // after sign-in. Stage 0/1 ignores this; wire it in when we add a
    // proper sign-in redirect.
    url.searchParams.set("from", req.nextUrl.pathname);
    return Response.redirect(url);
  }
});

// Routes the middleware gates. /, /u/[userId], /.well-known/*,
// /api/auth/* and Next.js internals stay public — anything not listed
// here is reachable without auth by default.
export const config = {
  matcher: [
    "/profile/:path*",
    "/settings/:path*",
    "/badges/:path*",
  ],
};
