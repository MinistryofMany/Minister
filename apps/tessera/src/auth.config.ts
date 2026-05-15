import type { NextAuthConfig } from "next-auth";

// Edge-safe Auth.js config. NO adapter (Prisma can't run on the Edge
// Runtime, which is where middleware lives), NO providers that pull in
// Node-only deps (`@simplewebauthn/server`, `jose`, etc.). Anything more
// substantial goes in src/auth.ts, which is only loaded from the Node
// runtime (route handlers + server components).
//
// Middleware imports this file, instantiates NextAuth with it, and uses
// the resulting `auth` export to verify the session JWT cookie. JWT
// verification is pure crypto on AUTH_SECRET — no DB hit, no provider
// code — which is exactly what makes middleware-level route protection
// work.
export const authConfig: NextAuthConfig = {
  providers: [],
  pages: { signIn: "/" },
  session: {
    strategy: "jwt",
    // Sliding 24h window. The JWT is re-issued at most once per hour
    // (updateAge) and each re-issue resets the 24h clock — so an active
    // user stays signed in indefinitely, an idle one is logged out
    // after 24h of inactivity. Tessera is wallet-shaped: bursty use, not
    // daily, so 24h hits the right point on the security/UX curve.
    maxAge: 24 * 60 * 60,
    updateAge: 60 * 60,
  },
  callbacks: {
    // First sign-in: stash the User id AND the user's current
    // sessionGeneration on the JWT. The adapter has already loaded the
    // User row at this point, so `user.sessionGeneration` is in hand —
    // no extra DB query needed (which matters: this callback is in the
    // edge-safe config, and we can't reach Prisma here).
    jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        token.gen = user.sessionGeneration ?? 0;
      }
      return token;
    },
    // Reading a session — surface both `id` and `sessionGeneration` so
    // the Node-side getCurrentSession() helper has what it needs to do
    // the DB-backed staleness check.
    session({ session, token }) {
      if (session.user && typeof token.id === "string") {
        session.user.id = token.id;
      }
      if (typeof token.gen === "number") {
        session.sessionGeneration = token.gen;
      }
      return session;
    },
  },
};

// Type augmentations. The session callback promises:
//   - `session.user.id` is a string after sign-in
//   - `session.sessionGeneration` is the gen snapshot from the JWT
// User gets `sessionGeneration` so the jwt callback can read it from the
// adapter-loaded row without an unsafe cast. Both are runtime-guarded
// in the callback; the rest of the codebase only ever sees `session`.
declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      name?: string | null;
      email?: string | null;
      image?: string | null;
    };
    sessionGeneration?: number;
  }

  interface User {
    sessionGeneration?: number;
  }
}
