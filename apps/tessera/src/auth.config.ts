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
  session: { strategy: "jwt" },
  callbacks: {
    // First sign-in: stash the User id on the JWT so future requests
    // don't need an adapter call to recover it.
    jwt({ token, user }) {
      if (user) token.id = user.id;
      return token;
    },
    // Reading a session — propagate the id from the token onto
    // session.user so callers see `session.user.id` exactly like they
    // did under DB strategy.
    session({ session, token }) {
      if (session.user && typeof token.id === "string") {
        session.user.id = token.id;
      }
      return session;
    },
  },
};

// Type augmentation. The session callback above promises `session.user.id`
// is a string after sign-in. We don't augment the JWT module — the
// runtime guard (`typeof token.id === "string"`) in the callback is the
// boundary check; the rest of the codebase only ever sees `session.user`.
declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      name?: string | null;
      email?: string | null;
      image?: string | null;
    };
  }
}
