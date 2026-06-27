import type { NextAuthConfig } from "next-auth";
// Imported (type-only, intentionally unused) so the
// `declare module "next-auth/jwt"` augmentation below resolves its target
// module under Bundler resolution.
import type { JWT as _JWT } from "next-auth/jwt";

import { aalForCredential, type Aal } from "@/lib/assurance";

// AAL the provider that just authenticated confers. Passkey is AAL2
// (phishing-resistant); email magic link and recovery sign-in are AAL1.
// Any unknown/future provider is treated as AAL1 (single-factor) until it
// is explicitly classified — never silently AAL2. Recovery additionally
// flags the session `recovered` (handled in the jwt callback).
function aalForProvider(provider: string): Aal {
  switch (provider) {
    case "passkey":
      return aalForCredential("passkey");
    case "recovery":
      return aalForCredential("recovery-code");
    case "email":
    default:
      return aalForCredential("email");
  }
}

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
    // after 24h of inactivity. Minister is wallet-shaped: bursty use, not
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
    //
    // AAL: `account` is present only on an actual sign-in event (not on
    // every JWT refresh). On sign-in we derive the AAL the authenticating
    // provider confers. A step-up re-auth (an already-signed-in user
    // re-authenticating with a stronger provider) raises the AAL via
    // Math.max — it never drops. Reaching AAL2 via a real factor clears the
    // `recovered` flag (the user has re-established a phishing-resistant
    // credential, so the reduced-capability recovery session is over). The
    // "recovery" provider stamps recovered=true.
    jwt({ token, user, account }) {
      if (user) {
        token.id = user.id;
        token.gen = user.sessionGeneration ?? 0;
      }
      if (account) {
        const newAal = aalForProvider(account.provider);
        const existingAal = typeof token.aal === "number" ? (token.aal as Aal) : 0;
        token.aal = Math.max(existingAal, newAal) as Aal;
        if (account.provider === "recovery") {
          token.recovered = true;
        }
        if (token.aal >= 2) {
          // Climbed to AAL2 with a real factor — no longer a recovery session.
          delete token.recovered;
        }
      } else if (typeof token.aal !== "number") {
        // Defensive: a JWT minted before AAL existed (or any refresh that
        // somehow lacks it) is treated as AAL1, the floor for a session that
        // already verified — never AAL0, never silently AAL2.
        token.aal = 1;
      }
      return token;
    },
    // Reading a session — surface `id`, `sessionGeneration`, `aal`, and the
    // `recovered` flag so the Node-side getCurrentSession() helper and the
    // requireAal guard have what they need.
    session({ session, token }) {
      if (session.user && typeof token.id === "string") {
        session.user.id = token.id;
      }
      if (typeof token.gen === "number") {
        session.sessionGeneration = token.gen;
      }
      session.aal = typeof token.aal === "number" ? (token.aal as Aal) : 0;
      if (token.recovered === true) {
        session.recovered = true;
      }
      return session;
    },
  },
};

// Type augmentations. The session callback promises:
//   - `session.user.id` is a string after sign-in
//   - `session.sessionGeneration` is the gen snapshot from the JWT
//   - `session.aal` is the authentication assurance level the session was
//     obtained at (0|1|2); `session.recovered` flags a reduced-capability
//     session obtained via a recovery flow.
// User gets `sessionGeneration` so the jwt callback can read it from the
// adapter-loaded row without an unsafe cast. All are runtime-guarded
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
    aal?: Aal;
    recovered?: boolean;
  }

  interface User {
    sessionGeneration?: number;
  }
}

// The JWT carries the same AAL state between requests. Declared so the
// callbacks read token.aal / token.recovered without unsafe casts.
declare module "next-auth/jwt" {
  interface JWT {
    id?: string;
    gen?: number;
    aal?: Aal;
    recovered?: boolean;
  }
}
