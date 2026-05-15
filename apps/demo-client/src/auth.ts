import NextAuth from "next-auth";

// Stage 4 — demo client signs in via Tessera using a generic Auth.js
// OIDC provider. Tessera publishes /.well-known/openid-configuration,
// so we hand Auth.js the issuer URL and it discovers the rest.
//
// We use JWT-strategy sessions on the RP side too (no DB on the demo
// client) and copy the relevant claims from the Tessera ID token onto
// our session: pairwise sub, name/picture, tessera_badges (the array
// of VC JWTs Tessera issued for the badges this user consented to
// disclose).
export const { handlers, auth, signIn, signOut } = NextAuth({
  session: { strategy: "jwt", maxAge: 60 * 60 }, // 1h — shorter than Tessera's 24h
  providers: [
    {
      id: "tessera",
      name: "Tessera",
      type: "oidc",
      issuer: process.env.TESSERA_ISSUER_URL ?? "http://localhost:3000",
      clientId: process.env.TESSERA_CLIENT_ID ?? "",
      clientSecret: process.env.TESSERA_CLIENT_SECRET ?? "",
      // Scopes we want to request. The user picks per-badge inside the
      // Tessera consent screen; we ask broadly here and accept whatever
      // they approve.
      authorization: {
        params: {
          scope: "openid profile badge:email-domain",
        },
      },
      // The discovery doc says subject_types: ["pairwise"] but Auth.js
      // doesn't care — it just verifies the id_token signature via
      // /jwks.json and reads the claims.
      checks: ["pkce", "state", "nonce"],
    },
  ],
  callbacks: {
    // The OIDC provider hands us id_token; we squirrel away pieces we
    // care about so server components don't have to keep re-decoding.
    async jwt({ token, account, profile }) {
      if (account?.id_token) {
        token.idToken = account.id_token;
        token.accessToken = account.access_token;
      }
      if (profile) {
        const p = profile as {
          sub?: unknown;
          name?: unknown;
          picture?: unknown;
          tessera_badges?: unknown;
        };
        if (typeof p.sub === "string") token.tesseraSub = p.sub;
        if (typeof p.name === "string") token.tesseraName = p.name;
        if (typeof p.picture === "string") token.tesseraPicture = p.picture;
        if (Array.isArray(p.tessera_badges)) {
          token.tesseraBadges = p.tessera_badges.filter(
            (x): x is string => typeof x === "string",
          );
        }
      }
      return token;
    },
    async session({ session, token }) {
      session.tesseraSub = (token.tesseraSub as string | undefined) ?? null;
      session.tesseraName = (token.tesseraName as string | undefined) ?? null;
      session.tesseraPicture = (token.tesseraPicture as string | undefined) ?? null;
      session.tesseraBadges = (token.tesseraBadges as string[] | undefined) ?? [];
      session.idToken = (token.idToken as string | undefined) ?? null;
      session.accessToken = (token.accessToken as string | undefined) ?? null;
      return session;
    },
  },
});

declare module "next-auth" {
  interface Session {
    tesseraSub: string | null;
    tesseraName: string | null;
    tesseraPicture: string | null;
    tesseraBadges: string[];
    idToken: string | null;
    accessToken: string | null;
  }
}
