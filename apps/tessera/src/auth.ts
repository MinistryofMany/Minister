import { PrismaAdapter } from "@auth/prisma-adapter";
import NextAuth, { type NextAuthConfig } from "next-auth";
import Passkey from "next-auth/providers/passkey";
import type { EmailConfig } from "next-auth/providers";

import { prisma } from "@/lib/prisma";

// Dev-mode email "provider": print the magic link to the server log
// instead of sending a real email. The user picked this over Mailhog for
// Stage 0. Swap in a real transport (Resend, SES, etc.) in later stages.
const ConsoleEmail = (): EmailConfig => ({
  id: "email",
  type: "email",
  name: "Email",
  from: "noreply@tessera.local",
  maxAge: 60 * 60, // 1 hour magic-link TTL
  // Required by EmailConfig but unused for our console transport.
  server: { host: "localhost", port: 0, auth: { user: "", pass: "" } },
  options: {},
  async sendVerificationRequest({ identifier, url }) {
    // Stage 0 dev-only transport. Do NOT log the URL in prod; it is a
    // bearer token.
    console.log(
      `\n[tessera:auth] Magic link for ${identifier}\n  ${url}\n  (click within 1h)\n`,
    );
  },
});

export const authConfig: NextAuthConfig = {
  adapter: PrismaAdapter(prisma),
  providers: [Passkey, ConsoleEmail()],
  experimental: { enableWebAuthn: true },
  session: { strategy: "database" },
  pages: {
    signIn: "/",
  },
};

export const { handlers, auth, signIn, signOut } = NextAuth(authConfig);
