import { PrismaAdapter } from "@auth/prisma-adapter";
import NextAuth from "next-auth";
import Passkey from "next-auth/providers/passkey";
import type { EmailConfig } from "next-auth/providers";

import { authConfig } from "@/auth.config";
import { prisma } from "@/lib/prisma";

// Dev-mode email "provider": print the magic link to the server log
// instead of sending a real email. Swap in a real transport (Resend, SES)
// in later stages.
const ConsoleEmail = (): EmailConfig => ({
  id: "email",
  type: "email",
  name: "Email",
  from: "noreply@tessera.local",
  maxAge: 60 * 60, // 1 hour magic-link TTL
  server: { host: "localhost", port: 0, auth: { user: "", pass: "" } },
  options: {},
  async sendVerificationRequest({ identifier, url }) {
    // Dev-only transport. NEVER log magic-link URLs in prod — they are
    // bearer tokens.
    console.log(
      `\n[tessera:auth] Magic link for ${identifier}\n  ${url}\n  (click within 1h)\n`,
    );
  },
});

// Full Auth.js config = edge-safe config + adapter + Node-only providers.
// Only the Node runtime (route handlers, server components) loads this
// file; middleware imports auth.config directly to keep the Edge bundle
// adapter-free.
export const { handlers, auth, signIn, signOut } = NextAuth({
  ...authConfig,
  adapter: PrismaAdapter(prisma),
  providers: [Passkey, ConsoleEmail()],
  experimental: { enableWebAuthn: true },
});
