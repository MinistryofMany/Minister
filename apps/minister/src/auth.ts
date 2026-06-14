import { PrismaAdapter } from "@auth/prisma-adapter";
import NextAuth from "next-auth";
import Passkey from "next-auth/providers/passkey";
import type { EmailConfig } from "next-auth/providers";

import { authConfig } from "@/auth.config";
import { sendMail } from "@/lib/mailer";
import { prisma } from "@/lib/prisma";

// Email sign-in provider. Delivery goes through the app's single
// mailer (Resend if configured, server-log in dev) so sign-in magic
// links use the same transport as plugin and share-link emails.
const EmailProvider = (): EmailConfig => ({
  id: "email",
  type: "email",
  name: "Email",
  from: process.env.MAIL_FROM ?? "noreply@minister.local",
  maxAge: 60 * 60, // 1 hour magic-link TTL
  server: { host: "localhost", port: 0, auth: { user: "", pass: "" } },
  options: {},
  async sendVerificationRequest({ identifier, url }) {
    await sendMail({
      to: identifier,
      subject: "Sign in to Minister",
      text: [
        "Click the link below to sign in to Minister:",
        "",
        url,
        "",
        "If you didn't request this, you can ignore this email. The link expires in 1 hour.",
      ].join("\n"),
      html: [
        `<p>Click the link below to sign in to Minister:</p>`,
        `<p><a href="${url}">Sign in to Minister</a></p>`,
        `<p style="color:#6b7280;font-size:12px">If you didn't request this, you can ignore this email. The link expires in 1 hour.</p>`,
      ].join(""),
    });
  },
});

// Full Auth.js config = edge-safe config + adapter + Node-only providers.
// Only the Node runtime (route handlers, server components) loads this
// file; middleware imports auth.config directly to keep the Edge bundle
// adapter-free.
export const { handlers, auth, signIn, signOut } = NextAuth({
  ...authConfig,
  adapter: PrismaAdapter(prisma),
  providers: [Passkey, EmailProvider()],
  experimental: { enableWebAuthn: true },
});
