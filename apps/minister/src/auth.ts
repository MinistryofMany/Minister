import { PrismaAdapter } from "@auth/prisma-adapter";
import { z } from "zod";
import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import Passkey from "next-auth/providers/passkey";
import type { EmailConfig } from "next-auth/providers";
import type { Adapter, AdapterUser } from "next-auth/adapters";

import { authConfig } from "@/auth.config";
import { audit } from "@/lib/audit";
import { createEmailUser, getUserByEmailIdentity, USER_SELECT } from "@/lib/email-signin-user";
import {
  emailButton,
  emailCode,
  emailFinePrint,
  emailLinkFallback,
  emailParagraph,
  emailText,
  renderEmail,
} from "@/lib/email-layout";
import { sendMail } from "@/lib/mailer";
import { prisma } from "@/lib/prisma";
import { clientIpFrom, signInOtpIdentityLimiter, signInOtpIpLimiter } from "@/lib/rate-limit";
import { verifyRecoveryTicket } from "@/lib/recovery-ticket";
import { createSignInOtp, verifySignInOtp } from "@/lib/signin-otp";
import { autoIssueEmailDomainBadge } from "@/server/auto-issue-email-domain";

// Email sign-in provider. Delivery goes through the app's single mailer
// (SMTP/Resend if configured, server-log in dev) so sign-in emails use the
// same transport as plugin and share-link emails.
//
// Every sign-in email carries BOTH a magic link and a short one-time code:
// the link for click-through on the same device, the code so a user reading
// email on their phone can type it to sign in on desktop. Either completes
// auth and yields the same session. The code is verified by the "email-otp"
// Credentials provider below.
const EmailProvider = (): EmailConfig => ({
  id: "email",
  type: "email",
  name: "Email",
  from: process.env.MAIL_FROM ?? "noreply@minister.local",
  maxAge: 60 * 60, // 1 hour magic-link TTL (the OTP TTL matches — see signin-otp.ts)
  server: { host: "localhost", port: 0, auth: { user: "", pass: "" } },
  options: {},
  async sendVerificationRequest({ identifier, url }) {
    const email = identifier.toLowerCase();
    // Mint the single-use code tied to this same identity. Stored hashed;
    // the plaintext exists only long enough to place it in the email body.
    // NEVER log the code.
    const code = await createSignInOtp(email);

    await sendMail({
      to: identifier,
      subject: "Sign in to Minister",
      text: [
        "Sign in to Minister one of two ways:",
        "",
        "1) Click this link on this device:",
        url,
        "",
        "2) Or enter this code where you started signing in:",
        `   ${code}`,
        "",
        "The link and code both expire in 1 hour and each can be used once.",
        "If you didn't request this, you can ignore this email.",
      ].join("\n"),
      html: renderEmail({
        title: "Sign in to Minister",
        heading: "Sign in to Minister",
        blocks: [
          emailText("Sign in one of two ways."),
          emailParagraph("<strong>1.</strong> Click the button to sign in on this device:"),
          emailButton("Sign in to Minister", url),
          emailLinkFallback(url),
          emailParagraph("<strong>2.</strong> Or enter this code where you started signing in:"),
          emailCode(code),
          emailFinePrint(
            "The link and code both expire in 1 hour and each can be used once. If you didn't request this, you can ignore this email.",
          ),
        ],
      }),
    });
  },
});

// UserEmail-aware adapter. Wraps the stock PrismaAdapter and overrides the
// two methods that must consult the UserEmail table so multi-email identity
// works. The resolution logic is shared with the email-otp provider (see
// @/lib/email-signin-user) so both email credentials land in the SAME
// account and never mint duplicates:
//
//   * getUserByEmail — resolve an address through UserEmail to its owning
//     user (a user's SECOND verified email signs into their EXISTING
//     account), falling back to the legacy User.email cache.
//
//   * createUser — runs only on a brand-new verified magic-link sign-in
//     (no existing UserEmail matched). Creates the User + a verified primary
//     UserEmail row in one transaction.
//
// We do NOT quarantine here: the first credential on a fresh account is the
// bootstrap. Quarantine on subsequently-added credentials is applied by the
// credential-management actions, not the adapter.
function ministerAdapter(): Adapter {
  const base = PrismaAdapter(prisma);
  return {
    ...base,
    getUserByEmail(email: string): Promise<AdapterUser | null> {
      return getUserByEmailIdentity(email);
    },
    async createUser(data: AdapterUser): Promise<AdapterUser> {
      // The email provider always supplies a verified address here; guard
      // anyway so we never write a UserEmail row with a null address.
      if (!data.email) {
        throw new Error("createUser requires an email (verified magic-link sign-in)");
      }
      return createEmailUser(data.email);
    },
  };
}

// Input to the email-otp provider. Both fields required; a parse failure is
// treated as an invalid attempt (uniform failure).
const OtpCredentials = z.object({
  email: z.string().email(),
  code: z.string().min(1).max(64),
});

// Email OTP sign-in provider. Verifies the short code from the sign-in email
// and produces the SAME session the magic-link callback does (AAL1, email
// factor). Failure modes all return null → one uniform "invalid code" error,
// so the form never reveals whether the code or the identity was wrong.
//
// Defense in depth against brute force (a short code is guessable):
//   * per-IP and per-identity sliding-window limits (rate-limit.ts)
//   * per-code lockout after N wrong guesses (signin-otp.ts)
//   * single-use consume on success
// Every attempt is audit-logged (no email, no code in the metadata).
const EmailOtpProvider = Credentials({
  id: "email-otp",
  name: "Email code",
  credentials: { email: {}, code: {} },
  async authorize(credentials, request): Promise<AdapterUser | null> {
    const parsed = OtpCredentials.safeParse(credentials);
    if (!parsed.success) {
      await audit(null, "auth.otp.failed", { reason: "malformed" });
      return null;
    }
    const email = parsed.data.email.toLowerCase();

    // Rate-limit before touching the code store. Per-IP bounds a single
    // client hammering many identities; per-identity bounds an address
    // attacked from rotating IPs.
    const ip = clientIpFrom(request.headers);
    if (!signInOtpIpLimiter.check(`otp:${ip}`).allowed) {
      await audit(null, "auth.otp.failed", { reason: "rate-limited-ip" });
      return null;
    }
    if (!signInOtpIdentityLimiter.check(`otp:${email}`).allowed) {
      await audit(null, "auth.otp.failed", { reason: "rate-limited-identity" });
      return null;
    }

    const result = await verifySignInOtp(email, parsed.data.code);
    if (!result.ok) {
      await audit(null, "auth.otp.failed", { reason: result.reason });
      return null;
    }

    // Code verified ⇒ the inbox is proven. Resolve to the owning account via
    // getUserByEmailIdentity, which matches ONLY verified emails — so an
    // unverified foreign pre-claim on this address never resolves here, and
    // proving control creates/reclaims a fresh account for the prover exactly
    // as the magic-link adapter path does.
    const existing = await getUserByEmailIdentity(email);
    const user = existing ?? (await createEmailUser(email));
    if (existing && existing.emailVerified === null) {
      // Backfill verification on the RESOLVED OWNER only. Both writes are
      // scoped to existing.id, so a proven inbox can only ever mark this
      // account's own claim verified — never a different account's claim.
      await prisma.user.update({
        where: { id: existing.id },
        data: { emailVerified: new Date() },
      });
      await prisma.userEmail.updateMany({
        where: { userId: existing.id, email, verifiedAt: null },
        data: { verifiedAt: new Date() },
      });
    }

    await audit(user.id, "auth.otp.success", {});
    return user;
  },
});

// Recovery sign-in provider. Authorizes a single-use, short-TTL, server-minted
// ticket (issued after a recovery-code redemption or a cleared badge
// threshold) and resolves it to the owning user. The jwt callback stamps the
// resulting session aal=1 + recovered=true.
const RecoveryProvider = Credentials({
  id: "recovery",
  name: "Recovery",
  credentials: { ticket: { label: "Recovery ticket", type: "text" } },
  async authorize(credentials): Promise<AdapterUser | null> {
    const ticket = credentials?.ticket;
    if (typeof ticket !== "string" || ticket.length === 0) return null;
    const verified = await verifyRecoveryTicket(ticket);
    if (!verified) return null;
    const user = await prisma.user.findUnique({
      where: { id: verified.userId },
      select: { ...USER_SELECT, isBanned: true, mergedIntoUserId: true },
    });
    if (!user) return null;
    // Recovery must not resurrect a banned or already-merged (tombstoned)
    // account.
    if (user.isBanned || user.mergedIntoUserId !== null) return null;
    return {
      id: user.id,
      name: user.name,
      email: user.email ?? "",
      emailVerified: user.emailVerified,
      image: user.image,
      sessionGeneration: user.sessionGeneration,
    };
  },
});

// Full Auth.js config = edge-safe config + adapter + Node-only providers.
// Only the Node runtime (route handlers, server components) loads this file;
// middleware imports auth.config directly to keep the Edge bundle adapter-free.
export const { handlers, auth, signIn, signOut } = NextAuth({
  ...authConfig,
  adapter: ministerAdapter(),
  providers: [Passkey, EmailProvider(), EmailOtpProvider, RecoveryProvider],
  experimental: { enableWebAuthn: true },
  events: {
    // Auto-issue the email-domain badge after a successful email sign-in
    // (magic link or OTP). Only the email credentials qualify — passkey and
    // recovery sign-ins carry no freshly-verified email. Fail-open: a badge
    // failure must never break the login, so we swallow-and-audit inside the
    // helper and guard again here.
    async signIn({ user, account }) {
      if (!account) return;
      if (account.provider !== "email" && account.provider !== "email-otp") return;
      const email = typeof user.email === "string" ? user.email : null;
      if (!user.id || !email) return;
      // Don't mint a badge for a banned or tombstoned (merged-away) account,
      // matching the recovery provider's refusal to resurrect one.
      const state = await prisma.user.findUnique({
        where: { id: user.id },
        select: { isBanned: true, mergedIntoUserId: true },
      });
      if (!state || state.isBanned || state.mergedIntoUserId !== null) return;
      try {
        await autoIssueEmailDomainBadge(user.id, email);
      } catch {
        // Already audited in the helper; never surface as a failed sign-in.
      }
    },
  },
});
