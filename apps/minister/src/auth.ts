import { PrismaAdapter } from "@auth/prisma-adapter";
import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import Passkey from "next-auth/providers/passkey";
import type { EmailConfig } from "next-auth/providers";
import type { Adapter, AdapterUser } from "next-auth/adapters";

import { authConfig } from "@/auth.config";
import { sendMail } from "@/lib/mailer";
import { prisma } from "@/lib/prisma";
import { verifyRecoveryTicket } from "@/lib/recovery-ticket";

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

// The User row shape we read when projecting to an AdapterUser. The base
// columns Auth.js needs, plus `sessionGeneration` — the jwt callback reads
// it off the returned user to stamp `token.gen`, which "sign out
// everywhere" depends on. The stock PrismaAdapter returns the whole row
// (no select), so it had this for free; our projected overrides must carry
// it explicitly or every login would stamp gen=0 and break revocation.
type UserRow = {
  id: string;
  name: string | null;
  email: string | null;
  emailVerified: Date | null;
  image: string | null;
  sessionGeneration: number;
};

// Project a Prisma User row to the AdapterUser shape Auth.js expects.
// AdapterUser requires a non-null `email`; when the lookup was by a
// specific UserEmail row, we pass that address through (`emailOverride`) so
// the user the email flow signs in carries the address it verified, not the
// possibly-different primary cache. `sessionGeneration` rides along (it's on
// the augmented next-auth User type) so the jwt callback can stamp token.gen.
function toAdapterUser(
  user: UserRow,
  emailOverride?: string,
): AdapterUser & { sessionGeneration: number } {
  return {
    id: user.id,
    name: user.name,
    email: emailOverride ?? user.email ?? "",
    emailVerified: user.emailVerified,
    image: user.image,
    sessionGeneration: user.sessionGeneration,
  };
}

const USER_SELECT = {
  id: true,
  name: true,
  email: true,
  emailVerified: true,
  image: true,
  sessionGeneration: true,
} as const;

// UserEmail-aware adapter. Wraps the stock PrismaAdapter and overrides the
// two methods that must consult the UserEmail table so multi-email identity
// works:
//
//   * getUserByEmail — resolve an address through UserEmail to its owning
//     user, so a user's SECOND verified email signs them into their
//     EXISTING account instead of minting a new one. UserEmail.email is
//     globally unique; if there's no UserEmail row we fall back to the
//     legacy User.email cache (covers accounts created before this table
//     and the bootstrap window between createUser's two writes).
//
//   * createUser — runs only on a brand-new verified magic-link sign-in
//     (no existing UserEmail matched). Create the User (email = primary
//     cache) AND a verified primary UserEmail row in one transaction, so
//     identity and its email store are never out of sync.
//
// We do NOT quarantine here: the first credential on a fresh account is the
// bootstrap. Quarantine on subsequently-added credentials is applied by the
// credential-management actions (slice 2), not the adapter.
function ministerAdapter(): Adapter {
  const base = PrismaAdapter(prisma);
  return {
    ...base,
    async getUserByEmail(email: string): Promise<AdapterUser | null> {
      const owned = await prisma.userEmail.findUnique({
        where: { email },
        select: { email: true, user: { select: USER_SELECT } },
      });
      if (owned) return toAdapterUser(owned.user, owned.email);
      // Fall back to the denormalized primary cache for accounts predating
      // the UserEmail table.
      const legacy = await prisma.user.findFirst({
        where: { email },
        select: USER_SELECT,
      });
      return legacy ? toAdapterUser(legacy) : null;
    },
    async createUser(data: AdapterUser): Promise<AdapterUser> {
      const email = data.email;
      // The email provider always supplies a verified address here; guard
      // anyway so we never write a UserEmail row with a null address.
      if (!email) {
        throw new Error("createUser requires an email (verified magic-link sign-in)");
      }
      const created = await prisma.$transaction(async (tx) => {
        const user = await tx.user.create({
          data: {
            name: data.name ?? undefined,
            email,
            emailVerified: data.emailVerified ?? new Date(),
            image: data.image ?? undefined,
          },
          select: USER_SELECT,
        });
        await tx.userEmail.create({
          data: {
            userId: user.id,
            email,
            isPrimary: true,
            // This path only runs for a verified magic-link sign-in.
            verifiedAt: new Date(),
          },
        });
        return user;
      });
      return toAdapterUser(created, email);
    },
  };
}

// Recovery sign-in provider. Authorizes a single-use, short-TTL,
// server-minted ticket (issued by slices 3/4 after a recovery code redemption
// or a cleared badge threshold) and resolves it to the owning user. The jwt
// callback stamps the resulting session aal=1 + recovered=true. No UI: slices
// 3/4 call issueRecoveryTicket(userId) then
// signIn("recovery", { ticket, redirect: false }).
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
    return toAdapterUser(user);
  },
});

// Full Auth.js config = edge-safe config + adapter + Node-only providers.
// Only the Node runtime (route handlers, server components) loads this
// file; middleware imports auth.config directly to keep the Edge bundle
// adapter-free.
export const { handlers, auth, signIn, signOut } = NextAuth({
  ...authConfig,
  adapter: ministerAdapter(),
  providers: [Passkey, EmailProvider(), RecoveryProvider],
  experimental: { enableWebAuthn: true },
});
