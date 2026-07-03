import type { AdapterUser } from "next-auth/adapters";

import { prisma } from "@/lib/prisma";

// Shared user resolution for the two email sign-in credentials: the magic
// link (via the Auth.js PrismaAdapter override in src/auth.ts) and the OTP
// code (via the email-otp Credentials provider). Both must land the user in
// the SAME account and produce the SAME AdapterUser shape, or the two paths
// would drift (e.g. mint duplicate accounts, or lose sessionGeneration and
// break "sign out everywhere"). Keeping the logic here makes that literal.

// The User columns we project to an AdapterUser. `sessionGeneration` rides
// along because the jwt callback stamps `token.gen` from it; drop it and
// every login would stamp gen=0 and break revocation.
export const USER_SELECT = {
  id: true,
  name: true,
  email: true,
  emailVerified: true,
  image: true,
  sessionGeneration: true,
} as const;

export type UserRow = {
  id: string;
  name: string | null;
  email: string | null;
  emailVerified: Date | null;
  image: string | null;
  sessionGeneration: number;
};

// Project a Prisma User row to the AdapterUser shape Auth.js expects.
// AdapterUser requires a non-null `email`; `emailOverride` passes through the
// specific address the flow verified (which may differ from the primary
// cache), so the session carries the address the user actually signed in
// with. `sessionGeneration` is on the augmented next-auth User type.
export function toAdapterUser(
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

// Resolve an address through UserEmail (globally unique) to its owning user
// so a user's SECOND verified email signs them into their EXISTING account.
// Falls back to the denormalized User.email cache for accounts that predate
// the UserEmail table.
export async function getUserByEmailIdentity(
  email: string,
): Promise<(AdapterUser & { sessionGeneration: number }) | null> {
  const owned = await prisma.userEmail.findUnique({
    where: { email },
    select: { email: true, user: { select: USER_SELECT } },
  });
  if (owned) return toAdapterUser(owned.user, owned.email);

  const legacy = await prisma.user.findFirst({ where: { email }, select: USER_SELECT });
  return legacy ? toAdapterUser(legacy) : null;
}

// Create a brand-new account for a freshly verified email. Writes the User
// (email = primary cache) AND a verified primary UserEmail row in one
// transaction so identity and its email store are never out of sync. Runs
// only when no existing UserEmail matched.
export async function createEmailUser(
  email: string,
): Promise<AdapterUser & { sessionGeneration: number }> {
  const created = await prisma.$transaction(async (tx) => {
    const user = await tx.user.create({
      data: { email, emailVerified: new Date() },
      select: USER_SELECT,
    });
    await tx.userEmail.create({
      data: { userId: user.id, email, isPrimary: true, verifiedAt: new Date() },
    });
    return user;
  });
  return toAdapterUser(created, email);
}
