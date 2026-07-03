import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// H1 regression: account pre-hijacking via unverified UserEmail rows.
//
// An in-memory stand-in for the User + UserEmail tables. Sign-in identity
// resolution (magic link AND OTP) must resolve ONLY through a VERIFIED
// UserEmail row; an unverified foreign PRE-CLAIM (an attacker's addEmail on the
// victim's address) must never sign the victim into the attacker's account.
// UserEmail.email is globally unique, so createEmailUser must clear the stale
// unverified claim in the SAME transaction it creates the new owner's row.
// ---------------------------------------------------------------------------

interface UserRow {
  id: string;
  name: string | null;
  email: string | null;
  emailVerified: Date | null;
  image: string | null;
  sessionGeneration: number;
}
interface EmailRow {
  id: string;
  userId: string;
  email: string;
  verifiedAt: Date | null;
  isPrimary: boolean;
  status: string;
}

const store = vi.hoisted(() => ({
  users: [] as UserRow[],
  emails: [] as EmailRow[],
  nextUser: 1,
  nextEmail: 1,
}));

function projectUser(u: UserRow): UserRow {
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    emailVerified: u.emailVerified,
    image: u.image,
    sessionGeneration: u.sessionGeneration,
  };
}

// The prisma double. userEmail.create enforces the real unique(email)
// constraint by throwing a P2002-shaped error, so the test proves the stale
// claim really was cleared before the new row is inserted.
const db = vi.hoisted(() => ({}) as Record<string, unknown>);

vi.mock("@/lib/prisma", () => {
  const userEmail = {
    findUnique: async ({ where }: { where: { email: string } }) => {
      const row = store.emails.find((e) => e.email === where.email);
      if (!row) return null;
      const owner = store.users.find((u) => u.id === row.userId);
      if (!owner) return null;
      return { email: row.email, verifiedAt: row.verifiedAt, user: projectUser(owner) };
    },
    create: async ({
      data,
    }: {
      data: { userId: string; email: string; isPrimary?: boolean; verifiedAt?: Date | null };
    }) => {
      if (store.emails.some((e) => e.email === data.email)) {
        throw Object.assign(new Error("Unique constraint failed"), { code: "P2002" });
      }
      const row: EmailRow = {
        id: `ue_${store.nextEmail++}`,
        userId: data.userId,
        email: data.email,
        verifiedAt: data.verifiedAt ?? null,
        isPrimary: data.isPrimary ?? false,
        status: "active",
      };
      store.emails.push(row);
      return row;
    },
    deleteMany: async ({ where }: { where: { email: string; verifiedAt?: null } }) => {
      const before = store.emails.length;
      store.emails = store.emails.filter((e) => {
        const emailMatch = e.email === where.email;
        const verifiedMatch = where.verifiedAt === null ? e.verifiedAt === null : true;
        return !(emailMatch && verifiedMatch);
      });
      return { count: before - store.emails.length };
    },
    updateMany: async ({
      where,
      data,
    }: {
      where: { userId: string; email: string; verifiedAt?: null };
      data: { verifiedAt: Date };
    }) => {
      let count = 0;
      for (const e of store.emails) {
        if (
          e.userId === where.userId &&
          e.email === where.email &&
          (where.verifiedAt === null ? e.verifiedAt === null : true)
        ) {
          e.verifiedAt = data.verifiedAt;
          count++;
        }
      }
      return { count };
    },
  };
  const user = {
    findFirst: async ({ where }: { where: { email: string } }) => {
      const u = store.users.find((x) => x.email === where.email);
      return u ? projectUser(u) : null;
    },
    create: async ({ data }: { data: { email: string; emailVerified?: Date | null } }) => {
      const u: UserRow = {
        id: `u_${store.nextUser++}`,
        name: null,
        email: data.email,
        emailVerified: data.emailVerified ?? null,
        image: null,
        sessionGeneration: 0,
      };
      store.users.push(u);
      return projectUser(u);
    },
    update: async ({ where, data }: { where: { id: string }; data: { emailVerified?: Date } }) => {
      const u = store.users.find((x) => x.id === where.id);
      if (u && data.emailVerified) u.emailVerified = data.emailVerified;
      return u ? projectUser(u) : null;
    },
  };
  const prisma = {
    userEmail,
    user,
    // Interactive-transaction form: run the callback against the same store.
    $transaction: async (fn: (tx: unknown) => Promise<unknown>) => fn({ userEmail, user }),
  };
  Object.assign(db, prisma);
  return { prisma };
});

import { createEmailUser, getUserByEmailIdentity } from "./email-signin-user";

const VICTIM = "victim@example.com";

// Mirror of the email-otp provider's resolution in auth.ts (verified-only
// resolve, else create; backfill verification on the RESOLVED OWNER only).
async function otpSignIn(email: string) {
  const existing = await getUserByEmailIdentity(email);
  const user = existing ?? (await createEmailUser(email));
  if (existing && existing.emailVerified === null) {
    await (db.user as { update: (a: unknown) => Promise<unknown> }).update({
      where: { id: existing.id },
      data: { emailVerified: new Date() },
    });
    await (db.userEmail as { updateMany: (a: unknown) => Promise<unknown> }).updateMany({
      where: { userId: existing.id, email, verifiedAt: null },
      data: { verifiedAt: new Date() },
    });
  }
  return user;
}

// Mirror of the magic-link adapter path: getUserByEmail, else createUser.
async function magicLinkSignIn(email: string) {
  const found = await getUserByEmailIdentity(email);
  return found ?? (await createEmailUser(email));
}

// Seed an attacker account holding an UNVERIFIED, quarantined pre-claim on the
// victim's address — exactly what credential-actions.addEmail writes.
function seedAttackerPreClaim(): string {
  const attacker: UserRow = {
    id: `u_${store.nextUser++}`,
    name: null,
    email: "attacker@evil.test",
    emailVerified: new Date(),
    image: null,
    sessionGeneration: 0,
  };
  store.users.push(attacker);
  store.emails.push({
    id: `ue_${store.nextEmail++}`,
    userId: attacker.id,
    email: VICTIM,
    verifiedAt: null,
    isPrimary: false,
    status: "quarantined",
  });
  return attacker.id;
}

function verifiedClaimOwner(email: string): string | null {
  const row = store.emails.find((e) => e.email === email && e.verifiedAt !== null);
  return row ? row.userId : null;
}

beforeEach(() => {
  store.users = [];
  store.emails = [];
  store.nextUser = 1;
  store.nextEmail = 1;
});

describe("H1: unverified pre-claim cannot hijack a sign-in", () => {
  it("magic link: victim lands in a NEW account, not the attacker's", async () => {
    const attackerId = seedAttackerPreClaim();

    const victim = await magicLinkSignIn(VICTIM);

    expect(victim.id).not.toBe(attackerId);
    // Victim owns the address now, verified; attacker holds no claim on it.
    expect(verifiedClaimOwner(VICTIM)).toBe(victim.id);
    expect(store.emails.some((e) => e.userId === attackerId && e.email === VICTIM)).toBe(false);
    // Only one row per (globally unique) address survives.
    expect(store.emails.filter((e) => e.email === VICTIM)).toHaveLength(1);
  });

  it("OTP: victim lands in a NEW account and the attacker never gets a verified claim", async () => {
    const attackerId = seedAttackerPreClaim();

    const victim = await otpSignIn(VICTIM);

    expect(victim.id).not.toBe(attackerId);
    expect(victim.emailVerified).not.toBeNull();
    // The attacker's stale claim was cleared; the verified claim is the victim's.
    expect(verifiedClaimOwner(VICTIM)).toBe(victim.id);
    expect(verifiedClaimOwner(VICTIM)).not.toBe(attackerId);
    expect(store.emails.some((e) => e.userId === attackerId && e.email === VICTIM)).toBe(false);
  });

  it("no session is ever minted for the attacker's account from the victim's proof", async () => {
    const attackerId = seedAttackerPreClaim();

    const viaOtp = await otpSignIn(VICTIM);
    expect(viaOtp.id).not.toBe(attackerId);

    // Reset and repeat for the magic-link path.
    store.users = [];
    store.emails = [];
    store.nextUser = 1;
    store.nextEmail = 1;
    const attackerId2 = seedAttackerPreClaim();
    const viaLink = await magicLinkSignIn(VICTIM);
    expect(viaLink.id).not.toBe(attackerId2);
  });
});

describe("H1: legitimate flows still work (no regression)", () => {
  it("a returning VERIFIED user resolves to their existing account", async () => {
    // Create the account by proving control once.
    const first = await magicLinkSignIn(VICTIM);
    // Sign in again: must be the SAME account, no duplicate.
    const again = await magicLinkSignIn(VICTIM);
    expect(again.id).toBe(first.id);
    expect(store.users).toHaveLength(1);
    expect(store.emails.filter((e) => e.email === VICTIM)).toHaveLength(1);
  });

  it("OTP for an existing verified user does not mint a second account", async () => {
    const first = await otpSignIn(VICTIM);
    const again = await otpSignIn(VICTIM);
    expect(again.id).toBe(first.id);
    expect(store.users).toHaveLength(1);
  });

  it("a user's own second verified email resolves to their account", async () => {
    const u = await magicLinkSignIn(VICTIM);
    // Simulate a second, already-verified address on the same account.
    store.emails.push({
      id: `ue_${store.nextEmail++}`,
      userId: u.id,
      email: "second@example.com",
      verifiedAt: new Date(),
      isPrimary: false,
      status: "active",
    });
    const resolved = await getUserByEmailIdentity("second@example.com");
    expect(resolved?.id).toBe(u.id);
  });
});
