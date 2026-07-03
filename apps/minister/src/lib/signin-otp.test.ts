import { beforeEach, describe, expect, it, vi } from "vitest";

// In-memory stand-in for the SignInOtp table (mirrors the recovery-codes test
// pattern: the real node:crypto HMAC runs offline; only the DB is mocked).
interface Row {
  id: string;
  identifier: string;
  codeHash: string;
  expires: Date;
  attempts: number;
  createdAt: Date;
}

const store = vi.hoisted(() => ({ rows: [] as Row[], nextId: 1, clock: 0 }));

vi.mock("@/lib/prisma", () => {
  const signInOtp = {
    deleteMany: vi.fn(async ({ where }: { where: { identifier: string } }) => {
      const before = store.rows.length;
      store.rows = store.rows.filter((r) => r.identifier !== where.identifier);
      return { count: before - store.rows.length };
    }),
    create: vi.fn(
      async ({ data }: { data: { identifier: string; codeHash: string; expires: Date } }) => {
        const row: Row = {
          id: `otp_${store.nextId++}`,
          identifier: data.identifier,
          codeHash: data.codeHash,
          expires: data.expires,
          attempts: 0,
          // Strictly increasing so orderBy createdAt desc is deterministic.
          createdAt: new Date(++store.clock),
        };
        store.rows.push(row);
        return row;
      },
    ),
    findFirst: vi.fn(async ({ where }: { where: { identifier: string } }) => {
      const matches = store.rows
        .filter((r) => r.identifier === where.identifier)
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
      return matches[0] ?? null;
    }),
    update: vi.fn(
      async ({ where, data }: { where: { id: string }; data: { attempts: number } }) => {
        const row = store.rows.find((r) => r.id === where.id);
        if (row) row.attempts = data.attempts;
        return row;
      },
    ),
  };

  return {
    prisma: {
      signInOtp,
      // createSignInOtp uses the array form; run the (eager) mock promises.
      $transaction: vi.fn(async (ops: Promise<unknown>[]) => Promise.all(ops)),
    },
  };
});

import { createSignInOtp, normalizeOtp, OTP_MAX_ATTEMPTS, verifySignInOtp } from "./signin-otp";

const ID = "user@work.test";

beforeEach(() => {
  store.rows = [];
  store.nextId = 1;
  store.clock = 0;
  process.env.AUTH_SECRET = "signin-otp-test-secret-at-least-32-chars!!";
});

describe("normalizeOtp", () => {
  it("uppercases and strips separators", () => {
    expect(normalizeOtp("ab-cd 23")).toBe("ABCD23");
  });
});

describe("createSignInOtp", () => {
  it("returns an 8-char code from the unambiguous alphabet and stores one hashed row", async () => {
    const code = await createSignInOtp(ID);
    expect(code).toMatch(/^[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{8}$/);
    expect(store.rows).toHaveLength(1);
    expect(store.rows[0]?.codeHash).not.toContain(code); // stored hashed, not plaintext
    expect(store.rows[0]?.identifier).toBe(ID);
  });

  it("clears any prior code for the identifier (one live code at a time)", async () => {
    await createSignInOtp(ID);
    await createSignInOtp(ID);
    expect(store.rows.filter((r) => r.identifier === ID)).toHaveLength(1);
  });
});

describe("verifySignInOtp", () => {
  it("accepts the correct code and consumes it (single-use)", async () => {
    const code = await createSignInOtp(ID);
    expect(await verifySignInOtp(ID, code)).toEqual({ ok: true });
    // Consumed: replay fails.
    expect(await verifySignInOtp(ID, code)).toEqual({ ok: false, reason: "no-code" });
  });

  it("is case- and separator-insensitive on the submitted code", async () => {
    const code = await createSignInOtp(ID);
    const messy = ` ${code.toLowerCase().slice(0, 4)}-${code.toLowerCase().slice(4)} `;
    expect(await verifySignInOtp(ID, messy)).toEqual({ ok: true });
  });

  it("reports no-code when nothing is pending", async () => {
    expect(await verifySignInOtp(ID, "ABCDEFGH")).toEqual({ ok: false, reason: "no-code" });
  });

  it("rejects and burns the code after OTP_MAX_ATTEMPTS wrong guesses", async () => {
    const code = await createSignInOtp(ID);
    const wrong = code === "22222222" ? "33333333" : "22222222";
    for (let i = 0; i < OTP_MAX_ATTEMPTS - 1; i++) {
      expect(await verifySignInOtp(ID, wrong)).toEqual({ ok: false, reason: "mismatch" });
    }
    // The Nth wrong guess trips the lockout and deletes the code.
    expect(await verifySignInOtp(ID, wrong)).toEqual({ ok: false, reason: "locked-out" });
    // Even the correct code no longer works — a fresh one is required.
    expect(await verifySignInOtp(ID, code)).toEqual({ ok: false, reason: "no-code" });
  });

  it("rejects an expired code and clears it", async () => {
    await createSignInOtp(ID);
    // Force expiry in the store.
    const row = store.rows[0];
    if (!row) throw new Error("expected a row");
    row.expires = new Date(Date.now() - 1000);
    expect(await verifySignInOtp(ID, "ANYTHING")).toEqual({ ok: false, reason: "expired" });
    expect(store.rows).toHaveLength(0);
  });
});
