import { beforeEach, describe, expect, it, vi } from "vitest";

// In-memory stand-in for the RecoveryCode table. Mirrors the recovery-ticket
// test pattern: the real Argon2id crypto (via @/lib/oidc-clients, the SAME
// hasher used for OidcClient.clientSecretHash) runs offline; only the DB is
// mocked. @/lib/oidc-clients imports @/lib/prisma at module load, so this mock
// must satisfy that import even though we only exercise recoveryCode here.

interface Row {
  id: string;
  userId: string;
  codeHash: string;
  usedAt: Date | null;
}

// The in-memory table store lives behind vi.hoisted so the vi.mock factory
// (hoisted to the top of the file) and the test bodies share one mutable array.
const store = vi.hoisted(() => ({ rows: [] as Row[], nextId: 1 }));

vi.mock("@/lib/prisma", () => {
  function matchWhere(row: Row, where: Record<string, unknown>): boolean {
    if ("id" in where && row.id !== where.id) return false;
    if ("userId" in where && row.userId !== where.userId) return false;
    if ("usedAt" in where && where.usedAt === null && row.usedAt !== null) return false;
    return true;
  }

  const recoveryCode = {
    deleteMany: vi.fn(async ({ where }: { where: Record<string, unknown> }) => {
      const before = store.rows.length;
      store.rows = store.rows.filter((r) => !matchWhere(r, where));
      return { count: before - store.rows.length };
    }),
    createMany: vi.fn(async ({ data }: { data: Array<{ userId: string; codeHash: string }> }) => {
      for (const d of data) {
        store.rows.push({
          id: `rc_${store.nextId++}`,
          userId: d.userId,
          codeHash: d.codeHash,
          usedAt: null,
        });
      }
      return { count: data.length };
    }),
    findMany: vi.fn(async ({ where }: { where: Record<string, unknown> }) =>
      store.rows
        .filter((r) => matchWhere(r, where))
        .map((r) => ({ id: r.id, codeHash: r.codeHash })),
    ),
    updateMany: vi.fn(
      async ({ where, data }: { where: Record<string, unknown>; data: { usedAt: Date } }) => {
        let count = 0;
        for (const r of store.rows) {
          if (matchWhere(r, where)) {
            r.usedAt = data.usedAt;
            count++;
          }
        }
        return { count };
      },
    ),
    count: vi.fn(
      async ({ where }: { where: Record<string, unknown> }) =>
        store.rows.filter((r) => matchWhere(r, where)).length,
    ),
  };

  const prisma = {
    recoveryCode,
    // generateRecoveryCodes wraps delete+create in $transaction(async tx => ...).
    // The tx handle is just the same client in this mock.
    $transaction: vi.fn(async (fn: (tx: typeof prisma) => Promise<unknown>) => fn(prisma)),
  };

  return { prisma };
});

import {
  countUnusedCodes,
  generateRecoveryCodes,
  normalizeRecoveryCode,
  redeemRecoveryCode,
} from "./recovery-codes";
import { RECOVERY_CODE_COUNT } from "./assurance";

const USER = "user_abc";
const OTHER = "user_xyz";

describe("recovery-codes", () => {
  beforeEach(() => {
    store.rows = [];
    store.nextId = 1;
    vi.clearAllMocks();
  });

  describe("generateRecoveryCodes", () => {
    it("returns RECOVERY_CODE_COUNT plaintext codes", async () => {
      const codes = await generateRecoveryCodes(USER);
      expect(codes).toHaveLength(RECOVERY_CODE_COUNT);
    });

    it("codes are unique and formatted XXXX-XXXX-XXXX from the safe alphabet", async () => {
      const codes = await generateRecoveryCodes(USER);
      expect(new Set(codes).size).toBe(codes.length);
      for (const code of codes) {
        // Three 4-char groups; alphabet excludes I, L, O, U.
        expect(code).toMatch(
          /^[ABCDEFGHJKMNPQRSTVWXYZ0-9]{4}-[ABCDEFGHJKMNPQRSTVWXYZ0-9]{4}-[ABCDEFGHJKMNPQRSTVWXYZ0-9]{4}$/,
        );
      }
    });

    it("stores one hashed (non-plaintext) row per code", async () => {
      const codes = await generateRecoveryCodes(USER);
      expect(store.rows).toHaveLength(RECOVERY_CODE_COUNT);
      for (const r of store.rows) {
        // Argon2id encoded hash, never the plaintext.
        expect(r.codeHash.startsWith("$argon2")).toBe(true);
        expect(codes).not.toContain(r.codeHash);
        expect(r.usedAt).toBeNull();
      }
    });

    it("regenerating deletes the user's unused codes (invalidates old batch)", async () => {
      const first = await generateRecoveryCodes(USER);
      await generateRecoveryCodes(USER);
      // Old unused codes are gone — none of the first batch verifies anymore.
      for (const code of first) {
        expect(await redeemRecoveryCode(USER, code)).toBe(false);
      }
      // Exactly one fresh batch remains.
      expect(store.rows.filter((r) => r.usedAt === null)).toHaveLength(RECOVERY_CODE_COUNT);
    });

    it("regenerating preserves already-USED rows (spent audit trail)", async () => {
      const codes = await generateRecoveryCodes(USER);
      const target = codes[0]!;
      expect(await redeemRecoveryCode(USER, target)).toBe(true);
      const usedBefore = store.rows.filter((r) => r.usedAt !== null).length;
      expect(usedBefore).toBe(1);

      await generateRecoveryCodes(USER);
      // The spent row survives; new batch is unused.
      expect(store.rows.filter((r) => r.usedAt !== null)).toHaveLength(1);
      expect(store.rows.filter((r) => r.usedAt === null)).toHaveLength(RECOVERY_CODE_COUNT);
    });

    it("does not touch another user's codes when regenerating", async () => {
      await generateRecoveryCodes(OTHER);
      await generateRecoveryCodes(USER);
      await generateRecoveryCodes(USER);
      expect(store.rows.filter((r) => r.userId === OTHER)).toHaveLength(RECOVERY_CODE_COUNT);
    });
  });

  describe("redeemRecoveryCode", () => {
    it("redeems a valid code (hash round-trip via the real hasher)", async () => {
      const codes = await generateRecoveryCodes(USER);
      expect(await redeemRecoveryCode(USER, codes[3]!)).toBe(true);
    });

    it("tolerates formatting differences (lowercase, no dashes, spaces)", async () => {
      const codes = await generateRecoveryCodes(USER);
      const messy = ` ${codes[0]!.replace(/-/g, "").toLowerCase()} `;
      expect(await redeemRecoveryCode(USER, messy)).toBe(true);
    });

    it("rejects a wrong code", async () => {
      await generateRecoveryCodes(USER);
      expect(await redeemRecoveryCode(USER, "AAAA-BBBB-CCCC")).toBe(false);
    });

    it("rejects a malformed (wrong-length) code without throwing", async () => {
      await generateRecoveryCodes(USER);
      expect(await redeemRecoveryCode(USER, "SHORT")).toBe(false);
    });

    it("returns false for a user with no codes (no enumeration signal)", async () => {
      const codes = await generateRecoveryCodes(USER);
      // A real code, but for the WRONG user, must not redeem.
      expect(await redeemRecoveryCode(OTHER, codes[0]!)).toBe(false);
    });

    it("is single-use: the same code can't be redeemed twice (double-spend)", async () => {
      const codes = await generateRecoveryCodes(USER);
      const code = codes[2]!;
      expect(await redeemRecoveryCode(USER, code)).toBe(true);
      expect(await redeemRecoveryCode(USER, code)).toBe(false);
    });

    it("guards double-spend even under a concurrent race on the same code", async () => {
      const codes = await generateRecoveryCodes(USER);
      const code = codes[5]!;
      const [a, b] = await Promise.all([
        redeemRecoveryCode(USER, code),
        redeemRecoveryCode(USER, code),
      ]);
      // Exactly one wins; the conditional updateMany(usedAt:null) arbitrates.
      expect([a, b].filter(Boolean)).toHaveLength(1);
    });

    it("only consumes the redeemed code, leaving the rest usable", async () => {
      const codes = await generateRecoveryCodes(USER);
      expect(await redeemRecoveryCode(USER, codes[0]!)).toBe(true);
      expect(await redeemRecoveryCode(USER, codes[1]!)).toBe(true);
      expect(store.rows.filter((r) => r.usedAt === null)).toHaveLength(RECOVERY_CODE_COUNT - 2);
    });
  });

  describe("countUnusedCodes", () => {
    it("counts only this user's unused codes", async () => {
      await generateRecoveryCodes(USER);
      await generateRecoveryCodes(OTHER);
      expect(await countUnusedCodes(USER)).toBe(RECOVERY_CODE_COUNT);

      const codes = await generateRecoveryCodes(USER); // regenerate USER
      await redeemRecoveryCode(USER, codes[0]!);
      expect(await countUnusedCodes(USER)).toBe(RECOVERY_CODE_COUNT - 1);
    });
  });

  describe("normalizeRecoveryCode", () => {
    it("strips separators/whitespace and uppercases", () => {
      expect(normalizeRecoveryCode("  abcd-efgh-jkmn ")).toBe("ABCDEFGHJKMN");
    });

    it("maps human-substituted glyphs back onto the alphabet", () => {
      // I/L→1, O→0, U→V — repairs a transcription of the omitted characters.
      expect(normalizeRecoveryCode("ILOU")).toBe("110V");
    });
  });
});
