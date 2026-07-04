import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

// In-memory prisma mock for the NullifierEntry ledger + User owner handles. The
// UNIQUE(value) constraint is modeled by an atomic check-then-insert that throws
// a real P2002 on a duplicate `value`, so the record-first dedup path (and the
// concurrent-race winner selection) is exercised against the same failure the
// database produces.
const h = vi.hoisted(() => {
  // A P2002 unique-violation error, duck-typed exactly as interim.ts detects it.
  const p2002 = (): Error =>
    Object.assign(new Error("Unique constraint failed"), { code: "P2002" });

  interface Entry {
    id: string;
    value: Uint8Array;
    ownerHandle: string;
    badgeType: string;
    createdAt: Date;
  }
  interface UserRow {
    id: string;
    dedupHandle: string | null;
  }
  const store = { entries: [] as Entry[], users: [] as UserRow[] };
  let seq = 1;

  const hex = (v: Uint8Array): string => Buffer.from(v).toString("hex");

  const nullifierEntry = {
    create: vi.fn(
      async (args: {
        data: { value: Uint8Array; ownerHandle: string; badgeType: string };
        select?: Record<string, true>;
      }) => {
        // Atomic UNIQUE(value) check-then-insert.
        if (store.entries.some((e) => hex(e.value) === hex(args.data.value))) {
          throw p2002();
        }
        const row: Entry = {
          id: `entry_${seq++}`,
          value: args.data.value,
          ownerHandle: args.data.ownerHandle,
          badgeType: args.data.badgeType,
          createdAt: new Date(),
        };
        store.entries.push(row);
        return { id: row.id };
      },
    ),
    findUnique: vi.fn(async (args: { where: { value?: Uint8Array; id?: string } }) => {
      const found = store.entries.find((e) =>
        args.where.value !== undefined
          ? hex(e.value) === hex(args.where.value)
          : e.id === args.where.id,
      );
      return found ? { ...found } : null;
    }),
    deleteMany: vi.fn(async (args: { where: { id: string; ownerHandle: string } }) => {
      const before = store.entries.length;
      store.entries = store.entries.filter(
        (e) => !(e.id === args.where.id && e.ownerHandle === args.where.ownerHandle),
      );
      return { count: before - store.entries.length };
    }),
    updateMany: vi.fn(
      async (args: {
        where: { id: { in: string[] }; ownerHandle: string };
        data: { ownerHandle: string };
      }) => {
        let count = 0;
        for (const e of store.entries) {
          if (args.where.id.in.includes(e.id) && e.ownerHandle === args.where.ownerHandle) {
            e.ownerHandle = args.data.ownerHandle;
            count++;
          }
        }
        return { count };
      },
    ),
  };

  const user = {
    findUnique: vi.fn(async (args: { where: { id: string } }) => {
      const u = store.users.find((r) => r.id === args.where.id);
      return u ? { ...u } : null;
    }),
    updateMany: vi.fn(
      async (args: { where: { id: string; dedupHandle: null }; data: { dedupHandle: string } }) => {
        let count = 0;
        for (const u of store.users) {
          if (u.id === args.where.id && u.dedupHandle === null) {
            u.dedupHandle = args.data.dedupHandle;
            count++;
          }
        }
        return { count };
      },
    ),
  };

  const prisma = { nullifierEntry, user };
  return { store, prisma };
});

vi.mock("@/lib/prisma", () => ({ prisma: h.prisma }));

import { deriveDedupValue, deriveDisclosedNullifier, lp, lpStr } from "./encoding";
import { collectUserNullifierRefs, ensureDedupHandle } from "./index";
import { interimBackend } from "./interim";

const SAVED = process.env.OIDC_PAIRWISE_SECRET;

beforeEach(() => {
  h.store.entries.length = 0;
  h.store.users.length = 0;
  vi.clearAllMocks();
});

afterAll(() => {
  if (SAVED === undefined) delete process.env.OIDC_PAIRWISE_SECRET;
  else process.env.OIDC_PAIRWISE_SECRET = SAVED;
});

// ===========================================================================
// LP encoding — the anti-collision guarantee
// ===========================================================================
describe("length-prefix encoding", () => {
  it("prefixes a 2-byte big-endian byte length", () => {
    expect([...lpStr("abc")]).toEqual([0x00, 0x03, 0x61, 0x62, 0x63]);
    expect([...lp(Buffer.alloc(0))]).toEqual([0x00, 0x00]);
  });

  it("never collides two distinct field splits (the whole point of LP)", () => {
    // Bare concat would map ("ab","c") and ("a","bc") to the same bytes; LP does not.
    const ab_c = Buffer.concat([lpStr("ab"), lpStr("c")]);
    const a_bc = Buffer.concat([lpStr("a"), lpStr("bc")]);
    expect(ab_c.equals(a_bc)).toBe(false);
  });
});

// ===========================================================================
// §2.1 per-field byte caps — interim must reject what Signet (Phase 3) rejects
// ===========================================================================
describe("§2.1 per-field caps", () => {
  const CAP_SECRET = "field-cap-test-secret-at-least-32-chars!!";
  const savedCap = process.env.OIDC_PAIRWISE_SECRET;
  beforeEach(() => {
    process.env.OIDC_PAIRWISE_SECRET = CAP_SECRET;
  });
  afterAll(() => {
    if (savedCap === undefined) delete process.env.OIDC_PAIRWISE_SECRET;
    else process.env.OIDC_PAIRWISE_SECRET = savedCap;
  });

  it("accepts fields at the cap and rejects one byte over", () => {
    // anchor cap 512
    expect(() => deriveDedupValue("a".repeat(512), "oauth-account")).not.toThrow();
    expect(() => deriveDedupValue("a".repeat(513), "oauth-account")).toThrow(/anchor too long/);
    // badge_type cap 64
    expect(() => deriveDedupValue("gh_1", "t".repeat(64))).not.toThrow();
    expect(() => deriveDedupValue("gh_1", "t".repeat(65))).toThrow(/badge_type too long/);
    // clientId cap 256
    const value = deriveDedupValue("gh_1", "oauth-account");
    expect(() => deriveDisclosedNullifier(value, "c".repeat(256))).not.toThrow();
    expect(() => deriveDisclosedNullifier(value, "c".repeat(257))).toThrow(/clientId too long/);
  });

  it("measures the cap in BYTES, not code points (multi-byte UTF-8)", () => {
    // A 4-byte emoji × 129 = 516 bytes > 512, though only 129 code points.
    expect(() => deriveDedupValue("😀".repeat(129), "oauth-account")).toThrow(/anchor too long/);
  });
});

// ===========================================================================
// FROZEN-BUT-NON-FOREVER golden vectors (interim backend, Phases 1-3 ONLY)
//
// ⚠ These pin the INTERIM HMAC construction. Unlike the pairwise vectors, they
// are DELIBERATELY NOT forever: at the Phase 3 flip the ledger moves into Signet
// (VOPRF), these values are REPLACED, and every interim badge is reissued (free
// at zero users; the window is tracked). Do NOT treat a change here as a
// breaking wire change the way the pairwise golden vectors are — but DO keep
// them stable within the interim window so an accidental drift is still caught.
// ===========================================================================
const GOLDEN_SECRET = "minister-interim-golden-secret-v1-nonforever!!";
const GOLDEN = {
  anchor: "12345678", // a github numeric account id
  valueB64u: "6RNR_N83VFCJt2cS6C7g-MYoOa90YKoyZ0oZRZyf1VM",
  value2B64u: "XdCX3XeOkcwmuGT3Q2ZmUKYA5hK6f5gXbQgb-IqS2bc", // same anchor, account-age type
  discloseAlpha: "mnv1:zr1JQ-F_DEqqx05xw3RA2ax6BiPC6d6pWg1NUFzVn80",
  discloseBravo: "mnv1:F2ukTkFAYTyvYC6Ih67u69uBD-p7szByGRjiAV7oC5Q",
} as const;

describe("interim golden vectors (NON-forever — replaced at the Phase 3 Signet flip)", () => {
  let prev: string | undefined;
  beforeEach(() => {
    prev = process.env.OIDC_PAIRWISE_SECRET;
    process.env.OIDC_PAIRWISE_SECRET = GOLDEN_SECRET;
  });
  afterAll(() => {
    if (prev === undefined) delete process.env.OIDC_PAIRWISE_SECRET;
    else process.env.OIDC_PAIRWISE_SECRET = prev;
  });

  it("dedup value is stable and type-separated", () => {
    const v = deriveDedupValue(GOLDEN.anchor, "oauth-account");
    expect(v.toString("base64url")).toBe(GOLDEN.valueB64u);
    // Same anchor, different badge_type ⇒ different value (own dedup namespace).
    const v2 = deriveDedupValue(GOLDEN.anchor, "account-age");
    expect(v2.toString("base64url")).toBe(GOLDEN.value2B64u);
    expect(v2.toString("base64url")).not.toBe(GOLDEN.valueB64u);
  });

  it("disclosed nullifier is mnv1-prefixed, per-RP, and stable", () => {
    const v = deriveDedupValue(GOLDEN.anchor, "oauth-account");
    expect(deriveDisclosedNullifier(v, "mc_client_alpha")).toBe(GOLDEN.discloseAlpha);
    expect(deriveDisclosedNullifier(v, "mc_client_bravo")).toBe(GOLDEN.discloseBravo);
    // Different RP ⇒ different disclosed value (cross-RP unlinkability).
    expect(GOLDEN.discloseAlpha).not.toBe(GOLDEN.discloseBravo);
  });

  it("fails closed when the interim key is absent", () => {
    delete process.env.OIDC_PAIRWISE_SECRET;
    expect(() => deriveDedupValue(GOLDEN.anchor, "oauth-account")).toThrow(/OIDC_PAIRWISE_SECRET/);
  });
});

// ===========================================================================
// Backend behavior
// ===========================================================================
describe("interimBackend", () => {
  beforeEach(() => {
    process.env.OIDC_PAIRWISE_SECRET = "interim-backend-test-secret-32-chars!!";
  });

  it("registers a new credential, then reports already_yours for the same owner", async () => {
    const a = await interimBackend.registerDedup({
      anchor: "gh_1",
      badgeType: "oauth-account",
      ownerHandle: "owner_A",
    });
    expect(a).toEqual({ status: "registered", entryRef: expect.any(String) });

    const again = await interimBackend.registerDedup({
      anchor: "gh_1",
      badgeType: "oauth-account",
      ownerHandle: "owner_A",
    });
    expect(again).toEqual({
      status: "already_yours",
      entryRef: (a as { entryRef: string }).entryRef,
    });
    expect(h.store.entries).toHaveLength(1);
  });

  it("refuses a credential already held by a DIFFERENT owner (taken)", async () => {
    await interimBackend.registerDedup({
      anchor: "gh_2",
      badgeType: "oauth-account",
      ownerHandle: "owner_A",
    });
    const taken = await interimBackend.registerDedup({
      anchor: "gh_2",
      badgeType: "oauth-account",
      ownerHandle: "owner_B",
    });
    expect(taken).toEqual({ status: "taken" });
    expect(h.store.entries).toHaveLength(1);
  });

  it("concurrent registrations of the same credential yield exactly one winner", async () => {
    const results = await Promise.all([
      interimBackend.registerDedup({
        anchor: "gh_r",
        badgeType: "oauth-account",
        ownerHandle: "A",
      }),
      interimBackend.registerDedup({
        anchor: "gh_r",
        badgeType: "oauth-account",
        ownerHandle: "B",
      }),
    ]);
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual(["registered", "taken"]);
    expect(h.store.entries).toHaveLength(1);
  });

  it("discloses a per-RP nullifier for the owner, and fails closed on owner mismatch", async () => {
    const reg = await interimBackend.registerDedup({
      anchor: "gh_3",
      badgeType: "oauth-account",
      ownerHandle: "owner_A",
    });
    const entryRef = (reg as { entryRef: string }).entryRef;

    const na = await interimBackend.disclose({
      entryRef,
      ownerHandle: "owner_A",
      clientId: "mc_x",
    });
    const nb = await interimBackend.disclose({
      entryRef,
      ownerHandle: "owner_A",
      clientId: "mc_y",
    });
    expect(na).toMatch(/^mnv1:[A-Za-z0-9_-]+$/);
    expect(na).not.toBe(nb); // per-RP

    // Owner-check: a mis-bound ref must NOT yield a value.
    await expect(
      interimBackend.disclose({ entryRef, ownerHandle: "attacker", clientId: "mc_x" }),
    ).rejects.toThrow(/owner mismatch/);
    // Missing entry fails closed too.
    await expect(
      interimBackend.disclose({ entryRef: "nope", ownerHandle: "owner_A", clientId: "mc_x" }),
    ).rejects.toThrow(/not found/);
  });

  it("release frees the credential to be re-registered from another account", async () => {
    const reg = await interimBackend.registerDedup({
      anchor: "gh_4",
      badgeType: "oauth-account",
      ownerHandle: "owner_A",
    });
    const entryRef = (reg as { entryRef: string }).entryRef;

    // Wrong owner can't release.
    await interimBackend.release({ entryRef, ownerHandle: "attacker" });
    expect(h.store.entries).toHaveLength(1);

    await interimBackend.release({ entryRef, ownerHandle: "owner_A" });
    expect(h.store.entries).toHaveLength(0);

    // Now a different account may claim the same credential.
    const reclaim = await interimBackend.registerDedup({
      anchor: "gh_4",
      badgeType: "oauth-account",
      ownerHandle: "owner_B",
    });
    expect(reclaim.status).toBe("registered");
  });

  it("reassignOwner re-tags exactly the listed refs, owner-checked per ref", async () => {
    const r1 = await interimBackend.registerDedup({
      anchor: "a",
      badgeType: "oauth-account",
      ownerHandle: "donor",
    });
    const r2 = await interimBackend.registerDedup({
      anchor: "b",
      badgeType: "account-age",
      ownerHandle: "donor",
    });
    const survivorOwned = await interimBackend.registerDedup({
      anchor: "c",
      badgeType: "oauth-account",
      ownerHandle: "survivor",
    });
    const refs = [(r1 as { entryRef: string }).entryRef, (r2 as { entryRef: string }).entryRef];

    const moved = await interimBackend.reassignOwner({
      entryRefs: refs,
      fromOwnerHandle: "donor",
      toOwnerHandle: "survivor",
    });
    expect(moved).toBe(2);
    // The survivor's own entry is untouched (never wholesale-moved).
    const survivorRef = (survivorOwned as { entryRef: string }).entryRef;
    expect(h.store.entries.every((e) => e.ownerHandle === "survivor")).toBe(true);
    // Re-tag back (reverse merge) moves exactly those two, not the survivor's own.
    const back = await interimBackend.reassignOwner({
      entryRefs: refs,
      fromOwnerHandle: "survivor",
      toOwnerHandle: "donor",
    });
    expect(back).toBe(2);
    expect(h.store.entries.find((e) => e.id === survivorRef)!.ownerHandle).toBe("survivor");
  });
});

// ===========================================================================
// Owner-handle minting + ref capture
// ===========================================================================
describe("ensureDedupHandle", () => {
  beforeEach(() => {
    process.env.OIDC_PAIRWISE_SECRET = "handle-test-secret-at-least-32-chars!!";
  });

  it("mints once, lazily, and returns the SAME handle on repeat calls", async () => {
    h.store.users.push({ id: "u1", dedupHandle: null });
    const first = await ensureDedupHandle("u1");
    expect(first).toMatch(/^[A-Za-z0-9_-]{22}$/); // 16 bytes base64url
    const second = await ensureDedupHandle("u1");
    expect(second).toBe(first); // stable — never regenerated
  });

  it("captures all of a user's ledger refs for release", async () => {
    h.store.users.push({ id: "u2", dedupHandle: "owner_u2" });
    // collectUserNullifierRefs also reads badges; give it a badge model.
    (h.prisma as unknown as { badge: unknown }).badge = {
      findMany: vi.fn(async () => [{ nullifierRef: "e1" }, { nullifierRef: "e2" }]),
    };
    const { ownerHandle, entryRefs } = await collectUserNullifierRefs("u2");
    expect(ownerHandle).toBe("owner_u2");
    expect(entryRefs.sort()).toEqual(["e1", "e2"]);
  });
});
