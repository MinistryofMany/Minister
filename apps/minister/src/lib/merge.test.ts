import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

// Unit tests for the account-merge data-reconciliation core (slice 5). Prisma is
// mocked with a small in-memory relational store that faithfully implements the
// handful of operations mergeAccounts/reverseMerge use (findMany with where +
// distinct, updateMany, deleteMany, update, create, and $transaction's callback
// form). pairwiseSub runs for real (it's a pure HMAC) against a test secret, so
// the SubjectOverride seam is exercised end to end, not stubbed.
//
// The store lets the assertions be about OUTCOMES (which rows ended up on whom,
// which were deleted, what the snapshot recorded) rather than about call spying,
// so the collision rules and the seam are genuinely verified.

interface Tables {
  user: Record<string, unknown>[];
  account: Record<string, unknown>[];
  session: Record<string, unknown>[];
  authenticator: Record<string, unknown>[];
  badge: Record<string, unknown>[];
  eligibility: Record<string, unknown>[];
  shareLink: Record<string, unknown>[];
  oidcAccessToken: Record<string, unknown>[];
  wizardSession: Record<string, unknown>[];
  auditLog: Record<string, unknown>[];
  userEmail: Record<string, unknown>[];
  recoveryCode: Record<string, unknown>[];
  recoveryAttempt: Record<string, unknown>[];
  subjectOverride: Record<string, unknown>[];
  inviteRedemption: Record<string, unknown>[];
  oidcClient: Record<string, unknown>[];
  mergeRecord: Record<string, unknown>[];
}

const h = vi.hoisted(() => {
  const tables: Tables = {
    user: [],
    account: [],
    session: [],
    authenticator: [],
    badge: [],
    eligibility: [],
    shareLink: [],
    oidcAccessToken: [],
    wizardSession: [],
    auditLog: [],
    userEmail: [],
    recoveryCode: [],
    recoveryAttempt: [],
    subjectOverride: [],
    inviteRedemption: [],
    oidcClient: [],
    mergeRecord: [],
  };
  let idSeq = 1;

  // Match a row against a Prisma-style `where`. Supports equality, `{ in: [...] }`,
  // `{ not: null }`, `{ gt: Date }`, and `OR: [...]`.
  function matchValue(rowVal: unknown, cond: unknown): boolean {
    if (cond !== null && typeof cond === "object" && !(cond instanceof Date)) {
      const c = cond as Record<string, unknown>;
      if ("in" in c) return (c.in as unknown[]).some((v) => v === rowVal);
      if ("not" in c) return rowVal !== c.not;
      if ("gt" in c) {
        const a = rowVal instanceof Date ? rowVal.getTime() : Number(rowVal);
        const b = c.gt instanceof Date ? (c.gt as Date).getTime() : Number(c.gt);
        return a > b;
      }
    }
    return rowVal === cond;
  }

  function matchWhere(row: Record<string, unknown>, where?: Record<string, unknown>): boolean {
    if (!where) return true;
    for (const [k, cond] of Object.entries(where)) {
      if (k === "OR") {
        const ok = (cond as Record<string, unknown>[]).some((sub) => matchWhere(row, sub));
        if (!ok) return false;
        continue;
      }
      if (!matchValue(row[k], cond)) return false;
    }
    return true;
  }

  function makeModel(name: keyof Tables) {
    const rows = () => tables[name];
    return {
      findMany: vi.fn(
        async (args?: {
          where?: Record<string, unknown>;
          select?: Record<string, true>;
          distinct?: string[];
        }) => {
          let out = rows().filter((r) => matchWhere(r, args?.where));
          if (args?.distinct) {
            const seen = new Set<string>();
            out = out.filter((r) => {
              const key = args.distinct!.map((d) => String(r[d])).join("|");
              if (seen.has(key)) return false;
              seen.add(key);
              return true;
            });
          }
          // Return shallow copies so callers can't mutate the store by reference.
          return out.map((r) => ({ ...r }));
        },
      ),
      findUnique: vi.fn(async (args: { where: Record<string, unknown> }) => {
        // Composite-key wheres arrive as { a_b: { a, b } }; flatten them.
        const flat: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(args.where)) {
          if (v !== null && typeof v === "object" && !(v instanceof Date)) {
            Object.assign(flat, v as Record<string, unknown>);
          } else {
            flat[k] = v;
          }
        }
        const found = rows().find((r) => matchWhere(r, flat));
        return found ? { ...found } : null;
      }),
      updateMany: vi.fn(
        async (args: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
          let count = 0;
          for (const r of rows()) {
            if (matchWhere(r, args.where)) {
              for (const [k, v] of Object.entries(args.data)) {
                if (v !== null && typeof v === "object" && "increment" in (v as object)) {
                  r[k] = (Number(r[k]) || 0) + Number((v as { increment: number }).increment);
                } else {
                  r[k] = v;
                }
              }
              count++;
            }
          }
          return { count };
        },
      ),
      update: vi.fn(
        async (args: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
          const flat: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(args.where)) {
            if (v !== null && typeof v === "object" && !(v instanceof Date)) {
              Object.assign(flat, v as Record<string, unknown>);
            } else {
              flat[k] = v;
            }
          }
          const r = rows().find((row) => matchWhere(row, flat));
          if (!r) {
            const err = new Error("Record to update not found.") as Error & { code: string };
            err.code = "P2025";
            throw err;
          }
          for (const [k, v] of Object.entries(args.data)) {
            if (v !== null && typeof v === "object" && "increment" in (v as object)) {
              r[k] = (Number(r[k]) || 0) + Number((v as { increment: number }).increment);
            } else {
              r[k] = v;
            }
          }
          return { ...r };
        },
      ),
      deleteMany: vi.fn(async (args: { where: Record<string, unknown> }) => {
        const before = rows().length;
        tables[name] = rows().filter((r) => !matchWhere(r, args.where));
        return { count: before - tables[name].length };
      }),
      create: vi.fn(
        async (args: { data: Record<string, unknown>; select?: Record<string, true> }) => {
          const row = { ...args.data };
          if (row.id === undefined) row.id = `gen_${idSeq++}`;
          // Mirror the schema's nullable defaults Prisma would supply, so reads see
          // the same shape (a not-yet-reversed MergeRecord has reversedAt === null).
          if (name === "mergeRecord" && row.reversedAt === undefined) row.reversedAt = null;
          rows().push(row);
          return { ...row };
        },
      ),
    };
  }

  const prisma: Record<string, unknown> = {
    $transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => fn(prisma)),
  };
  for (const name of Object.keys(tables) as (keyof Tables)[]) {
    prisma[name] = makeModel(name);
  }

  return { tables, prisma, matchWhere };
});

vi.mock("@/lib/prisma", () => ({ prisma: h.prisma }));

import { mergeAccounts, reverseMerge, type MergeSnapshot } from "./merge";
import { pairwiseSub } from "./oidc-tokens";

const SECRET = "merge-test-secret-which-is-32-chars!!";

const SURVIVOR = "user_survivor";
const DONOR = "user_donor";

function resetTables(): void {
  for (const name of Object.keys(h.tables) as (keyof typeof h.tables)[]) {
    h.tables[name] = [];
  }
}

// Seed two plain accounts. Callers push extra rows per test.
function seedUsers(
  survivor: Partial<Record<string, unknown>> = {},
  donor: Partial<Record<string, unknown>> = {},
): void {
  h.tables.user.push({
    id: SURVIVOR,
    isBanned: false,
    isAdmin: false,
    sessionGeneration: 0,
    email: "survivor@x.test",
    mergedIntoUserId: null,
    mergedAt: null,
    ...survivor,
  });
  h.tables.user.push({
    id: DONOR,
    isBanned: false,
    isAdmin: false,
    sessionGeneration: 0,
    email: "donor@x.test",
    mergedIntoUserId: null,
    mergedAt: null,
    ...donor,
  });
}

function user(id: string): Record<string, unknown> {
  const u = h.tables.user.find((r) => r.id === id);
  if (!u) throw new Error(`no user ${id}`);
  return u;
}

// Indexed access is checked (noUncheckedIndexedAccess); this asserts the row
// exists so the assertions below read cleanly.
function at(arr: Record<string, unknown>[], i: number): Record<string, unknown> {
  const r = arr[i];
  if (r === undefined) throw new Error(`no row at index ${i}`);
  return r;
}

function restoreEnv(pairwise: string | undefined, auth: string | undefined): void {
  if (pairwise === undefined) delete process.env.OIDC_PAIRWISE_SECRET;
  else process.env.OIDC_PAIRWISE_SECRET = pairwise;
  if (auth === undefined) delete process.env.AUTH_SECRET;
  else process.env.AUTH_SECRET = auth;
}

describe("mergeAccounts", () => {
  const ORIGINAL_PAIRWISE = process.env.OIDC_PAIRWISE_SECRET;
  const ORIGINAL_AUTH = process.env.AUTH_SECRET;

  beforeEach(() => {
    resetTables();
    process.env.OIDC_PAIRWISE_SECRET = SECRET;
    process.env.AUTH_SECRET = SECRET;
    for (const name of Object.keys(h.tables) as (keyof typeof h.tables)[]) {
      for (const m of Object.values(h.prisma[name] as Record<string, { mockClear?: () => void }>)) {
        m.mockClear?.();
      }
    }
  });

  afterAll(() => restoreEnv(ORIGINAL_PAIRWISE, ORIGINAL_AUTH));

  it("re-points the simple userId-FK models from donor to survivor", async () => {
    seedUsers();
    h.tables.account.push({ provider: "github", providerAccountId: "g1", userId: DONOR });
    h.tables.badge.push({ id: "b1", userId: DONOR, type: "email-domain", attributes: {} });
    h.tables.shareLink.push({ id: "sl1", userId: DONOR });
    h.tables.wizardSession.push({ id: "w1", userId: DONOR });
    h.tables.recoveryCode.push({ id: "rc1", userId: DONOR });
    h.tables.recoveryAttempt.push({ id: "ra1", userId: DONOR });
    h.tables.auditLog.push({ id: "al1", userId: DONOR });
    h.tables.session.push({ sessionToken: "st1", userId: DONOR });
    h.tables.authenticator.push({ credentialID: "cred1", userId: DONOR });

    await mergeAccounts(SURVIVOR, DONOR);

    expect(at(h.tables.account, 0).userId).toBe(SURVIVOR);
    expect(at(h.tables.badge, 0).userId).toBe(SURVIVOR);
    expect(at(h.tables.shareLink, 0).userId).toBe(SURVIVOR);
    expect(at(h.tables.wizardSession, 0).userId).toBe(SURVIVOR);
    expect(at(h.tables.recoveryCode, 0).userId).toBe(SURVIVOR);
    expect(at(h.tables.recoveryAttempt, 0).userId).toBe(SURVIVOR);
    expect(at(h.tables.auditLog, 0).userId).toBe(SURVIVOR);
    expect(at(h.tables.session, 0).userId).toBe(SURVIVOR);
    expect(at(h.tables.authenticator, 0).userId).toBe(SURVIVOR);
  });

  it("re-points OidcClient.ownerUserId and the donor's UserEmail rows", async () => {
    seedUsers();
    h.tables.oidcClient.push({ id: "oc1", ownerUserId: DONOR, clientId: "c-app" });
    h.tables.userEmail.push({ id: "ue1", userId: DONOR, email: "donor@x.test", isPrimary: true });

    await mergeAccounts(SURVIVOR, DONOR);

    expect(at(h.tables.oidcClient, 0).ownerUserId).toBe(SURVIVOR);
    expect(at(h.tables.userEmail, 0).userId).toBe(SURVIVOR);
  });

  it("Eligibility collision keeps the row with the EARLIER eligibleAt", async () => {
    seedUsers();
    // Same badgeType on both. Donor's eligibleAt is earlier → donor wins; the
    // survivor's row is deleted and the donor's moves over.
    const earlier = new Date("2020-01-01T00:00:00Z");
    const later = new Date("2024-01-01T00:00:00Z");
    h.tables.eligibility.push({
      id: "e_survivor",
      userId: SURVIVOR,
      badgeType: "age-over-21",
      eligibleAt: later,
      fuzzDays: 1,
      source: "s",
    });
    h.tables.eligibility.push({
      id: "e_donor",
      userId: DONOR,
      badgeType: "age-over-21",
      eligibleAt: earlier,
      fuzzDays: 2,
      source: "d",
    });

    await mergeAccounts(SURVIVOR, DONOR);

    const remaining = h.tables.eligibility;
    expect(remaining).toHaveLength(1);
    expect(at(remaining, 0).id).toBe("e_donor");
    expect(at(remaining, 0).userId).toBe(SURVIVOR);
    expect((at(remaining, 0).eligibleAt as Date).getTime()).toBe(earlier.getTime());
  });

  it("Eligibility collision keeps the SURVIVOR's row when it is earlier-or-equal", async () => {
    seedUsers();
    const earlier = new Date("2020-01-01T00:00:00Z");
    const later = new Date("2024-01-01T00:00:00Z");
    h.tables.eligibility.push({
      id: "e_survivor",
      userId: SURVIVOR,
      badgeType: "age-over-21",
      eligibleAt: earlier,
      fuzzDays: 1,
      source: "s",
    });
    h.tables.eligibility.push({
      id: "e_donor",
      userId: DONOR,
      badgeType: "age-over-21",
      eligibleAt: later,
      fuzzDays: 2,
      source: "d",
    });

    await mergeAccounts(SURVIVOR, DONOR);

    expect(h.tables.eligibility).toHaveLength(1);
    expect(at(h.tables.eligibility, 0).id).toBe("e_survivor");
    expect(at(h.tables.eligibility, 0).userId).toBe(SURVIVOR);
  });

  it("Eligibility with no collision simply moves to the survivor", async () => {
    seedUsers();
    h.tables.eligibility.push({
      id: "e_donor",
      userId: DONOR,
      badgeType: "residency-state",
      eligibleAt: new Date("2021-01-01T00:00:00Z"),
      fuzzDays: 0,
      source: "d",
    });

    await mergeAccounts(SURVIVOR, DONOR);

    expect(h.tables.eligibility).toHaveLength(1);
    expect(at(h.tables.eligibility, 0).userId).toBe(SURVIVOR);
  });

  it("InviteRedemption dedupes a shared code and moves a non-colliding one", async () => {
    seedUsers();
    // Shared code: both redeemed inviteCodeId 'inv-shared' → donor's dup deleted.
    h.tables.inviteRedemption.push({
      id: "ir_survivor",
      inviteCodeId: "inv-shared",
      userId: SURVIVOR,
      redeemedAt: new Date(),
    });
    h.tables.inviteRedemption.push({
      id: "ir_donor_dup",
      inviteCodeId: "inv-shared",
      userId: DONOR,
      redeemedAt: new Date(),
    });
    // Donor-only code: moves over.
    h.tables.inviteRedemption.push({
      id: "ir_donor_only",
      inviteCodeId: "inv-donor",
      userId: DONOR,
      redeemedAt: new Date(),
    });

    await mergeAccounts(SURVIVOR, DONOR);

    const ids = h.tables.inviteRedemption.map((r) => r.id).sort();
    expect(ids).toEqual(["ir_donor_only", "ir_survivor"]);
    expect(h.tables.inviteRedemption.find((r) => r.id === "ir_donor_only")!.userId).toBe(SURVIVOR);
  });

  it("creates a SubjectOverride for a DONOR-ONLY client carrying the donor's pairwise sub", async () => {
    seedUsers();
    // Donor used client 'rp-donor-only'; survivor never did.
    h.tables.oidcAccessToken.push({ jti: "t1", userId: DONOR, clientId: "rp-donor-only" });

    const summary = await mergeAccounts(SURVIVOR, DONOR);

    expect(summary.overridesCreated).toBe(1);
    expect(summary.strandedClients).toEqual([]);
    const ov = h.tables.subjectOverride.find(
      (o) => o.userId === SURVIVOR && o.clientId === "rp-donor-only",
    );
    expect(ov).toBeDefined();
    expect(ov!.sub).toBe(pairwiseSub(DONOR, "rp-donor-only"));
  });

  it("does NOT create an override for a SHARED client and records the donor sub as stranded", async () => {
    seedUsers();
    // Both used client 'rp-shared'.
    h.tables.oidcAccessToken.push({ jti: "ts", userId: SURVIVOR, clientId: "rp-shared" });
    h.tables.oidcAccessToken.push({ jti: "td", userId: DONOR, clientId: "rp-shared" });

    const summary = await mergeAccounts(SURVIVOR, DONOR);

    expect(summary.overridesCreated).toBe(0);
    expect(summary.strandedClients).toEqual(["rp-shared"]);
    // No override row was written for the shared client.
    expect(h.tables.subjectOverride.find((o) => o.clientId === "rp-shared")).toBeUndefined();
    // The snapshot records the stranded donor sub.
    const record = at(h.tables.mergeRecord, 0);
    const snap = record.snapshot as MergeSnapshot;
    expect(snap.strandedClients).toEqual([
      { clientId: "rp-shared", donorSub: pairwiseSub(DONOR, "rp-shared") },
    ]);
  });

  it("treats a client the survivor only has via an existing override as shared (stranded)", async () => {
    seedUsers();
    // Survivor already carries an override for 'rp-prior' (e.g. a prior merge).
    h.tables.subjectOverride.push({ userId: SURVIVOR, clientId: "rp-prior", sub: "prior-sub" });
    // Donor has token history with the same client.
    h.tables.oidcAccessToken.push({ jti: "td", userId: DONOR, clientId: "rp-prior" });

    const summary = await mergeAccounts(SURVIVOR, DONOR);

    expect(summary.overridesCreated).toBe(0);
    expect(summary.strandedClients).toEqual(["rp-prior"]);
    // The survivor's existing override is untouched.
    const ov = h.tables.subjectOverride.find(
      (o) => o.userId === SURVIVOR && o.clientId === "rp-prior",
    );
    expect(ov!.sub).toBe("prior-sub");
  });

  it("isBanned is sticky-OR: a banned donor bans the survivor", async () => {
    seedUsers({ isBanned: false }, { isBanned: true });
    await mergeAccounts(SURVIVOR, DONOR);
    expect(user(SURVIVOR).isBanned).toBe(true);
  });

  it("isBanned stays false when neither was banned", async () => {
    seedUsers({ isBanned: false }, { isBanned: false });
    await mergeAccounts(SURVIVOR, DONOR);
    expect(user(SURVIVOR).isBanned).toBe(false);
  });

  it("isAdmin is NEVER escalated from the donor", async () => {
    seedUsers({ isAdmin: false }, { isAdmin: true });
    await mergeAccounts(SURVIVOR, DONOR);
    // Survivor stays non-admin even though the donor was admin.
    expect(user(SURVIVOR).isAdmin).toBe(false);
  });

  it("bumps the survivor's sessionGeneration", async () => {
    seedUsers({ sessionGeneration: 3 });
    await mergeAccounts(SURVIVOR, DONOR);
    expect(user(SURVIVOR).sessionGeneration).toBe(4);
  });

  it("tombstones the donor and bumps its sessionGeneration", async () => {
    seedUsers({}, { sessionGeneration: 5 });
    await mergeAccounts(SURVIVOR, DONOR);
    const d = user(DONOR);
    expect(d.mergedIntoUserId).toBe(SURVIVOR);
    expect(d.mergedAt).toBeInstanceOf(Date);
    expect(d.sessionGeneration).toBe(6);
  });

  it("demotes a donor's primary email so the survivor keeps exactly one primary", async () => {
    seedUsers();
    h.tables.userEmail.push({ id: "ue_s", userId: SURVIVOR, isPrimary: true, email: "s@x.test" });
    h.tables.userEmail.push({ id: "ue_d", userId: DONOR, isPrimary: true, email: "d@x.test" });

    await mergeAccounts(SURVIVOR, DONOR);

    const survivorPrimaries = h.tables.userEmail.filter(
      (e) => e.userId === SURVIVOR && e.isPrimary === true,
    );
    expect(survivorPrimaries).toHaveLength(1);
    expect(at(survivorPrimaries, 0).id).toBe("ue_s");
    // The moved donor email is now the survivor's, demoted.
    const moved = h.tables.userEmail.find((e) => e.id === "ue_d");
    expect(moved!.userId).toBe(SURVIVOR);
    expect(moved!.isPrimary).toBe(false);
  });

  it("writes a MergeRecord with reversibleUntil = now + 7 days and a populated snapshot", async () => {
    seedUsers();
    h.tables.badge.push({ id: "b1", userId: DONOR, type: "email-domain", attributes: {} });

    const before = Date.now();
    const summary = await mergeAccounts(SURVIVOR, DONOR);
    const after = Date.now();

    const record = at(h.tables.mergeRecord, 0);
    expect(record.id).toBe(summary.mergeRecordId);
    expect(record.survivorUserId).toBe(SURVIVOR);
    expect(record.donorUserId).toBe(DONOR);

    const reversibleUntil = (record.reversibleUntil as Date).getTime();
    const sevenDays = 7 * 24 * 60 * 60 * 1000;
    expect(reversibleUntil).toBeGreaterThanOrEqual(before + sevenDays);
    expect(reversibleUntil).toBeLessThanOrEqual(after + sevenDays);

    const snap = record.snapshot as MergeSnapshot;
    expect(snap.version).toBe(1);
    expect(snap.moved.badge).toEqual(["b1"]);
    expect(summary.moved.badge).toBe(1);
  });

  it("refuses to merge an account into itself", async () => {
    seedUsers();
    await expect(mergeAccounts(SURVIVOR, SURVIVOR)).rejects.toThrow(/itself/);
  });

  it("refuses to merge an already-tombstoned donor", async () => {
    seedUsers({}, { mergedIntoUserId: "someone_else" });
    await expect(mergeAccounts(SURVIVOR, DONOR)).rejects.toThrow(/already merged/);
  });

  it("throws when the donor account is missing", async () => {
    seedUsers();
    h.tables.user = h.tables.user.filter((u) => u.id !== DONOR);
    await expect(mergeAccounts(SURVIVOR, DONOR)).rejects.toThrow(/Donor account .* not found/);
  });
});

describe("reverseMerge", () => {
  const ORIGINAL_PAIRWISE = process.env.OIDC_PAIRWISE_SECRET;
  const ORIGINAL_AUTH = process.env.AUTH_SECRET;

  beforeEach(() => {
    resetTables();
    process.env.OIDC_PAIRWISE_SECRET = SECRET;
    process.env.AUTH_SECRET = SECRET;
  });

  afterAll(() => restoreEnv(ORIGINAL_PAIRWISE, ORIGINAL_AUTH));

  it("un-tombstones the donor, restores the survivor ban flag, and removes created overrides", async () => {
    seedUsers({ isBanned: false }, { isBanned: true });
    // A donor-only client → an override is created at merge, removed on reverse.
    h.tables.oidcAccessToken.push({ jti: "t1", userId: DONOR, clientId: "rp-donor-only" });
    h.tables.badge.push({ id: "b1", userId: DONOR, type: "email-domain", attributes: {} });

    const summary = await mergeAccounts(SURVIVOR, DONOR);
    // Sticky-OR banned the survivor; donor is tombstoned; override + badge moved.
    expect(user(SURVIVOR).isBanned).toBe(true);
    expect(user(DONOR).mergedIntoUserId).toBe(SURVIVOR);
    expect(h.tables.subjectOverride).toHaveLength(1);
    expect(at(h.tables.badge, 0).userId).toBe(SURVIVOR);

    const result = await reverseMerge(summary.mergeRecordId);
    expect(result.ok).toBe(true);

    // Donor un-tombstoned.
    expect(user(DONOR).mergedIntoUserId).toBeNull();
    expect(user(DONOR).mergedAt).toBeNull();
    // Survivor ban restored to its pre-merge value (false).
    expect(user(SURVIVOR).isBanned).toBe(false);
    // The created override is gone.
    expect(h.tables.subjectOverride).toHaveLength(0);
    // The moved badge is back on the donor.
    expect(at(h.tables.badge, 0).userId).toBe(DONOR);
  });

  it("recreates a deleted Eligibility collision loser on reverse", async () => {
    seedUsers();
    const earlier = new Date("2020-01-01T00:00:00Z");
    const later = new Date("2024-01-01T00:00:00Z");
    // Survivor's is earlier → kept; donor's is deleted at merge, recreated on reverse.
    h.tables.eligibility.push({
      id: "e_survivor",
      userId: SURVIVOR,
      badgeType: "age-over-21",
      eligibleAt: earlier,
      fuzzDays: 1,
      source: "s",
    });
    h.tables.eligibility.push({
      id: "e_donor",
      userId: DONOR,
      badgeType: "age-over-21",
      eligibleAt: later,
      fuzzDays: 2,
      source: "d",
    });

    const summary = await mergeAccounts(SURVIVOR, DONOR);
    expect(h.tables.eligibility.map((e) => e.id)).toEqual(["e_survivor"]);

    await reverseMerge(summary.mergeRecordId);

    const byId = new Map(h.tables.eligibility.map((e) => [e.id, e]));
    expect(byId.has("e_donor")).toBe(true);
    expect(byId.get("e_donor")!.userId).toBe(DONOR);
    expect((byId.get("e_donor")!.eligibleAt as Date).getTime()).toBe(later.getTime());
  });

  it("recreates the SURVIVOR's deleted Eligibility (donor-wins branch) with original data on reverse", async () => {
    seedUsers();
    const earlier = new Date("2020-01-01T00:00:00Z");
    const later = new Date("2024-01-01T00:00:00Z");
    // Donor's is earlier → donor wins; the survivor's row is deleted at merge and
    // the donor's moves over. Reverse must recreate the survivor's row (with its
    // full original data) AND move the donor's row back to the donor.
    h.tables.eligibility.push({
      id: "e_survivor",
      userId: SURVIVOR,
      badgeType: "age-over-21",
      eligibleAt: later,
      fuzzDays: 7,
      source: "survivor-src",
    });
    h.tables.eligibility.push({
      id: "e_donor",
      userId: DONOR,
      badgeType: "age-over-21",
      eligibleAt: earlier,
      fuzzDays: 2,
      source: "donor-src",
    });

    const summary = await mergeAccounts(SURVIVOR, DONOR);
    // After merge: only the donor's (earlier) row survives, now owned by survivor.
    expect(h.tables.eligibility.map((e) => e.id)).toEqual(["e_donor"]);
    expect(at(h.tables.eligibility, 0).userId).toBe(SURVIVOR);

    const result = await reverseMerge(summary.mergeRecordId);
    expect(result.ok).toBe(true);

    const byId = new Map(h.tables.eligibility.map((e) => [e.id, e]));
    // Donor's row moved back to the donor.
    expect(byId.get("e_donor")!.userId).toBe(DONOR);
    // Survivor's row recreated with its original (later) data.
    const restored = byId.get("e_survivor");
    expect(restored).toBeDefined();
    expect(restored!.userId).toBe(SURVIVOR);
    expect((restored!.eligibleAt as Date).getTime()).toBe(later.getTime());
    expect(restored!.fuzzDays).toBe(7);
    expect(restored!.source).toBe("survivor-src");
  });

  it("refuses to reverse twice", async () => {
    seedUsers();
    const summary = await mergeAccounts(SURVIVOR, DONOR);
    expect((await reverseMerge(summary.mergeRecordId)).ok).toBe(true);
    const second = await reverseMerge(summary.mergeRecordId);
    expect(second.ok).toBe(false);
    expect(second.error).toMatch(/already reversed/);
  });

  it("refuses to reverse past the window", async () => {
    seedUsers();
    const summary = await mergeAccounts(SURVIVOR, DONOR);
    // Force the record past its reversal window.
    const record = h.tables.mergeRecord.find((r) => r.id === summary.mergeRecordId)!;
    record.reversibleUntil = new Date(Date.now() - 1000);
    const result = await reverseMerge(summary.mergeRecordId);
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/window/);
  });

  it("returns ok:false for a missing record", async () => {
    const result = await reverseMerge("nope");
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/not found/);
  });
});
