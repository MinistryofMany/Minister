import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Session } from "next-auth";

// createCohortDef tests (P2-U1). Deliberately does NOT mock @/lib/cohort-filter —
// the whole point is proving the action reuses P2-U0's real `cohortFilterSchema`
// (allowlist + known-type checks) rather than reimplementing validation. Only the
// admin gate, prisma writes, audit, and cache revalidation are mocked (same
// pattern as admin-recovery-config.test.ts: importing the real @/lib/session
// pulls in @/auth's Node env, which can't load under vitest).

const h = vi.hoisted(() => {
  const db = {
    cohortStatDef: {
      create: vi.fn((_a?: unknown): Promise<unknown> => Promise.resolve({ id: "def1" })),
    },
  };
  return {
    state: { session: null as Session | null },
    audit: vi.fn(async (..._a: unknown[]) => {}),
    db,
  };
});

vi.mock("@/lib/session", () => ({
  requireAdmin: async () => {
    if (!h.state.session?.user?.id) throw new Error("Not an admin");
    return h.state.session;
  },
}));
vi.mock("@/lib/audit", () => ({ audit: h.audit }));
vi.mock("@/lib/prisma", () => ({ prisma: h.db }));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));
// recomputeAllStats isn't exercised by these tests; stub it out so importing
// stats-actions.ts doesn't drag in the issuer/sybil-config machinery.
vi.mock("@/lib/stats-recompute", () => ({
  recomputeAllStats: vi.fn(async () => ({ durationMs: 0 })),
}));

import { createCohortDef } from "@/server/stats-actions";

const db = h.db;

function adminSession(): Session {
  return {
    user: { id: "admin1" },
    expires: new Date(Date.now() + 3_600_000).toISOString(),
  } as unknown as Session;
}

beforeEach(() => {
  vi.clearAllMocks();
  h.state.session = adminSession();
  db.cohortStatDef.create.mockResolvedValue({ id: "def1" });
});

describe("createCohortDef", () => {
  it("rejects a non-allowlisted key on the numerator (the injection-hole close, reused)", async () => {
    const res = await createCohortDef({
      label: "Bad cohort",
      numeratorFilter: { clauses: [{ type: "oauth-account", where: { handle: "octocat" } }] },
      denominatorFilter: { clauses: [{ type: "oauth-account", where: { provider: "github" } }] },
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.error).toMatch(/Numerator/);
    expect(res.error).toMatch(/not an allowlisted attribute/);
    expect(db.cohortStatDef.create).not.toHaveBeenCalled();
  });

  it("rejects a non-allowlisted key on the denominator, named separately from the numerator", async () => {
    const res = await createCohortDef({
      label: "Bad cohort",
      numeratorFilter: { clauses: [{ type: "oauth-account", where: { provider: "github" } }] },
      denominatorFilter: {
        clauses: [{ type: "email-domain", where: { domain: "corp.example.com" } }],
      },
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.error).toMatch(/Denominator/);
    expect(db.cohortStatDef.create).not.toHaveBeenCalled();
  });

  it("rejects an unknown badge type", async () => {
    const res = await createCohortDef({
      label: "Bad cohort",
      numeratorFilter: { clauses: [{ type: "totally-made-up" }] },
      denominatorFilter: { clauses: [{ type: "oauth-account", where: { provider: "github" } }] },
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.error).toMatch(/Unknown badge type/);
    expect(db.cohortStatDef.create).not.toHaveBeenCalled();
  });

  it("rejects a malformed filter shape (not the clause-array format)", async () => {
    const res = await createCohortDef({
      label: "Bad cohort",
      numeratorFilter: { type: "oauth-account" }, // missing the `clauses` wrapper
      denominatorFilter: { clauses: [{ type: "oauth-account", where: { provider: "github" } }] },
    });
    expect(res.ok).toBe(false);
    expect(db.cohortStatDef.create).not.toHaveBeenCalled();
  });

  it("rejects a label that is empty", async () => {
    const res = await createCohortDef({
      label: "   ",
      numeratorFilter: { clauses: [{ type: "oauth-account", where: { provider: "github" } }] },
      denominatorFilter: { clauses: [{ type: "oauth-account", where: { provider: "github" } }] },
    });
    expect(res.ok).toBe(false);
    expect(db.cohortStatDef.create).not.toHaveBeenCalled();
  });

  it("accepts a valid allowlisted def, inserts, audits, and revalidates", async () => {
    const res = await createCohortDef({
      label: "Aged GitHub accounts (share of GitHub accounts)",
      numeratorFilter: {
        clauses: [
          { type: "account-age", where: { provider: "github" }, whereGte: { olderThanMonths: 24 } },
        ],
      },
      denominatorFilter: {
        clauses: [{ type: "oauth-account", where: { provider: "github" } }],
      },
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("unreachable");
    expect(res.id).toBe("def1");

    expect(db.cohortStatDef.create).toHaveBeenCalledTimes(1);
    const call = db.cohortStatDef.create.mock.calls[0]?.[0] as {
      data: { label: string; numeratorFilter: unknown; denominatorFilter: unknown };
    };
    expect(call.data.label).toBe("Aged GitHub accounts (share of GitHub accounts)");
    expect(call.data.numeratorFilter).toEqual({
      clauses: [
        { type: "account-age", where: { provider: "github" }, whereGte: { olderThanMonths: 24 } },
      ],
    });

    expect(h.audit).toHaveBeenCalledWith(
      "admin1",
      "admin.stats.cohort_def_created",
      expect.objectContaining({ cohortStatDefId: "def1" }),
    );
  });

  it("rejects an anonymous / non-admin caller before touching prisma", async () => {
    h.state.session = null;
    const res = await createCohortDef({
      label: "Cohort",
      numeratorFilter: { clauses: [{ type: "oauth-account", where: { provider: "github" } }] },
      denominatorFilter: { clauses: [{ type: "oauth-account", where: { provider: "github" } }] },
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.error).toBe("Not authorized");
    expect(db.cohortStatDef.create).not.toHaveBeenCalled();
  });
});
