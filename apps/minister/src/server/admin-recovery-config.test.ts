import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Session } from "next-auth";

// ---------------------------------------------------------------------------
// Recovery-config guardrail tests. Two layers:
//   1. The PURE guardrail module (bounds, solo-block, asymmetric write plans) —
//      no mocks, exercised directly.
//   2. The recovery-config server ACTIONS with prisma / mailer / audit / session
//      mocked (importing the real @/lib/session pulls in @/auth's Node env, which
//      can't load under vitest). The mock re-implements requireAdmin / requireAal
//      / requireAuthRecency / StepUpRequiredError faithfully (pure, session-only),
//      so the AAL2 + non-recovered + auth-recency gate is genuinely exercised.
// ---------------------------------------------------------------------------

// --- Pure guardrail layer -----------------------------------------------------

import {
  RECOVERY_WEAKEN_DELAY_MS,
  planRecoveryWeightWrite,
  planThresholdWrite,
  soloBlockError,
  validateRecoveryWeightBounds,
  validateThresholdBounds,
} from "@/lib/recovery-config-guardrails";

describe("recovery-config guardrails (pure)", () => {
  it("rejects out-of-bounds recovery weights, accepts the edges", () => {
    expect(validateRecoveryWeightBounds(101)).not.toBeNull();
    expect(validateRecoveryWeightBounds(-1)).not.toBeNull();
    expect(validateRecoveryWeightBounds(1.5)).not.toBeNull();
    expect(validateRecoveryWeightBounds(0)).toBeNull();
    expect(validateRecoveryWeightBounds(100)).toBeNull();
  });

  it("rejects out-of-bounds thresholds, accepts the edges", () => {
    expect(validateThresholdBounds(99)).not.toBeNull();
    expect(validateThresholdBounds(1001)).not.toBeNull();
    expect(validateThresholdBounds(100)).toBeNull();
    expect(validateThresholdBounds(1000)).toBeNull();
  });

  it("solo-block: weight >= threshold needs allowSolo; tlsn seed (100==100, solo) stays valid", () => {
    expect(soloBlockError(100, 100, false)).not.toBeNull();
    expect(soloBlockError(100, 100, true)).toBeNull(); // the tlsn case
    expect(soloBlockError(100, 101, false)).toBeNull(); // below threshold
    expect(soloBlockError(99, 100, false)).toBeNull();
  });

  it("weight INCREASE schedules pending +72h and leaves live untouched", () => {
    const now = 1_000_000;
    const plan = planRecoveryWeightWrite(20, 40, now);
    expect(plan.kind).toBe("scheduled");
    if (plan.kind !== "scheduled") throw new Error("unreachable");
    expect(plan.pendingRecoveryWeight).toBe(40);
    expect(plan.recoveryEffectiveAt.getTime()).toBe(now + RECOVERY_WEAKEN_DELAY_MS);
    expect(RECOVERY_WEAKEN_DELAY_MS).toBe(72 * 60 * 60 * 1000);
  });

  it("weight DECREASE (and no-op equal) applies immediately and clears pending", () => {
    const dec = planRecoveryWeightWrite(20, 10, 0);
    expect(dec.kind).toBe("immediate");
    if (dec.kind !== "immediate") throw new Error("unreachable");
    expect(dec.recoveryWeight).toBe(10);
    expect(dec.pendingRecoveryWeight).toBeNull();
    expect(dec.recoveryEffectiveAt).toBeNull();

    const eq = planRecoveryWeightWrite(20, 20, 0);
    expect(eq.kind).toBe("immediate");
  });

  it("threshold INCREASE immediate, threshold DECREASE scheduled", () => {
    const now = 5_000;
    const up = planThresholdWrite(100, 200, now);
    expect(up.kind).toBe("immediate");
    if (up.kind !== "immediate") throw new Error("unreachable");
    expect(up.threshold).toBe(200);
    expect(up.pendingThreshold).toBeNull();

    const down = planThresholdWrite(200, 150, now);
    expect(down.kind).toBe("scheduled");
    if (down.kind !== "scheduled") throw new Error("unreachable");
    expect(down.pendingThreshold).toBe(150);
    expect(down.thresholdEffectiveAt.getTime()).toBe(now + RECOVERY_WEAKEN_DELAY_MS);
  });
});

// --- Action layer -------------------------------------------------------------

const h = vi.hoisted(() => {
  class StepUpRequiredError extends Error {
    readonly requiredAal: number;
    readonly currentAal: number;
    constructor(requiredAal: number, currentAal: number) {
      super(`Step-up required: needs AAL${requiredAal} (session is AAL${currentAal})`);
      this.name = "StepUpRequiredError";
      this.requiredAal = requiredAal;
      this.currentAal = currentAal;
    }
  }
  return {
    StepUpRequiredError,
    state: { session: null as Session | null },
    sendMail: vi.fn(async () => {}),
    audit: vi.fn(async () => {}),
    db: {
      badgeWeight: {
        findUnique: vi.fn((_a?: unknown): Promise<unknown> => Promise.resolve(null)),
        update: vi.fn((_a?: unknown): Promise<unknown> => Promise.resolve({})),
        findMany: vi.fn((_a?: unknown): Promise<unknown[]> => Promise.resolve([])),
      },
      recoveryConfig: {
        findUnique: vi.fn((_a?: unknown): Promise<unknown> => Promise.resolve(null)),
        update: vi.fn((_a?: unknown): Promise<unknown> => Promise.resolve({})),
      },
      user: {
        findMany: vi.fn((_a?: unknown): Promise<unknown[]> => Promise.resolve([])),
      },
    },
  };
});

// Read the `data` object of the first call made to a mocked prisma write.
function firstCallData(fn: { mock: { calls: unknown[][] } }): Record<string, unknown> {
  const call = fn.mock.calls[0];
  if (!call) throw new Error("expected a mutation call");
  return (call[0] as { data: Record<string, unknown> }).data;
}

vi.mock("@/lib/session", () => ({
  StepUpRequiredError: h.StepUpRequiredError,
  requireAdmin: async () => {
    if (!h.state.session?.user?.id) throw new Error("Not an admin");
    return h.state.session;
  },
  requireAal: (s: { aal?: number } | null, floor: number) => {
    const current = s?.aal ?? 0;
    if (current < floor) throw new h.StepUpRequiredError(floor, current);
  },
  requireAuthRecency: (s: { auth_time?: number; aal?: number } | null, maxAgeSecs: number) => {
    const authTime = s?.auth_time;
    const nowSecs = Math.floor(Date.now() / 1000);
    if (typeof authTime !== "number" || nowSecs - authTime > maxAgeSecs) {
      throw new h.StepUpRequiredError(2, s?.aal ?? 0);
    }
  },
}));

vi.mock("@/lib/mailer", () => ({ sendMail: h.sendMail }));
vi.mock("@/lib/audit", () => ({ audit: h.audit }));
vi.mock("@/lib/prisma", () => ({ prisma: h.db }));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));

import {
  setAllowSoloRecovery,
  updateRecoveryThreshold,
  updateRecoveryWeight,
} from "@/server/recovery-config-actions";

const db = h.db;

function freshAdmin(): Session {
  return {
    user: { id: "admin1" },
    aal: 2,
    auth_time: Math.floor(Date.now() / 1000) - 10,
    expires: new Date(Date.now() + 3_600_000).toISOString(),
  } as unknown as Session;
}

beforeEach(() => {
  vi.clearAllMocks();
  h.state.session = freshAdmin();
  db.badgeWeight.findMany.mockResolvedValue([]);
  db.user.findMany.mockResolvedValue([{ email: "a@example.com" }, { email: "b@example.com" }]);
  db.recoveryConfig.findUnique.mockResolvedValue({ threshold: 100, pendingThreshold: null });
});

describe("updateRecoveryWeight — gate", () => {
  it("stale auth_time returns the step-up contract, does not mutate", async () => {
    h.state.session = {
      ...freshAdmin(),
      auth_time: Math.floor(Date.now() / 1000) - 10_000,
    } as unknown as Session;
    db.badgeWeight.findUnique.mockResolvedValue({
      recoveryWeight: 20,
      pendingRecoveryWeight: null,
      recoveryEffectiveAt: null,
      allowSoloRecovery: false,
    });

    const res = await updateRecoveryWeight({
      badgeType: "oauth-account",
      qualifier: "github",
      recoveryWeight: 15,
    });
    expect(res).toEqual({ ok: false, stepUp: true, requiredAal: 2 });
    expect(db.badgeWeight.update).not.toHaveBeenCalled();
  });

  it("absent auth_time fails closed to step-up", async () => {
    h.state.session = { user: { id: "admin1" }, aal: 2 } as unknown as Session;
    const res = await updateRecoveryWeight({
      badgeType: "oauth-account",
      qualifier: "github",
      recoveryWeight: 15,
    });
    expect(res).toEqual({ ok: false, stepUp: true, requiredAal: 2 });
  });

  it("AAL below 2 returns step-up", async () => {
    h.state.session = { ...freshAdmin(), aal: 1 } as unknown as Session;
    const res = await updateRecoveryWeight({
      badgeType: "oauth-account",
      qualifier: "github",
      recoveryWeight: 15,
    });
    expect(res).toEqual({ ok: false, stepUp: true, requiredAal: 2 });
  });

  it("a recovered session is rejected (not a step-up)", async () => {
    h.state.session = { ...freshAdmin(), recovered: true } as unknown as Session;
    const res = await updateRecoveryWeight({
      badgeType: "oauth-account",
      qualifier: "github",
      recoveryWeight: 15,
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect("stepUp" in res && res.stepUp).toBeFalsy();
    if (!("error" in res)) throw new Error("expected a presentable error");
    expect(res.error).toMatch(/recovered/i);
  });
});

describe("updateRecoveryWeight — guardrails + asymmetric timing", () => {
  function eligibleRow(
    over: Partial<{
      recoveryWeight: number;
      pendingRecoveryWeight: number | null;
      recoveryEffectiveAt: Date | null;
      allowSoloRecovery: boolean;
    }> = {},
  ) {
    db.badgeWeight.findUnique.mockResolvedValue({
      recoveryWeight: 20,
      pendingRecoveryWeight: null,
      recoveryEffectiveAt: null,
      allowSoloRecovery: false,
      ...over,
    });
  }

  it("rejects an ineligible type outright", async () => {
    const res = await updateRecoveryWeight({
      badgeType: "invite-code",
      qualifier: "*",
      recoveryWeight: 10,
    });
    expect(res.ok).toBe(false);
    expect(db.badgeWeight.update).not.toHaveBeenCalled();
  });

  it("rejects weight 101 (out of bounds) before mutating", async () => {
    eligibleRow();
    const res = await updateRecoveryWeight({
      badgeType: "email-domain",
      qualifier: "*",
      recoveryWeight: 101,
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    if (!("error" in res)) throw new Error("expected a presentable error");
    expect(res.error).toMatch(/between 0 and 100/);
    expect(db.badgeWeight.update).not.toHaveBeenCalled();
  });

  it("solo-block: weight 100 with threshold 100 rejected without allowSolo", async () => {
    eligibleRow({ recoveryWeight: 15, allowSoloRecovery: false });
    db.recoveryConfig.findUnique.mockResolvedValue({ threshold: 100, pendingThreshold: null });
    const res = await updateRecoveryWeight({
      badgeType: "email-domain",
      qualifier: "*",
      recoveryWeight: 100,
    });
    expect(res.ok).toBe(false);
    expect(db.badgeWeight.update).not.toHaveBeenCalled();
  });

  it("solo-block: weight 100 with threshold 100 allowed WITH allowSolo (tlsn seed stays valid)", async () => {
    eligibleRow({ recoveryWeight: 100, allowSoloRecovery: true });
    db.recoveryConfig.findUnique.mockResolvedValue({ threshold: 100, pendingThreshold: null });
    const res = await updateRecoveryWeight({
      badgeType: "tlsn-attestation",
      qualifier: "*",
      recoveryWeight: 100,
    });
    expect(res.ok).toBe(true);
    expect(db.badgeWeight.update).toHaveBeenCalledTimes(1);
  });

  it("weight INCREASE writes pending+effectiveAt and leaves live unchanged", async () => {
    eligibleRow({ recoveryWeight: 20 });
    const res = await updateRecoveryWeight({
      badgeType: "oauth-account",
      qualifier: "github",
      recoveryWeight: 40,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("unreachable");
    expect(res.data.effectiveAt).toEqual(expect.any(String));
    const data = firstCallData(db.badgeWeight.update);
    expect(data.pendingRecoveryWeight).toBe(40);
    expect(data.recoveryEffectiveAt).toBeInstanceOf(Date);
    expect("recoveryWeight" in data).toBe(false); // live left untouched
  });

  it("weight DECREASE writes live and clears pending", async () => {
    eligibleRow({ recoveryWeight: 20 });
    const res = await updateRecoveryWeight({
      badgeType: "oauth-account",
      qualifier: "github",
      recoveryWeight: 10,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("unreachable");
    expect(res.data.effectiveAt).toBeNull();
    const data = firstCallData(db.badgeWeight.update);
    expect(data.recoveryWeight).toBe(10);
    expect(data.pendingRecoveryWeight).toBeNull();
    expect(data.recoveryEffectiveAt).toBeNull();
  });

  it("a defensive edit clears a prior pending weakening on the row", async () => {
    eligibleRow({
      recoveryWeight: 20,
      pendingRecoveryWeight: 40,
      recoveryEffectiveAt: new Date(Date.now() + 1000),
    });
    const res = await updateRecoveryWeight({
      badgeType: "oauth-account",
      qualifier: "github",
      recoveryWeight: 15,
    });
    expect(res.ok).toBe(true);
    const data = firstCallData(db.badgeWeight.update);
    expect(data.recoveryWeight).toBe(15);
    expect(data.pendingRecoveryWeight).toBeNull();
    expect(data.recoveryEffectiveAt).toBeNull();
  });

  it("broadcasts to every admin and audits with before/after", async () => {
    eligibleRow({ recoveryWeight: 20 });
    await updateRecoveryWeight({
      badgeType: "oauth-account",
      qualifier: "github",
      recoveryWeight: 10,
    });
    expect(h.sendMail).toHaveBeenCalledTimes(2); // one per admin
    expect(h.audit).toHaveBeenCalledWith(
      "admin1",
      "admin.recovery_config.updated",
      expect.objectContaining({
        field: "recoveryWeight:oauth-account:github",
        before: 20,
        after: 10,
      }),
    );
  });

  it("a mail failure does NOT roll back the committed change", async () => {
    eligibleRow({ recoveryWeight: 20 });
    h.sendMail.mockRejectedValueOnce(new Error("smtp down"));
    const res = await updateRecoveryWeight({
      badgeType: "oauth-account",
      qualifier: "github",
      recoveryWeight: 10,
    });
    expect(res.ok).toBe(true);
    expect(db.badgeWeight.update).toHaveBeenCalledTimes(1);
  });
});

describe("updateRecoveryThreshold — asymmetric timing + invariant", () => {
  it("rejects threshold 99 and 1001", async () => {
    expect((await updateRecoveryThreshold({ threshold: 99 })).ok).toBe(false);
    expect((await updateRecoveryThreshold({ threshold: 1001 })).ok).toBe(false);
    expect(db.recoveryConfig.update).not.toHaveBeenCalled();
  });

  it("threshold INCREASE applies immediately and clears pending", async () => {
    db.recoveryConfig.findUnique.mockResolvedValue({ threshold: 100, pendingThreshold: null });
    db.badgeWeight.findMany.mockResolvedValue([
      {
        badgeType: "email-domain",
        qualifier: "*",
        recoveryWeight: 15,
        pendingRecoveryWeight: null,
      },
    ]);
    const res = await updateRecoveryThreshold({ threshold: 200 });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("unreachable");
    expect(res.data.effectiveAt).toBeNull();
    const data = firstCallData(db.recoveryConfig.update);
    expect(data.threshold).toBe(200);
    expect(data.pendingThreshold).toBeNull();
    expect(data.thresholdEffectiveAt).toBeNull();
  });

  it("threshold DECREASE is scheduled 72h out, leaves live threshold", async () => {
    db.recoveryConfig.findUnique.mockResolvedValue({ threshold: 200, pendingThreshold: null });
    db.badgeWeight.findMany.mockResolvedValue([
      {
        badgeType: "email-domain",
        qualifier: "*",
        recoveryWeight: 15,
        pendingRecoveryWeight: null,
      },
    ]);
    const res = await updateRecoveryThreshold({ threshold: 150 });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("unreachable");
    expect(res.data.effectiveAt).toEqual(expect.any(String));
    const data = firstCallData(db.recoveryConfig.update);
    expect(data.pendingThreshold).toBe(150);
    expect(data.thresholdEffectiveAt).toBeInstanceOf(Date);
    expect("threshold" in data).toBe(false);
  });

  it("rejects a threshold decrease that would let a non-solo row solo-recover", async () => {
    db.recoveryConfig.findUnique.mockResolvedValue({ threshold: 1000, pendingThreshold: null });
    db.badgeWeight.findMany.mockResolvedValue([
      {
        badgeType: "residency-state",
        qualifier: "*",
        recoveryWeight: 60,
        pendingRecoveryWeight: null,
      },
    ]);
    const res = await updateRecoveryThreshold({ threshold: 60 });
    expect(res.ok).toBe(false);
    expect(db.recoveryConfig.update).not.toHaveBeenCalled();
  });
});

describe("setAllowSoloRecovery", () => {
  it("turning solo OFF is rejected while the row's weight meets the threshold", async () => {
    db.badgeWeight.findUnique.mockResolvedValue({
      allowSoloRecovery: true,
      recoveryWeight: 100,
      pendingRecoveryWeight: null,
    });
    db.recoveryConfig.findUnique.mockResolvedValue({ threshold: 100, pendingThreshold: null });
    const res = await setAllowSoloRecovery({
      badgeType: "tlsn-attestation",
      qualifier: "*",
      allowSoloRecovery: false,
    });
    expect(res.ok).toBe(false);
    expect(db.badgeWeight.update).not.toHaveBeenCalled();
  });

  it("turning solo ON applies immediately, audits, and broadcasts", async () => {
    db.badgeWeight.findUnique.mockResolvedValue({
      allowSoloRecovery: false,
      recoveryWeight: 15,
      pendingRecoveryWeight: null,
    });
    const res = await setAllowSoloRecovery({
      badgeType: "email-domain",
      qualifier: "*",
      allowSoloRecovery: true,
    });
    expect(res.ok).toBe(true);
    expect(db.badgeWeight.update).toHaveBeenCalledTimes(1);
    expect(h.sendMail).toHaveBeenCalledTimes(2);
    expect(h.audit).toHaveBeenCalledWith(
      "admin1",
      "admin.recovery_config.updated",
      expect.objectContaining({
        field: "allowSoloRecovery:email-domain:*",
        before: false,
        after: true,
      }),
    );
  });
});
