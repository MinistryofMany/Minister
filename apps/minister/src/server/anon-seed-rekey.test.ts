import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Session } from "next-auth";

// Unit tests for rekeyAnonSeed's gates (identity plan, O-6). @/env, @/lib/session,
// @/lib/prisma, and @/lib/audit are mocked; the REAL H-1 quarantine gate runs
// against the mocked authenticator rows (same approach as recovery-code-actions).
// Every refusal must leave the enrollment untouched — a re-key is destructive.

const h = vi.hoisted(() => ({
  env: { ANON_IDENTITY_ENABLED: true as boolean },
  currentSession: null as unknown,
  audit: vi.fn(async () => {}),
  rateLimit: { check: vi.fn(() => ({ allowed: true, retryAfterSeconds: 0 })) },
  db: {
    authenticator: { findMany: vi.fn() },
    anonSeedEnrollment: { findUnique: vi.fn(), update: vi.fn() },
    anonSeedBlob: { deleteMany: vi.fn() },
    auditLog: { findFirst: vi.fn() },
    $transaction: vi.fn(async (ops: Promise<unknown>[]) => Promise.all(ops)),
  },
}));

vi.mock("@/env", () => ({ env: h.env }));
vi.mock("@/lib/audit", () => ({ audit: h.audit }));
vi.mock("@/lib/prisma", () => ({ prisma: h.db }));
vi.mock("@/lib/rate-limit", () => ({ anonSeedActionLimiter: h.rateLimit }));
vi.mock("@/lib/session", () => ({
  getCurrentSession: vi.fn(async () => h.currentSession),
  requireSession: vi.fn(async () => h.currentSession),
}));

import { rekeyAnonSeed } from "@/server/anon-seed-actions";

const USER = "user-123";
const PHRASE = "re-key my identity";

function session(opts: { aal?: 0 | 1 | 2; authAgeSecs?: number; cred?: string }): Session {
  const nowSecs = Math.floor(Date.now() / 1000);
  return {
    user: { id: USER },
    aal: opts.aal ?? 2,
    auth_time: nowSecs - (opts.authAgeSecs ?? 30),
    ...(opts.cred !== undefined ? { cred: opts.cred } : {}),
    expires: new Date(Date.now() + 3600_000).toISOString(),
  } as Session;
}

function activePasskey(credentialID = "cred_orig") {
  return { credentialID, status: "active", quarantinedUntil: null };
}
function quarantinedPasskey(credentialID = "cred_graft") {
  return {
    credentialID,
    status: "quarantined",
    quarantinedUntil: new Date(Date.now() + 3_600_000),
  };
}
function activeEnrollment(epoch = 1) {
  return {
    userId: USER,
    enrollmentEpoch: epoch,
    seedGeneratedAt: new Date(),
    backupConfirmedAt: new Date(),
  };
}

function expectNoMutation() {
  expect(h.db.anonSeedEnrollment.update).not.toHaveBeenCalled();
  expect(h.db.anonSeedBlob.deleteMany).not.toHaveBeenCalled();
}

beforeEach(() => {
  vi.clearAllMocks();
  h.env.ANON_IDENTITY_ENABLED = true;
  h.currentSession = session({ aal: 2, cred: "cred_orig" });
  h.rateLimit.check.mockReturnValue({ allowed: true, retryAfterSeconds: 0 });
  h.db.authenticator.findMany.mockResolvedValue([activePasskey("cred_orig")]);
  h.db.auditLog.findFirst.mockResolvedValue(null);
  h.db.anonSeedEnrollment.findUnique.mockResolvedValue(activeEnrollment(1));
  // The bump-and-purge UPDATE nulls both timestamps, so the returned row is back
  // to `none` at the incremented epoch — mirror that here.
  h.db.anonSeedEnrollment.update.mockResolvedValue({
    userId: USER,
    enrollmentEpoch: 2,
    seedGeneratedAt: null,
    backupConfirmedAt: null,
  });
  h.db.anonSeedBlob.deleteMany.mockResolvedValue({ count: 0 });
});

describe("rekeyAnonSeed gates", () => {
  it("is inert when the feature flag is off", async () => {
    h.env.ANON_IDENTITY_ENABLED = false;
    const r = await rekeyAnonSeed({ confirmPhrase: PHRASE });
    expect(r.ok).toBe(false);
    expectNoMutation();
  });

  it("refuses a signed-out caller", async () => {
    h.currentSession = null;
    const r = await rekeyAnonSeed({ confirmPhrase: PHRASE });
    expect(r).toEqual({ ok: false, error: "Not signed in." });
    expectNoMutation();
  });

  it("stepUp below AAL2", async () => {
    h.currentSession = session({ aal: 1, cred: "cred_orig" });
    const r = await rekeyAnonSeed({ confirmPhrase: PHRASE });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect("stepUp" in r && r.stepUp).toBe(true);
    expectNoMutation();
  });

  it("stepUp when the auth is older than 5 minutes (recency)", async () => {
    h.currentSession = session({ aal: 2, authAgeSecs: 600, cred: "cred_orig" });
    const r = await rekeyAnonSeed({ confirmPhrase: PHRASE });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect("stepUp" in r && r.stepUp).toBe(true);
    expect(r.error).toMatch(/5 minutes/i);
    expectNoMutation();
  });

  it("refuses the wrong confirmation phrase", async () => {
    const r = await rekeyAnonSeed({ confirmPhrase: "nope" });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect(r.error).toMatch(/re-key my identity/i);
    expectNoMutation();
  });

  it("ATTACK: refuses when the acting credential is still quarantined (H-1)", async () => {
    h.currentSession = session({ aal: 2, cred: "cred_graft" });
    h.db.authenticator.findMany.mockResolvedValue([quarantinedPasskey("cred_graft")]);
    const r = await rekeyAnonSeed({ confirmPhrase: PHRASE });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect("quarantine" in r && r.quarantine).toBeTruthy();
    expectNoMutation();
    expect(h.audit).toHaveBeenCalledWith(
      USER,
      "credential.quarantine_refused",
      expect.objectContaining({ action: "anon-seed.rekey" }),
    );
  });

  it("enforces the cooldown when a recent re-key exists", async () => {
    h.db.auditLog.findFirst.mockResolvedValue({ createdAt: new Date() });
    const r = await rekeyAnonSeed({ confirmPhrase: PHRASE });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect(r.error).toMatch(/once a week/i);
    expect("retryAt" in r && r.retryAt).toBeTruthy();
    expectNoMutation();
  });

  it("refuses when there is no active Private Identity to re-key", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue({
      ...activeEnrollment(1),
      backupConfirmedAt: null,
    });
    const r = await rekeyAnonSeed({ confirmPhrase: PHRASE });
    expect(r.ok).toBe(false);
    expectNoMutation();
  });

  it("LEGIT: passes every gate, bumps the epoch, purges blobs, and audits", async () => {
    const r = await rekeyAnonSeed({ confirmPhrase: PHRASE });
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error("expected success");
    expect(r.state.enrollmentEpoch).toBe(2);
    expect(r.state.status).toBe("none");
    expect(h.db.anonSeedEnrollment.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { userId: USER },
        data: expect.objectContaining({ enrollmentEpoch: { increment: 1 } }),
      }),
    );
    expect(h.db.anonSeedBlob.deleteMany).toHaveBeenCalledWith({ where: { userId: USER } });
    expect(h.audit).toHaveBeenCalledWith(
      USER,
      "anon_seed.rekey",
      expect.objectContaining({ enrollmentEpoch: 2 }),
    );
  });
});
