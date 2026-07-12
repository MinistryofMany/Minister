import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Session } from "next-auth";

// ---------------------------------------------------------------------------
// Unit tests for the merge-ceremony POLICY gates (AAL floor, recovered-session
// refusal, and the H-1 quarantine gate), mirroring credential-actions.test.ts:
// Prisma, the mailer, merge surgery, and the proof helpers are mocked; the
// REAL quarantine gate (credential-gate + credential-lifecycle) runs against
// the mocked prisma client, so the enforcement itself is what's exercised.
// ---------------------------------------------------------------------------

const h = vi.hoisted(() => ({
  state: { currentSession: null as unknown },
  sendMail: vi.fn(async () => {}),
  audit: vi.fn(async () => {}),
  mergeAccounts: vi.fn(),
  issueDonorProof: vi.fn(async () => "proof-ticket"),
  verifyDonorProof: vi.fn(),
  db: {
    userEmail: { findUnique: vi.fn(), findMany: vi.fn() },
    user: { findUnique: vi.fn() },
    authenticator: { findMany: vi.fn() },
    verificationToken: { create: vi.fn(async () => ({})), deleteMany: vi.fn() },
  },
}));

vi.mock("@/lib/session", () => ({
  getCurrentSession: vi.fn(async () => h.state.currentSession),
}));
vi.mock("@/lib/prisma", () => ({ prisma: h.db }));
vi.mock("@/lib/mailer", () => ({ sendMail: h.sendMail }));
vi.mock("@/lib/audit", () => ({ audit: h.audit }));
vi.mock("@/lib/merge", () => ({ mergeAccounts: h.mergeAccounts }));
vi.mock("@/lib/merge-proof", () => ({
  issueDonorProof: h.issueDonorProof,
  verifyDonorProof: h.verifyDonorProof,
}));
// The per-IP limiter and header plumbing are out of scope here.
vi.mock("@/lib/rate-limit", () => ({
  clientIpFrom: () => "test-ip",
  createRateLimiter: () => ({ check: () => ({ allowed: true, retryAfterSeconds: 0 }) }),
}));
vi.mock("next/headers", () => ({ headers: vi.fn(async () => new Headers()) }));

import { confirmMerge, startMerge } from "./merge-actions";

const SURVIVOR = "user_survivor";
const DONOR = "user_donor";

function session(aal: 0 | 1 | 2, opts: { recovered?: boolean; cred?: string } = {}): Session {
  return {
    user: { id: SURVIVOR },
    aal,
    ...(opts.recovered ? { recovered: true } : {}),
    ...(opts.cred !== undefined ? { cred: opts.cred } : {}),
    expires: new Date(Date.now() + 3600_000).toISOString(),
  } as Session;
}

function setSession(s: Session | null): void {
  h.state.currentSession = s;
}

function activePasskey(credentialID = "cred_orig") {
  return { credentialID, status: "active", quarantinedUntil: null };
}
function quarantinedPasskey(credentialID = "cred_graft", msFromNow = 3_600_000) {
  return {
    credentialID,
    status: "quarantined",
    quarantinedUntil: new Date(Date.now() + msFromNow),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  setSession(null);
  h.db.verificationToken.create.mockResolvedValue({});
});

// ---------------------------------------------------------------------------
// startMerge
// ---------------------------------------------------------------------------

describe("startMerge gates", () => {
  function armEligibleDonor() {
    h.db.userEmail.findUnique.mockResolvedValue({
      verifiedAt: new Date(),
      user: { id: DONOR, isBanned: false, mergedIntoUserId: null },
    });
  }

  it("returns a typed stepUp result below AAL2 (never a throw)", async () => {
    setSession(session(1));
    const r = await startMerge("donor@example.com");
    expect(r.ok).toBe(false);
    expect(r.stepUp).toBe(true);
    expect(h.db.authenticator.findMany).not.toHaveBeenCalled();
    expect(h.sendMail).not.toHaveBeenCalled();
  });

  it("refuses a recovered session at AAL2", async () => {
    setSession(session(2, { recovered: true }));
    const r = await startMerge("donor@example.com");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/recovered session/i);
    expect(h.sendMail).not.toHaveBeenCalled();
  });

  it("ATTACK: refuses when the survivor's only passkey is quarantined — no donor link is minted", async () => {
    setSession(session(2, { cred: "cred_graft" }));
    h.db.authenticator.findMany.mockResolvedValue([quarantinedPasskey("cred_graft")]);
    armEligibleDonor();

    const r = await startMerge("donor@example.com");
    expect(r.ok).toBe(false);
    expect(r.quarantine?.reason).toBe("no-active-passkey");
    expect(r.error).toMatch(/unlocks in about/i);
    expect(h.db.verificationToken.create).not.toHaveBeenCalled();
    expect(h.sendMail).not.toHaveBeenCalled();
    expect(h.audit).toHaveBeenCalledWith(
      SURVIVOR,
      "credential.quarantine_refused",
      expect.objectContaining({ action: "merge.start" }),
    );
  });

  it("ATTACK: refuses a session riding the graft while the owner's active passkey exists (step-up clears it)", async () => {
    setSession(session(2, { cred: "cred_graft" }));
    h.db.authenticator.findMany.mockResolvedValue([
      activePasskey("cred_orig"),
      quarantinedPasskey("cred_graft"),
    ]);
    armEligibleDonor();

    const r = await startMerge("donor@example.com");
    expect(r.ok).toBe(false);
    expect(r.quarantine?.reason).toBe("acting-passkey-untrusted");
    expect(r.quarantine?.canStepUp).toBe(true);
    expect(h.sendMail).not.toHaveBeenCalled();
  });

  it("LEGIT: an established session (active acting passkey) starts the merge and mails the donor link", async () => {
    setSession(session(2, { cred: "cred_orig" }));
    h.db.authenticator.findMany.mockResolvedValue([
      activePasskey("cred_orig"),
      quarantinedPasskey("cred_graft"),
    ]);
    armEligibleDonor();

    const r = await startMerge("donor@example.com");
    expect(r).toEqual({ ok: true });
    expect(h.db.verificationToken.create).toHaveBeenCalledTimes(1);
    expect(h.sendMail).toHaveBeenCalledTimes(1);
    expect(h.audit).toHaveBeenCalledWith(
      SURVIVOR,
      "merge.link_requested",
      expect.objectContaining({ delivered: true }),
    );
  });

  it("LEGIT: time-based clearance — a lapsed window passes without any re-auth", async () => {
    setSession(session(2, { cred: "cred_new" }));
    h.db.authenticator.findMany.mockResolvedValue([quarantinedPasskey("cred_new", -1000)]);
    armEligibleDonor();

    const r = await startMerge("donor@example.com");
    expect(r).toEqual({ ok: true });
    expect(h.sendMail).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// confirmMerge
// ---------------------------------------------------------------------------

describe("confirmMerge gates", () => {
  function armMergeableAccounts() {
    h.verifyDonorProof.mockResolvedValue({ donorUserId: DONOR });
    h.db.user.findUnique.mockImplementation(
      async (args: { where: { id: string } }): Promise<Record<string, unknown> | null> => {
        if (args.where.id === SURVIVOR) return { mergedIntoUserId: null };
        if (args.where.id === DONOR) return { isBanned: false, mergedIntoUserId: null };
        return null;
      },
    );
    h.db.userEmail.findMany.mockResolvedValue([{ email: "owner@example.com" }]);
    h.mergeAccounts.mockResolvedValue({
      mergeRecordId: "mr_1",
      moved: { badges: 2 },
      overridesCreated: 1,
      strandedClients: [],
    });
  }

  it("returns a typed stepUp result below AAL2", async () => {
    setSession(session(1));
    const r = await confirmMerge("proof", DONOR);
    expect(r.ok).toBe(false);
    expect(r.stepUp).toBe(true);
    expect(h.verifyDonorProof).not.toHaveBeenCalled();
  });

  it("ATTACK: refuses an all-quarantined survivor and does NOT burn the single-use donor proof", async () => {
    setSession(session(2, { cred: "cred_graft" }));
    h.db.authenticator.findMany.mockResolvedValue([quarantinedPasskey("cred_graft")]);
    armMergeableAccounts();

    const r = await confirmMerge("proof", DONOR);
    expect(r.ok).toBe(false);
    expect(r.quarantine?.reason).toBe("no-active-passkey");
    // The gate must run BEFORE proof consumption: a refused user keeps their
    // ticket and can retry once the hold clears, instead of restarting the
    // whole ceremony.
    expect(h.verifyDonorProof).not.toHaveBeenCalled();
    expect(h.mergeAccounts).not.toHaveBeenCalled();
    expect(h.audit).toHaveBeenCalledWith(
      SURVIVOR,
      "credential.quarantine_refused",
      expect.objectContaining({ action: "merge.confirm" }),
    );
  });

  it("ATTACK: a merge STARTED before the graft can't be confirmed from the graft session (no laundering through a stale start)", async () => {
    // startMerge passed earlier under an active acting passkey; by confirm
    // time the session rides the quarantined graft. The confirm-time re-check
    // must refuse.
    setSession(session(2, { cred: "cred_graft" }));
    h.db.authenticator.findMany.mockResolvedValue([
      activePasskey("cred_orig"),
      quarantinedPasskey("cred_graft"),
    ]);
    armMergeableAccounts();

    const r = await confirmMerge("proof", DONOR);
    expect(r.ok).toBe(false);
    expect(r.quarantine?.reason).toBe("acting-passkey-untrusted");
    expect(r.quarantine?.canStepUp).toBe(true);
    expect(h.verifyDonorProof).not.toHaveBeenCalled();
    expect(h.mergeAccounts).not.toHaveBeenCalled();
  });

  it("LEGIT: an established survivor completes the merge and notifies every address", async () => {
    setSession(session(2, { cred: "cred_orig" }));
    h.db.authenticator.findMany.mockResolvedValue([activePasskey("cred_orig")]);
    armMergeableAccounts();

    const r = await confirmMerge("proof", DONOR);
    expect(r.ok).toBe(true);
    expect(r.moved).toEqual({ badges: 2 });
    expect(h.mergeAccounts).toHaveBeenCalledWith(SURVIVOR, DONOR);
    expect(h.sendMail).toHaveBeenCalledTimes(1);
  });

  it("still refuses a donor-proof/id mismatch after the gate passes", async () => {
    setSession(session(2, { cred: "cred_orig" }));
    h.db.authenticator.findMany.mockResolvedValue([activePasskey("cred_orig")]);
    armMergeableAccounts();
    h.verifyDonorProof.mockResolvedValue({ donorUserId: "someone_else" });

    const r = await confirmMerge("proof", DONOR);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/doesn't match/i);
    expect(h.mergeAccounts).not.toHaveBeenCalled();
  });
});
