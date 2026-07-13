import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Session } from "next-auth";

// ---------------------------------------------------------------------------
// Unit tests for generateMyRecoveryCodes' gates: the AAL2 floor (as a typed
// stepUp result, not a throw) and the H-1 quarantine gate. Minting recovery
// codes is the persistence pivot a grafted passkey wants — a code re-enters
// the account after the graft is discovered and removed — so a session held
// up only by a still-quarantined passkey must be refused. The REAL gate runs
// against the mocked prisma client; @/auth is mocked (it can't load under
// vitest) but the redeem path that uses it is not under test here.
// ---------------------------------------------------------------------------

const h = vi.hoisted(() => ({
  state: { currentSession: null as unknown },
  audit: vi.fn(async () => {}),
  notifyCredentialChange: vi.fn(async () => {}),
  generateRecoveryCodes: vi.fn(async () => ["code-1", "code-2"]),
  redeemRecoveryCode: vi.fn(),
  issueRecoveryTicket: vi.fn(),
  signIn: vi.fn(),
  db: {
    authenticator: { findMany: vi.fn() },
    userEmail: { findUnique: vi.fn() },
    user: { findFirst: vi.fn() },
  },
}));

vi.mock("@/auth", () => ({ signIn: h.signIn }));
vi.mock("@/lib/session", () => ({
  getCurrentSession: vi.fn(async () => h.state.currentSession),
}));
vi.mock("@/lib/prisma", () => ({ prisma: h.db }));
vi.mock("@/lib/audit", () => ({ audit: h.audit }));
vi.mock("@/lib/credential-notify", () => ({ notifyCredentialChange: h.notifyCredentialChange }));
vi.mock("@/lib/recovery-codes", () => ({
  generateRecoveryCodes: h.generateRecoveryCodes,
  redeemRecoveryCode: h.redeemRecoveryCode,
}));
vi.mock("@/lib/recovery-ticket", () => ({ issueRecoveryTicket: h.issueRecoveryTicket }));
vi.mock("@/lib/rate-limit", () => ({
  clientIpFrom: () => "test-ip",
  createRateLimiter: () => ({ check: () => ({ allowed: true, retryAfterSeconds: 0 }) }),
}));
vi.mock("next/headers", () => ({ headers: vi.fn(async () => new Headers()) }));

import { generateMyRecoveryCodes } from "./recovery-code-actions";

const USER = "user_1";

function session(aal: 0 | 1 | 2, opts: { cred?: string } = {}): Session {
  return {
    user: { id: USER },
    aal,
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
  h.generateRecoveryCodes.mockResolvedValue(["code-1", "code-2"]);
});

describe("generateMyRecoveryCodes gates", () => {
  it("returns a typed 'Not signed in' failure without a session", async () => {
    const r = await generateMyRecoveryCodes();
    expect(r).toEqual({ ok: false, error: "Not signed in" });
  });

  it("returns a typed stepUp result below AAL2 (never a throw — prod scrubs thrown messages)", async () => {
    setSession(session(1));
    const r = await generateMyRecoveryCodes();
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected a refusal");
    expect(r.stepUp).toBe(true);
    expect(r.error).toMatch(/passkey/i);
    expect(h.generateRecoveryCodes).not.toHaveBeenCalled();
  });

  it("ATTACK: refuses when the user's only passkey is still quarantined — no codes are minted", async () => {
    setSession(session(2, { cred: "cred_graft" }));
    h.db.authenticator.findMany.mockResolvedValue([quarantinedPasskey("cred_graft")]);

    const r = await generateMyRecoveryCodes();
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected a refusal");
    if (r.stepUp) throw new Error("expected quarantine refusal, got stepUp");
    expect(r.quarantine?.reason).toBe("no-active-passkey");
    expect(r.quarantine?.retryAt).not.toBeNull();
    expect(r.error).toMatch(/unlocks in about/i);
    expect(h.generateRecoveryCodes).not.toHaveBeenCalled();
    expect(h.notifyCredentialChange).not.toHaveBeenCalled();
    expect(h.audit).toHaveBeenCalledWith(
      USER,
      "credential.quarantine_refused",
      expect.objectContaining({ action: "recovery-codes.generate" }),
    );
  });

  it("ATTACK: refuses a session riding the graft while an established passkey exists (re-auth clears it)", async () => {
    setSession(session(2, { cred: "cred_graft" }));
    h.db.authenticator.findMany.mockResolvedValue([
      activePasskey("cred_orig"),
      quarantinedPasskey("cred_graft"),
    ]);

    const r = await generateMyRecoveryCodes();
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected a refusal");
    if (r.stepUp) throw new Error("expected quarantine refusal, got stepUp");
    expect(r.quarantine?.reason).toBe("acting-passkey-untrusted");
    expect(r.quarantine?.canStepUp).toBe(true);
    expect(h.generateRecoveryCodes).not.toHaveBeenCalled();
  });

  it("LEGIT: an established session mints codes and notifies every verified address", async () => {
    setSession(session(2, { cred: "cred_orig" }));
    h.db.authenticator.findMany.mockResolvedValue([
      activePasskey("cred_orig"),
      quarantinedPasskey("cred_graft"),
    ]);

    const r = await generateMyRecoveryCodes();
    expect(r).toEqual({ ok: true, codes: ["code-1", "code-2"] });
    expect(h.generateRecoveryCodes).toHaveBeenCalledWith(USER);
    expect(h.notifyCredentialChange).toHaveBeenCalledWith(USER, "recovery codes regenerated");
  });

  it("LEGIT: the freshly-recovered flow is not dead-ended — a bootstrap (active) passkey mints codes immediately", async () => {
    // Recovery lands AAL1+recovered; the user bootstraps a FIRST passkey,
    // which is active by design (no quarantine on the bootstrap), signs in
    // with it (AAL2, recovered cleared), and regenerates codes right away.
    setSession(session(2, { cred: "cred_bootstrap" }));
    h.db.authenticator.findMany.mockResolvedValue([activePasskey("cred_bootstrap")]);

    const r = await generateMyRecoveryCodes();
    expect(r.ok).toBe(true);
  });

  it("LEGIT: time-based clearance — a lapsed quarantine window mints codes without re-auth", async () => {
    setSession(session(2, { cred: "cred_new" }));
    h.db.authenticator.findMany.mockResolvedValue([quarantinedPasskey("cred_new", -1000)]);

    const r = await generateMyRecoveryCodes();
    expect(r.ok).toBe(true);
  });
});
