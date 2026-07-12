import { describe, expect, it } from "vitest";

import { CREDENTIAL_QUARANTINE_MS } from "@/lib/assurance";
import {
  describeRemaining,
  effectiveCredentialStatus,
  evaluatePrivilegedGate,
  lifecycleForNewPasskey,
  PrivilegedActionQuarantineError,
  type GatePasskeyRow,
} from "@/lib/credential-lifecycle";

const NOW = Date.parse("2026-07-12T12:00:00.000Z");
const HOUR = 60 * 60 * 1000;

function active(credentialID: string): GatePasskeyRow {
  return { credentialID, status: "active", quarantinedUntil: null };
}

function quarantined(credentialID: string, untilOffsetMs: number | null): GatePasskeyRow {
  return {
    credentialID,
    status: "quarantined",
    quarantinedUntil: untilOffsetMs === null ? null : new Date(NOW + untilOffsetMs),
  };
}

// ---------------------------------------------------------------------------
// effectiveCredentialStatus — lazy expiry.
// ---------------------------------------------------------------------------

describe("effectiveCredentialStatus", () => {
  it("active stays active", () => {
    expect(effectiveCredentialStatus("active", null, NOW)).toBe("active");
  });

  it("unknown statuses default to active (the column default)", () => {
    expect(effectiveCredentialStatus("garbage", null, NOW)).toBe("active");
  });

  it("in-window quarantine reads quarantined", () => {
    expect(effectiveCredentialStatus("quarantined", new Date(NOW + HOUR), NOW)).toBe("quarantined");
  });

  it("lapsed-window quarantine reads active (lazy expiry)", () => {
    expect(effectiveCredentialStatus("quarantined", new Date(NOW - 1), NOW)).toBe("active");
  });

  it("a window expiring exactly now reads active", () => {
    expect(effectiveCredentialStatus("quarantined", new Date(NOW), NOW)).toBe("active");
  });

  it("quarantined with no window never lapses", () => {
    expect(effectiveCredentialStatus("quarantined", null, NOW)).toBe("quarantined");
  });
});

// ---------------------------------------------------------------------------
// lifecycleForNewPasskey — write-time stamping rule.
// ---------------------------------------------------------------------------

describe("lifecycleForNewPasskey", () => {
  it("first passkey bootstraps active (DESIGNDECISIONS #4)", () => {
    expect(lifecycleForNewPasskey(0, NOW)).toEqual({ status: "active", quarantinedUntil: null });
  });

  it("every subsequent passkey is quarantined for the full window", () => {
    const r = lifecycleForNewPasskey(1, NOW);
    expect(r.status).toBe("quarantined");
    expect(r.quarantinedUntil?.getTime()).toBe(NOW + CREDENTIAL_QUARANTINE_MS);
  });
});

// ---------------------------------------------------------------------------
// describeRemaining — coarse human durations.
// ---------------------------------------------------------------------------

describe("describeRemaining", () => {
  it("sub-90-minutes reads as about an hour", () => {
    expect(describeRemaining(NOW + 20 * 60 * 1000, NOW)).toBe("about an hour");
    expect(describeRemaining(NOW + 89 * 60 * 1000, NOW)).toBe("about an hour");
  });

  it("hours round up", () => {
    expect(describeRemaining(NOW + 2.5 * HOUR, NOW)).toBe("about 3 hours");
    expect(describeRemaining(NOW + 47 * HOUR, NOW)).toBe("about 47 hours");
  });

  it("48h+ reads in days, rounded up", () => {
    expect(describeRemaining(NOW + 49 * HOUR, NOW)).toBe("about 3 days");
    expect(describeRemaining(NOW + CREDENTIAL_QUARANTINE_MS, NOW)).toBe("about 3 days");
  });

  it("elapsed reads as moments (never a negative promise)", () => {
    expect(describeRemaining(NOW - 1, NOW)).toBe("moments");
  });
});

// ---------------------------------------------------------------------------
// evaluatePrivilegedGate — the H-1 policy matrix.
// ---------------------------------------------------------------------------

describe("evaluatePrivilegedGate", () => {
  it("allows a user with an active passkey and no cred claim (legacy session)", () => {
    expect(evaluatePrivilegedGate([active("a")], undefined, NOW)).toBeNull();
  });

  it("allows a session acting with its active passkey", () => {
    expect(evaluatePrivilegedGate([active("a"), quarantined("b", HOUR)], "a", NOW)).toBeNull();
  });

  it("ATTACK: refuses when every passkey is quarantined (graft-only account state)", () => {
    const r = evaluatePrivilegedGate([quarantined("b", 5 * HOUR)], "b", NOW);
    expect(r).not.toBeNull();
    expect(r!.reason).toBe("no-active-passkey");
    // No established passkey exists, so a re-auth ceremony can't clear it.
    expect(r!.canStepUp).toBe(false);
    expect(r!.retryAt).toBe(new Date(NOW + 5 * HOUR).toISOString());
    expect(r!.message).toContain("unlocks in about 5 hours");
  });

  it("refuses the all-quarantined state regardless of the cred claim", () => {
    const r = evaluatePrivilegedGate([quarantined("b", HOUR)], undefined, NOW);
    expect(r?.reason).toBe("no-active-passkey");
  });

  it("picks the EARLIEST lapsing window as retryAt when several are quarantined", () => {
    const r = evaluatePrivilegedGate(
      [quarantined("b", 5 * HOUR), quarantined("c", 2 * HOUR)],
      undefined,
      NOW,
    );
    expect(r!.retryAt).toBe(new Date(NOW + 2 * HOUR).toISOString());
  });

  it("ATTACK: refuses a session riding the quarantined graft even though an active passkey exists", () => {
    const r = evaluatePrivilegedGate([active("a"), quarantined("b", 3 * HOUR)], "b", NOW);
    expect(r).not.toBeNull();
    expect(r!.reason).toBe("acting-passkey-untrusted");
    // Forgiving: the owner clears this instantly with their established passkey.
    expect(r!.canStepUp).toBe(true);
    expect(r!.retryAt).toBe(new Date(NOW + 3 * HOUR).toISOString());
    expect(r!.message).toContain("Confirm with one of your other passkeys");
  });

  it("refuses a cred claim naming a passkey no longer on the account", () => {
    const r = evaluatePrivilegedGate([active("a")], "gone", NOW);
    expect(r?.reason).toBe("acting-passkey-untrusted");
    expect(r?.canStepUp).toBe(true);
    expect(r?.retryAt).toBeNull();
  });

  it("time-based clearance: a lapsed window makes the same state pass", () => {
    expect(evaluatePrivilegedGate([quarantined("b", -1)], "b", NOW)).toBeNull();
  });

  it("refuses an account with zero passkeys with add-a-passkey guidance", () => {
    const r = evaluatePrivilegedGate([], undefined, NOW);
    expect(r?.reason).toBe("no-active-passkey");
    expect(r?.retryAt).toBeNull();
    expect(r?.message).toContain("Add a passkey");
  });

  it("a quarantined row with no window refuses without a retry time (fails closed, still explains)", () => {
    const r = evaluatePrivilegedGate([quarantined("b", null)], undefined, NOW);
    expect(r?.reason).toBe("no-active-passkey");
    expect(r?.retryAt).toBeNull();
    expect(r?.message.length).toBeGreaterThan(0);
  });
});

describe("PrivilegedActionQuarantineError", () => {
  it("carries the refusal and uses its message", () => {
    const refusal = evaluatePrivilegedGate([quarantined("b", HOUR)], undefined, NOW)!;
    const err = new PrivilegedActionQuarantineError(refusal);
    expect(err.refusal).toBe(refusal);
    expect(err.message).toBe(refusal.message);
    expect(err.name).toBe("PrivilegedActionQuarantineError");
  });
});
