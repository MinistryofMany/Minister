import { beforeEach, describe, expect, it, vi } from "vitest";

// Badge gate regression (spec §6.4): startWizard must refuse to start any badge
// wizard while the user's Private Identity enrollment is PENDING_BACKUP, so no
// badge value is built on an unbackuped seed. The gate predicate is mocked here
// (its own logic is covered in lib/anon-seed/backup-gate.test.ts); this pins the
// wizard-runtime behaviour: a pending user gets the typed, linkable error BEFORE
// the plugin runs or any session row is written.
const h = vi.hoisted(() => ({ isAnonBackupPending: vi.fn() }));

vi.mock("@/lib/anon-seed/backup-gate", () => ({
  isAnonBackupPending: h.isAnonBackupPending,
}));

import { AnonBackupPendingError, startWizard } from "./wizard";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("startWizard — Private Identity backup gate", () => {
  it("throws AnonBackupPendingError when the user is mid-enrollment (PENDING_BACKUP)", async () => {
    h.isAnonBackupPending.mockResolvedValue(true);
    // invite-code is always configured (no external creds), so the flow reaches
    // the gate rather than short-circuiting on PluginNotConfiguredError.
    await expect(startWizard("invite-code", "user-1", "http://localhost:3000")).rejects.toThrow(
      AnonBackupPendingError,
    );
    expect(h.isAnonBackupPending).toHaveBeenCalledWith("user-1");
  });

  it("the error links to the Private Identity settings page", async () => {
    h.isAnonBackupPending.mockResolvedValue(true);
    let caught: unknown;
    try {
      await startWizard("invite-code", "user-1", "http://localhost:3000");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(AnonBackupPendingError);
    const err = caught as AnonBackupPendingError;
    expect(err.href).toBe("/settings/private-identity");
    expect(err.message).toMatch(/back(ing)? up/i);
  });

  it("consults the gate AFTER the unconfigured-plugin guard (unknown plugin still fails first)", async () => {
    h.isAnonBackupPending.mockResolvedValue(true);
    // An unknown plugin fails on the plugin lookup before the gate is consulted.
    await expect(startWizard("no-such-plugin", "user-1", "http://localhost:3000")).rejects.toThrow(
      /unknown plugin/i,
    );
    expect(h.isAnonBackupPending).not.toHaveBeenCalled();
  });
});
