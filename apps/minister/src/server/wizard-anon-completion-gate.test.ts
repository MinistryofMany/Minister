import type { HandleStepResult, IssuedBadge, Plugin } from "@minister/plugin-sdk";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Completion-gate regression (spec §6.4): issueBadgesAndComplete is the single
// choke point every badge-issuance path routes through. startWizard already
// refuses to START a wizard mid-enrollment, but a user can generate a seed (→
// PENDING_BACKUP) AFTER a wizard began and then reach completion — so the gate
// must ALSO fire at the terminal step, before anything is minted. This pins:
// a PENDING_BACKUP user is refused (nothing minted), a none/ACTIVE (or flag-off)
// user completes normally. The gate predicate is mocked (its own logic lives in
// lib/anon-seed/backup-gate.test.ts); issueBadge is mocked to isolate the gate
// from the real signing/nullifier path.
const h = vi.hoisted(() => ({
  isAnonBackupPending: vi.fn(),
  issueBadge: vi.fn(async () => "badge_minted_1"),
  session: {
    id: "ws-complete",
    userId: "user-1",
    pluginId: "invite-code",
    state: { currentStep: { id: "s", kind: "form", payload: {} }, data: {} },
    completedAt: null as Date | null,
    pendingToken: null as string | null,
    expiresAt: new Date(Date.now() + 60_000),
  },
  wizardUpdate: vi.fn(async () => ({})),
}));

vi.mock("@/lib/anon-seed/backup-gate", () => ({ isAnonBackupPending: h.isAnonBackupPending }));
vi.mock("@/server/issue-badge", () => ({ issueBadge: h.issueBadge }));
vi.mock("@/lib/audit", () => ({ audit: vi.fn(async () => undefined) }));
vi.mock("@/lib/mailer", () => ({ sendMail: vi.fn(async () => undefined) }));
vi.mock("@/plugins/registry", () => ({ getPlugin: vi.fn() }));
vi.mock("@/lib/prisma", () => ({
  prisma: {
    wizardSession: {
      findFirst: vi.fn(async () => ({ ...h.session })),
      update: h.wizardUpdate,
    },
  },
}));

import { getPlugin } from "@/plugins/registry";
import { AnonBackupPendingError, submitStep } from "@/server/wizard";

// A badge with NO sybilAnchor: issueBadgesAndComplete skips the whole nullifier
// path and routes straight through the gate → issueBadge → final scrub, so the
// gate is exercised without the signing/ledger machinery.
const inviteBadge: IssuedBadge = {
  type: "invite-code",
  attributes: { label: "cohort" },
  claims: { label: "cohort" },
};

function completingPlugin(): Plugin {
  return {
    manifest: {
      id: "invite-code",
      name: "Invite code",
      description: "",
      badgeTypes: ["invite-code"],
      requiresExtension: false,
    },
    startWizard: vi.fn(),
    handleStep: vi.fn(async (): Promise<HandleStepResult> => ({
      kind: "complete",
      badges: [inviteBadge],
    })),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  h.issueBadge.mockResolvedValue("badge_minted_1");
  vi.mocked(getPlugin).mockReturnValue(completingPlugin());
});

describe("issueBadgesAndComplete — Private Identity backup gate", () => {
  it("refuses a completing wizard while PENDING_BACKUP — nothing is minted", async () => {
    h.isAnonBackupPending.mockResolvedValue(true);
    await expect(
      submitStep("ws-complete", "user-1", "http://localhost:3000", { code: "x" }),
    ).rejects.toThrow(AnonBackupPendingError);
    expect(h.isAnonBackupPending).toHaveBeenCalledWith("user-1");
    // Gate fires before any badge is minted and before the session is completed.
    expect(h.issueBadge).not.toHaveBeenCalled();
    expect(h.wizardUpdate).not.toHaveBeenCalled();
  });

  it("completes normally for a none/ACTIVE (or flag-off) user — gate returns false", async () => {
    h.isAnonBackupPending.mockResolvedValue(false);
    const res = await submitStep("ws-complete", "user-1", "http://localhost:3000", { code: "x" });
    expect(res.kind).toBe("complete");
    if (res.kind !== "complete") return;
    expect(res.badgeIds).toEqual(["badge_minted_1"]);
    expect(h.issueBadge).toHaveBeenCalledOnce();
  });
});
