import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

// Redemption hits Prisma; mock the lib so the plugin is testable as a
// pure state machine. The non-DB exports keep their real behavior.
vi.mock("@/lib/invite-codes", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/invite-codes")>();
  return { ...actual, redeemInviteCode: vi.fn() };
});

import {
  ALREADY_REDEEMED_MESSAGE,
  INVALID_CODE_MESSAGE,
  redeemInviteCode,
} from "@/lib/invite-codes";

import { inviteCodePlugin } from "./index";

const redeemMock = vi.mocked(redeemInviteCode);

function ctx(): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
  };
}

function formState(): WizardState {
  return {
    pluginId: "invite-code",
    userId: "user_test",
    currentStep: {
      id: "enter-code",
      kind: "form",
      payload: { title: "Redeem an invite code", fields: [] },
    },
    data: {},
  };
}

beforeEach(() => {
  redeemMock.mockReset();
});

describe("inviteCodePlugin.startWizard", () => {
  it("opens with a single-field code form", async () => {
    const state = await inviteCodePlugin.startWizard(ctx());
    expect(state.currentStep.kind).toBe("form");
    if (state.currentStep.kind !== "form") throw new Error("kind");
    expect(state.currentStep.payload.fields).toHaveLength(1);
    expect(state.currentStep.payload.fields[0]?.name).toBe("code");
  });
});

describe("inviteCodePlugin.handleStep", () => {
  it("completes with an invite-code badge carrying only the label", async () => {
    redeemMock.mockResolvedValue({
      ok: true,
      inviteCodeId: "ic_1",
      label: "Beta cohort",
    });
    const c = ctx();
    const result = await inviteCodePlugin.handleStep(
      formState(),
      { code: "abcd-efgh-jklm" },
      c,
    );
    expect(result.kind).toBe("complete");
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges).toEqual([
      {
        type: "invite-code",
        attributes: { label: "Beta cohort" },
        claims: { label: "Beta cohort" },
      },
    ]);
    // The plugin normalizes before redeeming.
    expect(redeemMock).toHaveBeenCalledWith("ABCD-EFGH-JKLM", "user_test");
    // Audit metadata names the campaign, never the code.
    expect(c.audit.log).toHaveBeenCalledWith("plugin.invite_code.redeemed", {
      inviteCodeId: "ic_1",
      label: "Beta cohort",
    });
  });

  it("surfaces the uniform rejection message", async () => {
    redeemMock.mockResolvedValue({ ok: false, message: INVALID_CODE_MESSAGE });
    const result = await inviteCodePlugin.handleStep(
      formState(),
      { code: "NOPE" },
      ctx(),
    );
    expect(result).toEqual({ kind: "error", message: INVALID_CODE_MESSAGE });
  });

  it("surfaces the already-redeemed message", async () => {
    redeemMock.mockResolvedValue({
      ok: false,
      message: ALREADY_REDEEMED_MESSAGE,
    });
    const result = await inviteCodePlugin.handleStep(
      formState(),
      { code: "ABCD-EFGH-JKLM" },
      ctx(),
    );
    expect(result).toEqual({ kind: "error", message: ALREADY_REDEEMED_MESSAGE });
  });

  it("rejects malformed input without calling redeem", async () => {
    const result = await inviteCodePlugin.handleStep(formState(), {}, ctx());
    expect(result.kind).toBe("error");
    expect(redeemMock).not.toHaveBeenCalled();
  });

  it("errors on an unexpected step id", async () => {
    const state: WizardState = {
      ...formState(),
      currentStep: {
        id: "someplace-else",
        kind: "info",
        payload: { title: "x", body: "y" },
      },
    };
    const result = await inviteCodePlugin.handleStep(
      state,
      { code: "ABCD" },
      ctx(),
    );
    expect(result.kind).toBe("error");
    expect(redeemMock).not.toHaveBeenCalled();
  });
});
