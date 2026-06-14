import { z } from "zod";

import type { Plugin, WizardState } from "@minister/plugin-sdk";

import { normalizeInviteCode, redeemInviteCode } from "@/lib/invite-codes";

const STEP_FORM = "enter-code";

const FormInput = z.object({
  code: z.string().min(1, "Enter an invite code"),
});

export const inviteCodePlugin: Plugin = {
  manifest: {
    id: "invite-code",
    name: "Invite code",
    description:
      "Redeem an invite code from a Minister admin. The badge names the campaign you were invited to — the code itself is never stored in the credential.",
    badgeTypes: ["invite-code"],
    requiresExtension: false,
    iconKey: "ticket",
  },

  async startWizard(ctx) {
    return makeFormStep(ctx.userId);
  },

  async handleStep(state, input, ctx) {
    if (state.currentStep.id !== STEP_FORM) {
      return {
        kind: "error",
        message: `Unknown wizard step: ${state.currentStep.id}`,
      };
    }

    const parsed = FormInput.safeParse(input);
    if (!parsed.success) {
      return {
        kind: "error",
        message: parsed.error.issues[0]?.message ?? "Enter an invite code",
      };
    }

    const result = await redeemInviteCode(
      normalizeInviteCode(parsed.data.code),
      ctx.userId,
    );
    if (!result.ok) {
      return { kind: "error", message: result.message };
    }

    // The code string stays out of the audit metadata for the same
    // reason it stays out of the VC: multi-use codes are still live.
    await ctx.audit.log("plugin.invite_code.redeemed", {
      inviteCodeId: result.inviteCodeId,
      label: result.label,
    });

    return {
      kind: "complete",
      badges: [
        {
          type: "invite-code",
          attributes: { label: result.label },
          claims: { label: result.label },
        },
      ],
    };
  },
};

function makeFormStep(userId: string): WizardState {
  return {
    pluginId: "invite-code",
    userId,
    currentStep: {
      id: STEP_FORM,
      kind: "form",
      payload: {
        title: "Redeem an invite code",
        description:
          "Enter the code you were given. Codes can be single- or multi-use and may expire.",
        fields: [
          {
            name: "code",
            label: "Invite code",
            type: "text",
            placeholder: "ABCD-EFGH-JKLM",
            helpText: "Case doesn't matter.",
            required: true,
          },
        ],
        submitLabel: "Redeem",
      },
    },
    data: {},
  };
}
