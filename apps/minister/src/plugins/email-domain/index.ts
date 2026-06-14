import { randomBytes } from "node:crypto";

import { z } from "zod";

import type {
  Plugin,
  PluginContext,
  WizardState,
} from "@minister/plugin-sdk";

const STEP_FORM = "collect-email";
const STEP_MAGIC = "wait-magic-link";
const TOKEN_BYTES = 32;

const FormInput = z.object({
  email: z.string().email(),
});

const VerifyInput = z.object({
  token: z.string().min(8),
});

function tokenFromBytes(n: number): string {
  return randomBytes(n).toString("base64url");
}

function deriveDomain(email: string): string | null {
  const at = email.lastIndexOf("@");
  if (at < 0 || at === email.length - 1) return null;
  return email.slice(at + 1).toLowerCase();
}

export const emailDomainPlugin: Plugin = {
  manifest: {
    id: "email-domain",
    name: "Email domain",
    description:
      "Prove you control an email address at a given domain. Verified via a one-time link sent to that address — Minister never stores the email itself, only the domain.",
    badgeTypes: ["email-domain"],
    requiresExtension: false,
    iconKey: "at-sign",
  },

  async startWizard(ctx) {
    return makeFormStep(ctx.userId);
  },

  async handleStep(state, input, ctx) {
    switch (state.currentStep.id) {
      case STEP_FORM: {
        const parsed = FormInput.safeParse(input);
        if (!parsed.success) {
          return {
            kind: "error",
            message: parsed.error.issues[0]?.message ?? "Invalid email",
          };
        }
        const email = parsed.data.email.toLowerCase();
        const domain = deriveDomain(email);
        if (!domain) {
          return { kind: "error", message: "Couldn't parse domain from email" };
        }
        const token = tokenFromBytes(TOKEN_BYTES);

        // We don't yet know the wizard session id here — the runtime
        // assigns it. The verify URL therefore embeds only the token
        // (the runtime can look up the session by pendingToken).
        const verifyUrl = `${ctx.origin}/badges/new/email-domain/verify?token=${encodeURIComponent(token)}`;

        await ctx.sendMail({
          to: email,
          subject: "Verify your email for Minister",
          text: [
            "Someone (hopefully you) asked Minister to issue a badge proving",
            `control of an email address at ${domain}.`,
            "",
            "If that's you, click the link below to complete the proof:",
            verifyUrl,
            "",
            "If not, ignore this email — no badge will be issued.",
          ].join("\n"),
        });

        await ctx.audit.log("plugin.email_domain.verification_sent", {
          domain,
        });

        return {
          kind: "continue",
          state: {
            ...state,
            currentStep: {
              id: STEP_MAGIC,
              kind: "magic-link",
              payload: {
                sentTo: email,
                description: "Open the link in the email to finish.",
                expectedToken: token,
              },
            },
            // We retain the *domain*, not the email, in wizard state so
            // a wizard-state dump (e.g. via Prisma Studio) shows minimum
            // PII. The token is the wizard-runtime's pendingToken.
            data: { domain },
          },
        };
      }

      case STEP_MAGIC: {
        const parsed = VerifyInput.safeParse(input);
        if (!parsed.success) {
          return { kind: "error", message: "Missing verification token" };
        }
        // The wizard runtime has already confirmed `token` matches the
        // session's pendingToken before reaching the plugin. So we
        // trust the input here.
        const domain =
          typeof state.data.domain === "string" ? state.data.domain : "";
        if (!domain) {
          return {
            kind: "error",
            message: "Wizard state missing domain — restart the flow.",
          };
        }
        await ctx.audit.log("plugin.email_domain.verified", { domain });

        return {
          kind: "complete",
          badges: [
            {
              type: "email-domain",
              attributes: { domain },
              claims: { domain },
            },
          ],
        };
      }
    }

    return { kind: "error", message: `Unknown wizard step: ${state.currentStep.id}` };
  },
};

function makeFormStep(userId: string): WizardState {
  return {
    pluginId: "email-domain",
    userId,
    currentStep: {
      id: STEP_FORM,
      kind: "form",
      payload: {
        title: "Verify an email domain",
        description:
          "Enter any email address at the domain you want to attest. Minister will email a verification link; clicking it issues the badge.",
        fields: [
          {
            name: "email",
            label: "Email address",
            type: "email",
            placeholder: "you@example.com",
            required: true,
          },
        ],
        submitLabel: "Send verification link",
      },
    },
    data: {},
  };
}

// Surfaces the typed PluginContext type for the registry.
export type _PluginContextRef = PluginContext;
