import { randomBytes } from "node:crypto";

import { z } from "zod";

import type { Plugin, PluginContext, WizardState } from "@minister/plugin-sdk";

import {
  emailButton,
  emailFinePrint,
  emailLinkFallback,
  emailText,
  renderEmail,
} from "@/lib/email-layout";
import { normalizeEmailAnchor } from "@/lib/nullifier/normalize";

// email-exact: a small clone of the email-domain plugin. It proves control of an
// email address and reveals the FULL (normalized) address as the claim — less
// private than email-domain, opt-in by design. It shares email-domain's Sybil
// anchor (the normalized full address) but issues under its OWN badge_type, so
// the dedup namespace is DISTINCT: holding both an email-domain and an
// email-exact badge for the same mailbox does not self-collide.

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

export const emailExactPlugin: Plugin = {
  manifest: {
    id: "email-exact",
    name: "Email address",
    description:
      "Prove you control a specific email address, revealing the full address. Less private than the email-domain badge — verified via a one-time link sent to that address. The badge attests the CANONICAL (normalized) form of the address (lowercased; for Gmail, dots and any +tag are dropped), which can differ from exactly what you typed.",
    badgeTypes: ["email-exact"],
    requiresExtension: false,
    iconKey: "mail",
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

        const verifyUrl = `${ctx.origin}/badges/new/email-exact/verify?token=${encodeURIComponent(token)}`;

        await ctx.sendMail({
          to: email,
          subject: "Verify your email for Minister",
          text: [
            "Someone (hopefully you) asked Minister to issue a badge proving",
            "control of this exact email address.",
            "",
            "If that's you, click the link below to complete the proof:",
            verifyUrl,
            "",
            "If not, ignore this email — no badge will be issued.",
          ].join("\n"),
          html: renderEmail({
            title: "Verify your email for Minister",
            heading: "Verify your email address",
            blocks: [
              emailText(
                "Someone (hopefully you) asked Minister to issue a badge proving control of this exact email address.",
              ),
              emailText("If that's you, complete the proof:"),
              emailButton("Verify this email", verifyUrl),
              emailLinkFallback(verifyUrl),
              emailFinePrint("If not, ignore this email — no badge will be issued."),
            ],
          }),
        });

        // Audit records the domain only — never the address.
        await ctx.audit.log("plugin.email_exact.verification_sent", { domain });

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
            // Carry the full address across the round trip: it is BOTH the Sybil
            // anchor and (normalized) the disclosed claim, captured only AT
            // VERIFY once inbox control is proven (build-plan §2.3 anti-squat).
            // The runtime scrubs `data` on completion; the AuditLog never sees
            // the address (domain only, above).
            data: { email },
          },
        };
      }

      case STEP_MAGIC: {
        const parsed = VerifyInput.safeParse(input);
        if (!parsed.success) {
          return { kind: "error", message: "Missing verification token" };
        }
        // The wizard runtime has already confirmed `token` matches the session's
        // pendingToken before reaching the plugin.
        const email = typeof state.data.email === "string" ? state.data.email : "";
        if (!email) {
          return {
            kind: "error",
            message: "Wizard state missing the verified address — restart the flow.",
          };
        }
        // Inbox control proven → the normalized full address is BOTH the anchor
        // and the revealed claim. Same normalization as email-domain, so the two
        // badges share one anchor; the distinct badge_type keeps their dedup
        // namespaces separate. `revealsAnchor` opts this badge out of the
        // runtime's anchor-leak guard, since the address here is disclosed by
        // design.
        const normalized = normalizeEmailAnchor(email);
        const domain = deriveDomain(normalized) ?? "";
        await ctx.audit.log("plugin.email_exact.verified", { domain });

        return {
          kind: "complete",
          badges: [
            {
              type: "email-exact",
              attributes: { email: normalized },
              claims: { email: normalized },
              sybilAnchor: normalized,
              revealsAnchor: true,
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
    pluginId: "email-exact",
    userId,
    currentStep: {
      id: STEP_FORM,
      kind: "form",
      payload: {
        title: "Verify an email address",
        description:
          "Enter the email address you want to attest. Minister will email a verification link; clicking it issues a badge revealing the canonical (normalized) form of that address — an exact-string match by a relying party is not guaranteed.",
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
