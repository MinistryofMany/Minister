import { randomBytes } from "node:crypto";

import { z } from "zod";

import type { Plugin } from "@minister/plugin-sdk";

import { verifyPresentation } from "@/lib/tlsn-verifier";

const STEP_PROVE = "tlsn-prove";

// The generic TLSNotary plugin. Asks the extension to prove a specific
// domain returned a specific substring (a needle the user expects to
// find in the response body), then issues a `tlsn-attestation` badge
// recording { domain, claim }. Specialized plugins (id.me — Stage 8)
// extend this pattern with their own selectors + claim extraction.
//
// Wizard contract:
//   1. startWizard → extension-action step. Payload carries `action:
//      "tlsn-prove"` plus the params the extension needs: target URL,
//      expected substring (the "needle"), the wizard's pendingToken.
//      Extension does the TLSN proof, posts the finalized presentation
//      to /api/tlsn/submit with { sessionToken, presentation }.
//   2. handleStep is invoked by /api/tlsn/submit with input
//      { presentation: <base64> }. We hand it to tlsn-verifier, then
//      check the verified transcript actually contains the needle the
//      user agreed to attest, then issue the badge.

const SubmitInput = z.object({
  presentation: z.string().min(1),
});

const PluginParams = z.object({
  domain: z.string().min(1),
  url: z.string().url(),
  needle: z.string().min(1),
});

function randomToken(): string {
  return randomBytes(24).toString("base64url");
}

export const tlsnAttestationPlugin: Plugin = {
  manifest: {
    id: "tlsn-attestation",
    name: "TLSNotary attestation",
    description:
      "Prove a specific fact appears on a specific HTTPS page using TLSNotary. Requires the Minister browser extension.",
    badgeTypes: ["tlsn-attestation"],
    requiresExtension: true,
    iconKey: "shield-check",
  },

  async startWizard(ctx) {
    // For the generic plugin we hard-code a demo target. Specialized
    // plugins (id.me, github-stars, etc.) override with their own
    // values and don't ship as the plain `tlsn-attestation` flow.
    // TODO(stage-8): replace with a real per-plugin configuration
    // once specific plugins land.
    const params = PluginParams.parse({
      domain: "example.com",
      url: "https://example.com/",
      needle: "Example Domain",
    });

    const token = randomToken();
    return {
      pluginId: "tlsn-attestation",
      userId: ctx.userId,
      currentStep: {
        id: STEP_PROVE,
        kind: "extension-action",
        payload: {
          action: "tlsn-prove",
          params: {
            url: params.url,
            // Echo the submit URL so the extension knows where to
            // POST the finished presentation. Sessions are scoped to
            // the issuer's origin.
            submitUrl: `${ctx.origin}/api/tlsn/submit`,
            sessionToken: token,
          },
          description: `Prove that ${params.url} contains the text "${params.needle}".`,
          expectedSubmissionToken: token,
        },
      },
      // Stash everything the verify step needs — we don't trust the
      // extension to re-send these.
      data: {
        domain: params.domain,
        url: params.url,
        needle: params.needle,
      },
    };
  },

  async handleStep(state, input, ctx) {
    if (state.currentStep.id !== STEP_PROVE) {
      return { kind: "error", message: `Unknown step: ${state.currentStep.id}` };
    }

    const parsed = SubmitInput.safeParse(input);
    if (!parsed.success) {
      return {
        kind: "error",
        message: parsed.error.issues[0]?.message ?? "Invalid submission",
      };
    }

    const domain = typeof state.data.domain === "string" ? state.data.domain : "";
    const needle = typeof state.data.needle === "string" ? state.data.needle : "";
    if (!domain || !needle) {
      return {
        kind: "error",
        message: "Wizard state corrupted — restart the flow",
      };
    }

    let transcript;
    try {
      transcript = await verifyPresentation({
        presentation: parsed.data.presentation,
        expectedDomain: domain,
      });
    } catch (err) {
      return {
        kind: "error",
        message: `Verification failed: ${err instanceof Error ? err.message : err}`,
      };
    }

    // The verifier confirmed the TLS session and the server name; now
    // confirm the response body actually contains the substring the
    // user agreed to attest. The verifier doesn't know our plugin
    // semantics, so this check happens here.
    if (!transcript.received.includes(needle)) {
      return {
        kind: "error",
        message: `Expected the response to contain "${needle}" but it didn't`,
      };
    }

    await ctx.audit.log("plugin.tlsn_attestation.verified", {
      domain,
      // Do NOT log the needle if a future plugin uses it for something
      // sensitive — for the generic plugin it's user-chosen and fine.
      needleHash: hashForAudit(needle),
    });

    return {
      kind: "complete",
      badges: [
        {
          type: "tlsn-attestation",
          attributes: { domain, claim: needle },
          claims: { domain, claim: needle },
        },
      ],
    };
  },
};

// Coarse fingerprint of a needle for the audit log — enough to
// correlate repeat attempts without storing the exact string.
function hashForAudit(value: string): string {
  // Cheap deterministic hash. Audit log fingerprinting only — not a
  // security primitive.
  let h = 0;
  for (let i = 0; i < value.length; i++) {
    h = (h * 31 + value.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(36);
}
