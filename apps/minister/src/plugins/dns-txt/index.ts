import { z } from "zod";

import type { Plugin, WizardState } from "@minister/plugin-sdk";

import { randomToken } from "../oauth-common";
import { CORROBORATING_RESOLVERS, resolveTxtVia } from "./resolve";
import {
  buildDomainControlBadge,
  challengeHost,
  challengeValue,
  normalizeDomain,
  txtRecordsContainChallenge,
} from "./verify";

const STEP_FORM = "dns-domain";
const STEP_VERIFY = "dns-verify";

const FormInput = z.object({
  domain: z.string().min(1),
});

function makeFormStep(userId: string): WizardState {
  return {
    pluginId: "dns-txt",
    userId,
    currentStep: {
      id: STEP_FORM,
      kind: "form",
      payload: {
        title: "Prove control of a domain",
        description:
          "Enter a domain you control. Minister gives you a one-time TXT record to publish in that " +
          "domain's DNS; once it resolves, the badge is issued. The badge records only the domain.",
        fields: [
          {
            name: "domain",
            label: "Domain",
            type: "text",
            placeholder: "example.com",
            required: true,
          },
        ],
        submitLabel: "Continue",
      },
    },
    data: {},
  };
}

// Info-step body walking the user through publishing the TXT record. The token
// is a public challenge (not a secret), so it is fine to show it here. We ask
// for a dedicated `_minister-challenge.<domain>` host rather than the apex so it
// never collides with the domain's existing TXT records and can be deleted
// freely once the badge is issued.
function verifyStepBody(domain: string, token: string): string {
  const host = challengeHost(domain);
  const value = challengeValue(token);
  return [
    `Add this DNS TXT record to prove control of ${domain}:`,
    ``,
    `    Host / Name:  ${host}`,
    `    Type:         TXT`,
    `    Value:        ${value}`,
    ``,
    `1. Open your DNS provider's dashboard for ${domain}.`,
    `2. Create a new TXT record with the host and value above (some providers`,
    `   want just "_minister-challenge" as the host and add the domain for you).`,
    `3. Save it, then come back and click Verify.`,
    ``,
    `DNS changes can take a few minutes — sometimes longer — to propagate. If the ` +
      `first check comes up empty, wait a moment and click Verify again. You can ` +
      `delete the record once the badge is issued.`,
  ].join("\n");
}

// Was this a "the record isn't visible yet" DNS outcome (name has no such record
// / does not exist), as opposed to a transient resolver failure? Both are
// retryable, but they get different copy so the user knows whether to add the
// record or just wait.
function isNoRecordError(err: unknown): boolean {
  const code =
    typeof err === "object" && err !== null ? (err as { code?: unknown }).code : undefined;
  // ENOTFOUND: NXDOMAIN (the challenge host doesn't exist yet).
  // ENODATA:   the host exists but has no TXT records yet.
  return code === "ENOTFOUND" || code === "ENODATA";
}

// The result of asking ONE public resolver for the challenge host:
//  - match:     resolved and a TXT record holds the exact challenge value.
//  - no-match:  resolved, but no record held the value (present-but-wrong).
//  - no-record: NXDOMAIN / no TXT records yet (still propagating).
//  - error:     any other resolver failure (SERVFAIL / timeout / unreachable).
// Every non-match is retryable; the caller only issues when BOTH say `match`.
type ResolverOutcome =
  | { status: "match" }
  | { status: "no-match" }
  | { status: "no-record" }
  | { status: "error"; message: string };

// Ask a single resolver and classify the answer, never throwing: a resolver
// failure is a failed corroboration, not a crash. Kept off "use server" (this is
// a plain module) so it can be a sync-returning async helper.
async function queryResolver(
  server: string,
  host: string,
  expectedValue: string,
): Promise<ResolverOutcome> {
  try {
    const records = await resolveTxtVia(server, host);
    return txtRecordsContainChallenge(records, expectedValue)
      ? { status: "match" }
      : { status: "no-match" };
  } catch (err) {
    if (isNoRecordError(err)) return { status: "no-record" };
    return { status: "error", message: err instanceof Error ? err.message : String(err) };
  }
}

export const dnsTxtPlugin: Plugin = {
  manifest: {
    id: "dns-txt",
    name: "Domain control",
    description:
      "Prove you control a DNS domain by publishing a one-time TXT record. Issues a " +
      "`domain-control` badge that records only the domain. Needs no third-party sign-in.",
    badgeTypes: ["domain-control"],
    requiresExtension: false,
    iconKey: "globe",
  },

  // No credentials required — DNS resolution is keyless, so always available.

  async startWizard(ctx) {
    return makeFormStep(ctx.userId);
  },

  async handleStep(state, input, ctx) {
    switch (state.currentStep.id) {
      case STEP_FORM: {
        const parsed = FormInput.safeParse(input);
        if (!parsed.success) {
          return { kind: "error", message: "Enter a domain." };
        }
        const domain = normalizeDomain(parsed.data.domain);
        if (!domain) {
          return {
            kind: "error",
            message:
              "That doesn't look like a domain. Enter a bare hostname like example.com — not a " +
              "URL, IP address, or localhost.",
          };
        }
        // High-entropy, single-use challenge token (192 bits). Carried
        // server-side in wizard `data`; the runtime never returns `data` to the
        // browser (toClientState scrubs it). It reaches the user only as the
        // display string in the info-step body below.
        const token = randomToken(24);

        // Do NOT log the user-typed domain here: control is unproven at this
        // point, so recording an arbitrary domain against the requester would be
        // an unverified-claim leak. The domain is logged only on the verified
        // event below (the revealsAnchor exception, mirroring hackernews).
        await ctx.audit.log("plugin.dns_txt.challenge_issued", {});

        return {
          kind: "continue",
          state: {
            ...state,
            currentStep: {
              id: STEP_VERIFY,
              kind: "info",
              payload: {
                title: "Publish the TXT record",
                body: verifyStepBody(domain, token),
                continueLabel: "Verify",
              },
            },
            // Server-side only (scrubbed from any client copy). The domain is not
            // the Sybil anchor until the token is confirmed present in DNS; a new
            // domain means restarting the flow, which discards this token.
            data: { domain, token },
          },
        };
      }

      case STEP_VERIFY: {
        const domain = typeof state.data.domain === "string" ? state.data.domain : "";
        const token = typeof state.data.token === "string" ? state.data.token : "";
        if (!domain || !token) {
          return {
            kind: "error",
            message: "This flow lost its challenge token — restart it.",
          };
        }

        // Re-validate the carried domain before it ever reaches the resolver —
        // belt and suspenders against a tampered session (form-step validation
        // already ran, but the resolver call must never trust unvalidated input).
        const host = normalizeDomain(domain);
        if (!host) {
          return { kind: "error", message: "This flow lost a valid domain — restart it." };
        }

        // DNS-ONLY: a TXT lookup, never an HTTP fetch of the domain, so there is
        // no SSRF surface. We corroborate the challenge across TWO independent
        // public resolvers (Cloudflare 1.1.1.1 AND Google 8.8.8.8) instead of the
        // box's single default resolver: a poisoned answer at one resolver could
        // otherwise mint an impersonation-relevant `domain-control` claim over a
        // domain the requester does not own. Both resolvers must independently
        // return the exact token; anything else — a miss, a disagreement, or a
        // resolver error — fails closed and stays on the retryable info step.
        // (This means the box must be able to reach both resolvers on port 53.)
        const challengeHostName = challengeHost(host);
        const expectedValue = challengeValue(token);
        const outcomes = await Promise.all(
          CORROBORATING_RESOLVERS.map((server) =>
            queryResolver(server, challengeHostName, expectedValue),
          ),
        );

        if (outcomes.every((o) => o.status === "match")) {
          // Both resolvers agree the token is published. Control is proven. The
          // domain IS the disclosed value and the Sybil anchor (revealsAnchor),
          // so it legitimately appears in the badge and in this verified audit
          // event.
          await ctx.audit.log("plugin.dns_txt.verified", { domain: host });
          return { kind: "complete", badges: [buildDomainControlBadge(host)] };
        }

        // Corroboration failed — fail closed. Every branch below is retryable
        // (the record may still be propagating unevenly across resolvers); we
        // keep the info step and surface the most actionable copy. A hard
        // resolver error takes precedence, then a not-yet-visible record, then a
        // present-but-wrong / disagreeing value.
        const errored = outcomes.find(
          (o): o is Extract<ResolverOutcome, { status: "error" }> => o.status === "error",
        );
        if (errored) {
          return {
            kind: "error",
            message: `DNS lookup failed: ${errored.message}. Wait a moment and click Verify again.`,
          };
        }
        if (outcomes.some((o) => o.status === "no-record")) {
          return {
            kind: "error",
            message:
              "We couldn't find the TXT record yet. DNS changes can take a few minutes to " +
              "propagate — double-check the host and value, then wait a moment and click Verify again.",
          };
        }
        return {
          kind: "error",
          message:
            "We reached the DNS record but the verification value didn't match yet. If you just " +
            "added it, DNS can take a few minutes to propagate — wait a moment and click Verify again.",
        };
      }
    }

    return { kind: "error", message: `Unknown wizard step: ${state.currentStep.id}` };
  },
};
