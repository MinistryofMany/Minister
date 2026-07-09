import { z } from "zod";

import type { Plugin, WizardState } from "@minister/plugin-sdk";

import { randomToken } from "../oauth-common";
import { aboutContainsToken, buildHackerNewsBadges, isValidHackerNewsUsername } from "./verify";

const STEP_FORM = "hn-username";
const STEP_VERIFY = "hn-verify";

// The public, keyless HN Firebase API. `<id>` is the username.
const HN_USER_URL = (id: string) =>
  `https://hacker-news.firebaseio.com/v0/user/${encodeURIComponent(id)}.json`;

const FormInput = z.object({
  username: z.string().min(1),
});

const HnUser = z.object({
  id: z.string().min(1),
  created: z.number().optional(),
  about: z.string().optional(),
});

function makeFormStep(userId: string): WizardState {
  return {
    pluginId: "hackernews",
    userId,
    currentStep: {
      id: STEP_FORM,
      kind: "form",
      payload: {
        title: "Prove your Hacker News account",
        description:
          "Hacker News has no sign-in for apps, so we verify with a one-time token you paste into your profile. Enter your username to begin.",
        fields: [
          {
            name: "username",
            label: "Hacker News username",
            type: "text",
            placeholder: "pg",
            required: true,
          },
        ],
        submitLabel: "Continue",
      },
    },
    data: {},
  };
}

// Info-step body walking the user through pasting the token. The token is a
// public challenge (not a secret), so it is fine to show it and to persist it in
// the step payload.
function verifyStepBody(username: string, token: string): string {
  return [
    `Copy this one-time token:`,
    ``,
    `    ${token}`,
    ``,
    `1. Open your Hacker News profile at https://news.ycombinator.com/user?id=${username}`,
    `2. Click "edit", paste the token anywhere in your "about" box, and submit.`,
    `3. Come back and click Verify below.`,
    ``,
    `Hacker News can take a few minutes to publish profile edits. If the first check comes up empty, wait a moment and click Verify again. You can remove the token from your profile once the badge is issued.`,
  ].join("\n");
}

export const hackernewsPlugin: Plugin = {
  manifest: {
    id: "hackernews",
    name: "Hacker News",
    description:
      "Prove you control a Hacker News account with a one-time token pasted into your profile. " +
      "Issues an `oauth-account` badge plus, when the account is old enough, a coarse account-age " +
      "badge. Needs no third-party sign-in.",
    badgeTypes: ["oauth-account", "account-age"],
    requiresExtension: false,
    iconKey: "link",
  },

  // No credentials required — always available.

  async startWizard(ctx) {
    return makeFormStep(ctx.userId);
  },

  async handleStep(state, input, ctx) {
    switch (state.currentStep.id) {
      case STEP_FORM: {
        const parsed = FormInput.safeParse(input);
        if (!parsed.success) {
          return { kind: "error", message: "Enter your Hacker News username" };
        }
        const username = parsed.data.username.trim();
        if (!isValidHackerNewsUsername(username)) {
          return { kind: "error", message: "That doesn't look like a Hacker News username." };
        }
        const token = `minister-${randomToken(9)}`;

        await ctx.audit.log("plugin.hackernews.challenge_issued", { handle: username });

        return {
          kind: "continue",
          state: {
            ...state,
            currentStep: {
              id: STEP_VERIFY,
              kind: "info",
              payload: {
                title: "Paste the token into your Hacker News profile",
                body: verifyStepBody(username, token),
                continueLabel: "Verify",
              },
            },
            // Carried server-side across the info step; never returned to the
            // browser (toClientState scrubs `data`). The username is not the
            // anchor until the token is confirmed present, at which point we
            // re-read it from HN's own response for canonical casing.
            data: { username, token },
          },
        };
      }

      case STEP_VERIFY: {
        const username = typeof state.data.username === "string" ? state.data.username : "";
        const token = typeof state.data.token === "string" ? state.data.token : "";
        if (!username || !token) {
          return {
            kind: "error",
            message: "This flow lost its challenge token — restart it.",
          };
        }

        let res: Response;
        try {
          res = await fetch(HN_USER_URL(username));
        } catch (err) {
          return {
            kind: "error",
            message: `Failed to reach Hacker News: ${err instanceof Error ? err.message : err}`,
          };
        }
        if (!res.ok) {
          return { kind: "error", message: `Hacker News returned ${res.status} — try again.` };
        }

        const raw: unknown = await res.json();
        if (raw === null) {
          return {
            kind: "error",
            message: `We couldn't find a Hacker News user named "${username}". Check the spelling and try again.`,
          };
        }
        const userParse = HnUser.safeParse(raw);
        if (!userParse.success) {
          return { kind: "error", message: "Hacker News returned an unexpected profile shape." };
        }
        const hn = userParse.data;

        if (!aboutContainsToken(hn.about, token)) {
          return {
            kind: "error",
            message:
              "We couldn't find the token in your Hacker News profile yet. Hacker News can take a few minutes to publish edits — wait a moment and click Verify again.",
          };
        }

        // Anchor on HN's own `id` (canonical casing), not the user-typed value.
        const badges = buildHackerNewsBadges({ id: hn.id, created: hn.created }, new Date());

        await ctx.audit.log("plugin.hackernews.verified", {
          handle: hn.id,
          issuedTypes: badges.map((b) => b.type),
        });

        return { kind: "complete", badges };
      }
    }

    return { kind: "error", message: `Unknown wizard step: ${state.currentStep.id}` };
  },
};
