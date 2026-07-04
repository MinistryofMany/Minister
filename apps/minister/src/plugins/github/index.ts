import { randomBytes } from "node:crypto";

import { z } from "zod";

import type { Plugin } from "@minister/plugin-sdk";

import { buildGithubBadges } from "./derive";

const STEP_AUTHORIZE = "github-authorize";

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL = "https://api.github.com/user";

// The plugin sends the user out to GitHub with this scope; we only
// need read access to the user's public profile. The acid test is /user
// returning id + login.
const REQUESTED_SCOPES = "read:user";

const CallbackInput = z.object({
  code: z.string().min(1),
});

const GithubUser = z.object({
  id: z.number().int(),
  login: z.string().min(1),
  // Extra facts drive the derived badges (account-age, following). All
  // optional: a partial /user response still yields the oauth-account badge.
  // We read these but never persist the raw values — only coarse thresholds.
  created_at: z.string().min(1).optional(),
  followers: z.number().int().nonnegative().optional(),
  // Avatar/name are nice-to-haves; not part of the badge claims.
});

function randomState(): string {
  return randomBytes(24).toString("base64url");
}

function readClientCreds(): { clientId: string; clientSecret: string } | null {
  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret };
}

export const githubPlugin: Plugin = {
  manifest: {
    id: "github",
    name: "GitHub",
    description:
      "Prove you control a GitHub account. Issues an `oauth-account` badge plus " +
      "coarse, privacy-preserving anti-sybil badges the account supports: " +
      "account age and a follower-count tier.",
    badgeTypes: ["oauth-account", "account-age", "social-following"],
    requiresExtension: false,
    iconKey: "link",
  },

  // GitHub OAuth is optional at deploy time. Without both credentials the
  // whole flow is dead, so the host hides the entry instead of surfacing a
  // wizard that would throw on the first step.
  isConfigured() {
    return readClientCreds() !== null;
  },

  async startWizard(ctx) {
    const creds = readClientCreds();
    if (!creds) {
      throw new Error(
        "GitHub plugin is not configured: set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET",
      );
    }

    const state = randomState();
    const redirectUri = `${ctx.origin}/badges/new/github/callback`;
    const authorizeUrl = new URL(GITHUB_AUTHORIZE_URL);
    authorizeUrl.searchParams.set("client_id", creds.clientId);
    authorizeUrl.searchParams.set("redirect_uri", redirectUri);
    authorizeUrl.searchParams.set("scope", REQUESTED_SCOPES);
    authorizeUrl.searchParams.set("state", state);
    // GitHub also supports `allow_signup=false` if we ever want to
    // require an existing GH account.

    await ctx.audit.log("plugin.github.authorize_initiated", {});

    return {
      pluginId: "github",
      userId: ctx.userId,
      currentStep: {
        id: STEP_AUTHORIZE,
        kind: "redirect",
        payload: {
          url: authorizeUrl.toString(),
          description:
            "We'll send you to GitHub to authorize this badge. After you approve, you'll bounce back here and Minister will issue the credential.",
          expectedState: state,
        },
      },
      // Stash the redirect URI so we can present it back to GitHub at
      // /token time — GitHub requires it to match.
      data: { redirectUri },
    };
  },

  async handleStep(state, input, ctx) {
    if (state.currentStep.id !== STEP_AUTHORIZE) {
      return {
        kind: "error",
        message: `Unknown wizard step: ${state.currentStep.id}`,
      };
    }

    const parsed = CallbackInput.safeParse(input);
    if (!parsed.success) {
      return { kind: "error", message: "Missing GitHub callback code" };
    }

    const creds = readClientCreds();
    if (!creds) {
      return {
        kind: "error",
        message: "GitHub plugin missing GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET",
      };
    }

    const redirectUri = typeof state.data.redirectUri === "string" ? state.data.redirectUri : "";
    if (!redirectUri) {
      return {
        kind: "error",
        message: "Wizard state missing redirect URI — restart the flow",
      };
    }

    // Exchange the code for an access token.
    let tokenResponse;
    try {
      tokenResponse = await fetch(GITHUB_TOKEN_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: new URLSearchParams({
          client_id: creds.clientId,
          client_secret: creds.clientSecret,
          code: parsed.data.code,
          redirect_uri: redirectUri,
        }).toString(),
      });
    } catch (err) {
      return {
        kind: "error",
        message: `Failed to reach GitHub: ${err instanceof Error ? err.message : err}`,
      };
    }
    if (!tokenResponse.ok) {
      return {
        kind: "error",
        message: `GitHub token endpoint returned ${tokenResponse.status}`,
      };
    }
    const tokenJson = (await tokenResponse.json()) as {
      access_token?: unknown;
      error?: unknown;
      error_description?: unknown;
    };
    if (typeof tokenJson.error === "string") {
      return {
        kind: "error",
        message: `GitHub: ${typeof tokenJson.error_description === "string" ? tokenJson.error_description : tokenJson.error}`,
      };
    }
    if (typeof tokenJson.access_token !== "string") {
      return { kind: "error", message: "GitHub did not return an access_token" };
    }

    // Look up the user.
    const userResponse = await fetch(GITHUB_USER_URL, {
      headers: {
        Authorization: `Bearer ${tokenJson.access_token}`,
        // GitHub recommends a User-Agent identifying the app.
        "User-Agent": "Minister",
        Accept: "application/vnd.github+json",
      },
    });
    if (!userResponse.ok) {
      return {
        kind: "error",
        message: `GitHub /user returned ${userResponse.status}`,
      };
    }
    const userParse = GithubUser.safeParse(await userResponse.json());
    if (!userParse.success) {
      return {
        kind: "error",
        message: "GitHub returned an unexpected user shape",
      };
    }
    const ghUser = userParse.data;

    const badges = buildGithubBadges(
      {
        id: ghUser.id,
        login: ghUser.login,
        createdAt: ghUser.created_at,
        followers: ghUser.followers,
      },
      new Date(),
    );

    // Audit the derived badge TYPES + the revealed handle only. The numeric
    // github id (the Sybil anchor) is DELIBERATELY NOT logged: it is a raw
    // anchor that must be discarded after nullification, and the AuditLog is one
    // of the at-rest stores it must never land in (this used to leak it).
    await ctx.audit.log("plugin.github.verified", {
      handle: ghUser.login,
      issuedTypes: badges.map((b) => b.type),
    });

    return { kind: "complete", badges };
  },
};
