import { z } from "zod";

import type { Plugin } from "@minister/plugin-sdk";

import { pkcePair, randomToken } from "../oauth-common";
import { buildRedditBadges } from "./derive";

const STEP_AUTHORIZE = "reddit-authorize";

const REDDIT_AUTHORIZE_URL = "https://www.reddit.com/api/v1/authorize";
const REDDIT_TOKEN_URL = "https://www.reddit.com/api/v1/access_token";
const REDDIT_ME_URL = "https://oauth.reddit.com/api/v1/me";

// Reddit issues an identity-scoped token; `/api/v1/me` returns id + name.
const REQUESTED_SCOPES = "identity";
// Reddit rejects requests without a descriptive, non-generic User-Agent.
const USER_AGENT = "Minister/1.0 (badge verifier; +https://ministry.id)";

const CallbackInput = z.object({
  code: z.string().min(1),
});

const RedditUser = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  // `created_utc` is unix SECONDS (a float). Optional: a partial response still
  // yields the oauth-account badge.
  created_utc: z.number().optional(),
});

function readClientCreds(): { clientId: string; clientSecret: string } | null {
  const clientId = process.env.REDDIT_CLIENT_ID;
  const clientSecret = process.env.REDDIT_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret };
}

export const redditPlugin: Plugin = {
  manifest: {
    id: "reddit",
    name: "Reddit",
    description:
      "Prove you control a Reddit account. Issues an `oauth-account` badge plus, when the " +
      "account is old enough, a coarse account-age badge. The badge records only your " +
      "username, never your internal Reddit id.",
    badgeTypes: ["oauth-account", "account-age"],
    requiresExtension: false,
    iconKey: "link",
  },

  // Reddit OAuth is optional at deploy time. Without both credentials the flow
  // is dead, so the host hides the entry rather than routing into a throwing
  // wizard.
  isConfigured() {
    return readClientCreds() !== null;
  },

  async startWizard(ctx) {
    const creds = readClientCreds();
    if (!creds) {
      throw new Error(
        "Reddit plugin is not configured: set REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET",
      );
    }

    const state = randomToken();
    // PKCE (S256): the verifier is stashed server-side and replayed at the token
    // exchange, binding this authorization code to this browser session.
    const { verifier, challenge } = pkcePair();
    const redirectUri = `${ctx.origin}/badges/new/reddit/callback`;
    const authorizeUrl = new URL(REDDIT_AUTHORIZE_URL);
    authorizeUrl.searchParams.set("client_id", creds.clientId);
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("redirect_uri", redirectUri);
    // A temporary token is all we need — we read /me once, then discard it.
    authorizeUrl.searchParams.set("duration", "temporary");
    authorizeUrl.searchParams.set("scope", REQUESTED_SCOPES);
    authorizeUrl.searchParams.set("code_challenge", challenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    await ctx.audit.log("plugin.reddit.authorize_initiated", {});

    return {
      pluginId: "reddit",
      userId: ctx.userId,
      currentStep: {
        id: STEP_AUTHORIZE,
        kind: "redirect",
        payload: {
          url: authorizeUrl.toString(),
          description:
            "We'll send you to Reddit to authorize this badge. After you approve, you'll bounce back here and Minister will issue the credential.",
          expectedState: state,
        },
      },
      // Reddit requires the same redirect_uri at /access_token; stash it alongside
      // the PKCE verifier. Both are server-side only (toClientState scrubs `data`).
      data: { redirectUri, codeVerifier: verifier },
    };
  },

  async handleStep(state, input, ctx) {
    if (state.currentStep.id !== STEP_AUTHORIZE) {
      return { kind: "error", message: `Unknown wizard step: ${state.currentStep.id}` };
    }

    const parsed = CallbackInput.safeParse(input);
    if (!parsed.success) {
      return { kind: "error", message: "Missing Reddit callback code" };
    }

    const creds = readClientCreds();
    if (!creds) {
      return {
        kind: "error",
        message: "Reddit plugin missing REDDIT_CLIENT_ID / REDDIT_CLIENT_SECRET",
      };
    }

    const redirectUri = typeof state.data.redirectUri === "string" ? state.data.redirectUri : "";
    const codeVerifier = typeof state.data.codeVerifier === "string" ? state.data.codeVerifier : "";
    if (!redirectUri || !codeVerifier) {
      return { kind: "error", message: "Wizard state missing PKCE data — restart the flow" };
    }

    // Exchange the code for an access token. Reddit authenticates the client
    // with HTTP Basic (client_id:client_secret), NOT body params, and completes
    // PKCE with the code_verifier.
    const basic = Buffer.from(`${creds.clientId}:${creds.clientSecret}`).toString("base64");
    let tokenResponse: Response;
    try {
      tokenResponse = await fetch(REDDIT_TOKEN_URL, {
        method: "POST",
        headers: {
          Authorization: `Basic ${basic}`,
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
          "User-Agent": USER_AGENT,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: parsed.data.code,
          redirect_uri: redirectUri,
          code_verifier: codeVerifier,
        }).toString(),
      });
    } catch (err) {
      return {
        kind: "error",
        message: `Failed to reach Reddit: ${err instanceof Error ? err.message : err}`,
      };
    }
    if (!tokenResponse.ok) {
      return { kind: "error", message: `Reddit token endpoint returned ${tokenResponse.status}` };
    }
    const tokenJson = (await tokenResponse.json()) as {
      access_token?: unknown;
      error?: unknown;
    };
    if (typeof tokenJson.error === "string") {
      return { kind: "error", message: `Reddit: ${tokenJson.error}` };
    }
    if (typeof tokenJson.access_token !== "string") {
      return { kind: "error", message: "Reddit did not return an access_token" };
    }

    // Look up the user.
    const meResponse = await fetch(REDDIT_ME_URL, {
      headers: {
        Authorization: `Bearer ${tokenJson.access_token}`,
        "User-Agent": USER_AGENT,
        Accept: "application/json",
      },
    });
    if (!meResponse.ok) {
      return { kind: "error", message: `Reddit /me returned ${meResponse.status}` };
    }
    const userParse = RedditUser.safeParse(await meResponse.json());
    if (!userParse.success) {
      return { kind: "error", message: "Reddit returned an unexpected user shape" };
    }
    const user = userParse.data;

    const badges = buildRedditBadges(
      { id: user.id, name: user.name, createdUtc: user.created_utc },
      new Date(),
    );

    // Audit the issued types only. Neither the immutable Reddit fullname (the
    // Sybil anchor) nor the username handle is logged — the AuditLog is an at-rest
    // store that keeps no account-identifying value.
    await ctx.audit.log("plugin.reddit.verified", {
      issuedTypes: badges.map((b) => b.type),
    });

    return { kind: "complete", badges };
  },
};
