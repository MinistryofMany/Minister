import { z } from "zod";

import type { Plugin } from "@minister/plugin-sdk";

import { pkcePair, randomToken } from "../oauth-common";
import { buildXBadges } from "./derive";

const STEP_AUTHORIZE = "x-authorize";

const X_AUTHORIZE_URL = "https://twitter.com/i/oauth2/authorize";
const X_TOKEN_URL = "https://api.twitter.com/2/oauth2/token";
const X_ME_URL = "https://api.twitter.com/2/users/me?user.fields=created_at";

// users.read needs tweet.read alongside it to call /2/users/me.
const REQUESTED_SCOPES = "users.read tweet.read";

const CallbackInput = z.object({
  code: z.string().min(1),
});

const XMe = z.object({
  data: z.object({
    id: z.string().min(1),
    username: z.string().min(1),
    created_at: z.string().min(1).optional(),
  }),
});

function readClientCreds(): { clientId: string; clientSecret: string } | null {
  const clientId = process.env.X_CLIENT_ID;
  const clientSecret = process.env.X_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret };
}

export const xPlugin: Plugin = {
  manifest: {
    id: "x",
    name: "X (Twitter)",
    description:
      "Prove you control an X (Twitter) account. Issues an `oauth-account` badge plus, when the " +
      "account is old enough, a coarse account-age badge. The badge records only your @handle, " +
      "never your internal X id.",
    badgeTypes: ["oauth-account", "account-age"],
    requiresExtension: false,
    iconKey: "link",
  },

  isConfigured() {
    return readClientCreds() !== null;
  },

  async startWizard(ctx) {
    const creds = readClientCreds();
    if (!creds) {
      throw new Error("X plugin is not configured: set X_CLIENT_ID and X_CLIENT_SECRET");
    }

    const state = randomToken();
    // X mandates PKCE (S256) on the OAuth 2.0 auth-code flow. The verifier is
    // stashed server-side and replayed at the token exchange.
    const { verifier, challenge } = pkcePair();
    const redirectUri = `${ctx.origin}/badges/new/x/callback`;

    const authorizeUrl = new URL(X_AUTHORIZE_URL);
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("client_id", creds.clientId);
    authorizeUrl.searchParams.set("redirect_uri", redirectUri);
    authorizeUrl.searchParams.set("scope", REQUESTED_SCOPES);
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("code_challenge", challenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    await ctx.audit.log("plugin.x.authorize_initiated", {});

    return {
      pluginId: "x",
      userId: ctx.userId,
      currentStep: {
        id: STEP_AUTHORIZE,
        kind: "redirect",
        payload: {
          url: authorizeUrl.toString(),
          description:
            "We'll send you to X to authorize this badge. After you approve, you'll bounce back here and Minister will issue the credential.",
          expectedState: state,
        },
      },
      // redirectUri must match at the token endpoint; codeVerifier completes the
      // PKCE exchange. Both are server-side only (toClientState scrubs `data`).
      data: { redirectUri, codeVerifier: verifier },
    };
  },

  async handleStep(state, input, ctx) {
    if (state.currentStep.id !== STEP_AUTHORIZE) {
      return { kind: "error", message: `Unknown wizard step: ${state.currentStep.id}` };
    }

    const parsed = CallbackInput.safeParse(input);
    if (!parsed.success) {
      return { kind: "error", message: "Missing X callback code" };
    }

    const creds = readClientCreds();
    if (!creds) {
      return { kind: "error", message: "X plugin missing X_CLIENT_ID / X_CLIENT_SECRET" };
    }

    const redirectUri = typeof state.data.redirectUri === "string" ? state.data.redirectUri : "";
    const codeVerifier = typeof state.data.codeVerifier === "string" ? state.data.codeVerifier : "";
    if (!redirectUri || !codeVerifier) {
      return { kind: "error", message: "Wizard state missing PKCE data — restart the flow" };
    }

    // X authenticates the confidential client with HTTP Basic and completes PKCE
    // with the code_verifier.
    const basic = Buffer.from(`${creds.clientId}:${creds.clientSecret}`).toString("base64");
    let tokenResponse: Response;
    try {
      tokenResponse = await fetch(X_TOKEN_URL, {
        method: "POST",
        headers: {
          Authorization: `Basic ${basic}`,
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: parsed.data.code,
          redirect_uri: redirectUri,
          code_verifier: codeVerifier,
          client_id: creds.clientId,
        }).toString(),
      });
    } catch (err) {
      return {
        kind: "error",
        message: `Failed to reach X: ${err instanceof Error ? err.message : err}`,
      };
    }
    if (!tokenResponse.ok) {
      return { kind: "error", message: `X token endpoint returned ${tokenResponse.status}` };
    }
    const tokenJson = (await tokenResponse.json()) as {
      access_token?: unknown;
      error?: unknown;
      error_description?: unknown;
    };
    if (typeof tokenJson.error === "string") {
      return {
        kind: "error",
        message: `X: ${typeof tokenJson.error_description === "string" ? tokenJson.error_description : tokenJson.error}`,
      };
    }
    if (typeof tokenJson.access_token !== "string") {
      return { kind: "error", message: "X did not return an access_token" };
    }

    const meResponse = await fetch(X_ME_URL, {
      headers: {
        Authorization: `Bearer ${tokenJson.access_token}`,
        Accept: "application/json",
      },
    });
    if (!meResponse.ok) {
      return { kind: "error", message: `X /users/me returned ${meResponse.status}` };
    }
    const meParse = XMe.safeParse(await meResponse.json());
    if (!meParse.success) {
      return { kind: "error", message: "X returned an unexpected user shape" };
    }
    const me = meParse.data.data;

    const badges = buildXBadges(
      { id: me.id, username: me.username, createdAt: me.created_at },
      new Date(),
    );

    await ctx.audit.log("plugin.x.verified", {
      // Neither the numeric id (the anchor) nor the @handle is logged — the
      // AuditLog is an at-rest store that keeps only the issued types.
      issuedTypes: badges.map((b) => b.type),
    });

    return { kind: "complete", badges };
  },
};
