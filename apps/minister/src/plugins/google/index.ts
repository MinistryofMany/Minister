import { z } from "zod";

import type { IssuedBadge, Plugin } from "@minister/plugin-sdk";

import { pkcePair, randomToken } from "../oauth-common";

const STEP_AUTHORIZE = "google-authorize";

const GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";

// Tier-1 only: plain account ownership via OpenID Connect. `openid email` is a
// non-sensitive scope set (no Google security review). YouTube channel ownership
// needs youtube.readonly, a sensitive scope requiring app review — that is a
// deliberate follow-on, documented in oauth.md, NOT built here.
const REQUESTED_SCOPES = "openid email";

const CallbackInput = z.object({
  code: z.string().min(1),
});

const GoogleUserinfo = z.object({
  // Google's stable, immutable subject id. The Sybil anchor.
  sub: z.string().min(1),
  email: z.string().email().optional(),
  email_verified: z.boolean().optional(),
});

function readClientCreds(): { clientId: string; clientSecret: string } | null {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret };
}

export const googlePlugin: Plugin = {
  manifest: {
    id: "google",
    name: "Google",
    description:
      "Prove you control a Google account. Issues an `oauth-account` badge recording your " +
      "verified email address. YouTube channel ownership is a separate, future flow.",
    badgeTypes: ["oauth-account"],
    requiresExtension: false,
    iconKey: "link",
  },

  isConfigured() {
    return readClientCreds() !== null;
  },

  async startWizard(ctx) {
    const creds = readClientCreds();
    if (!creds) {
      throw new Error(
        "Google plugin is not configured: set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET",
      );
    }

    const state = randomToken();
    // PKCE (S256): the verifier is stashed server-side and replayed at the token
    // exchange, binding this authorization code to this browser session.
    const { verifier, challenge } = pkcePair();
    const redirectUri = `${ctx.origin}/badges/new/google/callback`;
    const authorizeUrl = new URL(GOOGLE_AUTHORIZE_URL);
    authorizeUrl.searchParams.set("client_id", creds.clientId);
    authorizeUrl.searchParams.set("redirect_uri", redirectUri);
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("scope", REQUESTED_SCOPES);
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("code_challenge", challenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    await ctx.audit.log("plugin.google.authorize_initiated", {});

    return {
      pluginId: "google",
      userId: ctx.userId,
      currentStep: {
        id: STEP_AUTHORIZE,
        kind: "redirect",
        payload: {
          url: authorizeUrl.toString(),
          description:
            "We'll send you to Google to authorize this badge. After you approve, you'll bounce back here and Minister will issue the credential.",
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
      return { kind: "error", message: "Missing Google callback code" };
    }

    const creds = readClientCreds();
    if (!creds) {
      return {
        kind: "error",
        message: "Google plugin missing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET",
      };
    }

    const redirectUri = typeof state.data.redirectUri === "string" ? state.data.redirectUri : "";
    const codeVerifier = typeof state.data.codeVerifier === "string" ? state.data.codeVerifier : "";
    if (!redirectUri || !codeVerifier) {
      return { kind: "error", message: "Wizard state missing PKCE data — restart the flow" };
    }

    let tokenResponse: Response;
    try {
      tokenResponse = await fetch(GOOGLE_TOKEN_URL, {
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
          grant_type: "authorization_code",
          code_verifier: codeVerifier,
        }).toString(),
      });
    } catch (err) {
      return {
        kind: "error",
        message: `Failed to reach Google: ${err instanceof Error ? err.message : err}`,
      };
    }
    if (!tokenResponse.ok) {
      return { kind: "error", message: `Google token endpoint returned ${tokenResponse.status}` };
    }
    const tokenJson = (await tokenResponse.json()) as {
      access_token?: unknown;
      error?: unknown;
      error_description?: unknown;
    };
    if (typeof tokenJson.error === "string") {
      return {
        kind: "error",
        message: `Google: ${typeof tokenJson.error_description === "string" ? tokenJson.error_description : tokenJson.error}`,
      };
    }
    if (typeof tokenJson.access_token !== "string") {
      return { kind: "error", message: "Google did not return an access_token" };
    }

    const userResponse = await fetch(GOOGLE_USERINFO_URL, {
      headers: {
        Authorization: `Bearer ${tokenJson.access_token}`,
        Accept: "application/json",
      },
    });
    if (!userResponse.ok) {
      return { kind: "error", message: `Google userinfo returned ${userResponse.status}` };
    }
    const userParse = GoogleUserinfo.safeParse(await userResponse.json());
    if (!userParse.success) {
      return { kind: "error", message: "Google returned an unexpected userinfo shape" };
    }
    const info = userParse.data;

    // The immutable `sub` is the Sybil anchor: nullified and discarded. Only a
    // VERIFIED email address is disclosed as the handle (renameable / separable
    // from the anchor).
    const claims: Record<string, unknown> = { provider: "google" };
    if (info.email && info.email_verified) claims.handle = info.email;
    const badge: IssuedBadge = {
      type: "oauth-account",
      attributes: { ...claims },
      claims,
      sybilAnchor: info.sub,
    };

    // The verified email is PII; the AuditLog is a long-lived at-rest store, so
    // record only the email DOMAIN (never the local part), matching the
    // anchor-discipline the other providers keep. `sub` (the anchor) is never
    // logged.
    const emailDomain =
      typeof claims.handle === "string" ? (claims.handle.split("@").at(-1) ?? null) : null;
    await ctx.audit.log("plugin.google.verified", {
      emailDomain,
      issuedTypes: ["oauth-account"],
    });

    return { kind: "complete", badges: [badge] };
  },
};
