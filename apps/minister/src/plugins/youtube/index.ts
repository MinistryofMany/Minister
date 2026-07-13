import { z } from "zod";

import type { IssuedBadge, Plugin } from "@minister/plugin-sdk";

import { hasEnvCreds, pkcePair, randomToken } from "../oauth-common";

const STEP_AUTHORIZE = "youtube-authorize";

// Same Google Cloud project / OAuth client as the google plugin — Google does
// not require a SEPARATE registered app per product, only the API (YouTube
// Data API v3) enabled and the scope requested at authorize time. We reuse
// GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET rather than adding a parallel
// YOUTUBE_CLIENT_ID pair, so there is exactly one Google OAuth client to
// provision and rotate.
const GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const YOUTUBE_CHANNELS_URL =
  "https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true";

// youtube.readonly is a SENSITIVE scope (unlike google/index.ts's `openid
// email`): it requires Google OAuth app verification/review before it works
// for anyone beyond the app's registered test users. That review is a
// deployment-time prerequisite, not something this plugin can route around —
// see oauth.md.
const REQUESTED_SCOPES = "https://www.googleapis.com/auth/youtube.readonly";

const CallbackInput = z.object({
  code: z.string().min(1),
});

const YoutubeChannelsResponse = z.object({
  items: z
    .array(
      z.object({
        // The channel id is immutable and unique per Google account's YouTube
        // presence — the Sybil anchor.
        id: z.string().min(1),
        snippet: z
          .object({
            title: z.string().min(1).optional(),
            // The `@handle`-style customUrl, when the channel has claimed one.
            // Preferred as the disclosed handle over the freeform title.
            customUrl: z.string().min(1).optional(),
          })
          .optional(),
      }),
    )
    .default([]),
});

function readClientCreds(): { clientId: string; clientSecret: string } | null {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret };
}

export const youtubePlugin: Plugin = {
  manifest: {
    id: "youtube",
    name: "YouTube",
    description:
      "Prove you control a YouTube channel. Issues an `oauth-account` badge recording your " +
      "channel's public handle. Shares Minister's Google OAuth client (GOOGLE_CLIENT_ID / " +
      "GOOGLE_CLIENT_SECRET) — same Google Cloud project as the Google plugin, just a " +
      "different requested scope and API. Requires Google OAuth app verification for the " +
      "sensitive `youtube.readonly` scope before it works beyond registered test users.",
    badgeTypes: ["oauth-account"],
    requiresExtension: false,
    iconKey: "link",
  },

  isConfigured() {
    return hasEnvCreds(["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"]);
  },

  async startWizard(ctx) {
    const creds = readClientCreds();
    if (!creds) {
      throw new Error(
        "YouTube plugin is not configured: set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET",
      );
    }

    const state = randomToken();
    // PKCE (S256): the verifier is stashed server-side and replayed at the token
    // exchange, binding this authorization code to this browser session.
    const { verifier, challenge } = pkcePair();
    const redirectUri = `${ctx.origin}/badges/new/youtube/callback`;
    const authorizeUrl = new URL(GOOGLE_AUTHORIZE_URL);
    authorizeUrl.searchParams.set("client_id", creds.clientId);
    authorizeUrl.searchParams.set("redirect_uri", redirectUri);
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("scope", REQUESTED_SCOPES);
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("code_challenge", challenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    await ctx.audit.log("plugin.youtube.authorize_initiated", {});

    return {
      pluginId: "youtube",
      userId: ctx.userId,
      currentStep: {
        id: STEP_AUTHORIZE,
        kind: "redirect",
        payload: {
          url: authorizeUrl.toString(),
          description:
            "We'll send you to Google to authorize this badge against your YouTube channel. " +
            "After you approve, you'll bounce back here and Minister will issue the credential.",
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
      return { kind: "error", message: "Missing YouTube callback code" };
    }

    const creds = readClientCreds();
    if (!creds) {
      return {
        kind: "error",
        message: "YouTube plugin missing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET",
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

    const channelsResponse = await fetch(YOUTUBE_CHANNELS_URL, {
      headers: {
        Authorization: `Bearer ${tokenJson.access_token}`,
        Accept: "application/json",
      },
    });
    if (!channelsResponse.ok) {
      return {
        kind: "error",
        message: `YouTube channels endpoint returned ${channelsResponse.status}`,
      };
    }
    const channelsParse = YoutubeChannelsResponse.safeParse(await channelsResponse.json());
    if (!channelsParse.success) {
      return { kind: "error", message: "YouTube returned an unexpected channels shape" };
    }
    const channel = channelsParse.data.items[0];
    if (!channel) {
      return {
        kind: "error",
        message: "No YouTube channel found for this Google account — create a channel first",
      };
    }

    // The immutable channel id is the Sybil anchor: nullified and discarded. The
    // disclosed handle prefers the claimed `@handle`-style customUrl over the
    // freeform display title (renameable but still recognizable).
    const handle = channel.snippet?.customUrl ?? channel.snippet?.title;
    const claims: Record<string, unknown> = { provider: "youtube" };
    if (handle) claims.handle = handle;
    const badge: IssuedBadge = {
      type: "oauth-account",
      attributes: { ...claims },
      claims,
      sybilAnchor: channel.id,
    };

    // Audit the issued types only — neither the immutable channel id (the
    // anchor) nor the handle is logged, matching the other oauth providers.
    await ctx.audit.log("plugin.youtube.verified", {
      issuedTypes: ["oauth-account"],
    });

    return { kind: "complete", badges: [badge] };
  },
};
