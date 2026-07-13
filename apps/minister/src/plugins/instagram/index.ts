import { randomBytes } from "node:crypto";

import { z } from "zod";

import type { IssuedBadge, Plugin } from "@minister/plugin-sdk";

import { hasEnvCreds } from "../oauth-common";

const STEP_AUTHORIZE = "instagram-authorize";

// IMPORTANT — read before touching this file (see oauth.md "Instagram"):
// Meta shut down the Instagram Basic Display API (Dec 2024), which was the
// only OAuth path that proved control of a plain PERSONAL Instagram account.
// The only remaining OAuth-based identity API is "Instagram API with Facebook
// Login", which reaches ONLY Instagram Business/Creator accounts that are
// linked to a Facebook Page the user administers. This plugin therefore
// proves "you administer a Facebook Page with a linked Instagram
// Business/Creator account" — NOT "you own a personal Instagram account".
// Register the OAuth app at developers.facebook.com (a Meta App with the
// Facebook Login + Instagram products enabled), not at any Instagram-specific
// developer console.
const FACEBOOK_AUTHORIZE_URL = "https://www.facebook.com/v21.0/dialog/oauth";
const FACEBOOK_TOKEN_URL = "https://graph.facebook.com/v21.0/oauth/access_token";
const FACEBOOK_GRAPH_BASE = "https://graph.facebook.com/v21.0";

// `pages_show_list` lists the pages the user administers; `instagram_basic`
// reads the Instagram Business/Creator account linked to one of those pages.
// Both are Advanced Access permissions — Meta App Review is required before
// this works for anyone beyond the app's own admins/testers/developers.
const REQUESTED_SCOPES = "pages_show_list,instagram_basic";

const CallbackInput = z.object({
  code: z.string().min(1),
});

const FacebookPage = z.object({
  id: z.string().min(1),
  // Meta returns a page-scoped access token alongside each page in the same
  // response, so no extra round trip is needed to authenticate the next call.
  access_token: z.string().min(1),
});
const FacebookPagesResponse = z.object({
  data: z.array(FacebookPage).default([]),
});

const PageInstagramLink = z.object({
  instagram_business_account: z.object({ id: z.string().min(1) }).optional(),
});

const InstagramAccount = z.object({
  id: z.string().min(1),
  username: z.string().min(1).optional(),
});

function randomState(): string {
  return randomBytes(24).toString("base64url");
}

function readClientCreds(): { clientId: string; clientSecret: string } | null {
  // Named INSTAGRAM_* to match this plugin's badge provider value, though the
  // underlying credential is a Meta/Facebook App id + secret (a single Meta
  // App has both the Facebook Login and Instagram products enabled).
  const clientId = process.env.INSTAGRAM_CLIENT_ID;
  const clientSecret = process.env.INSTAGRAM_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret };
}

// Walk the user's administered Pages (as returned, no further pagination) and
// return the first Instagram Business/Creator account linked to one of them,
// or null if none is linked. Each lookup is scoped to that page's own
// page-access-token, per Meta's Instagram-via-Facebook-Login pattern.
async function findLinkedInstagramAccount(
  pages: readonly { id: string; access_token: string }[],
): Promise<{ igAccountId: string; pageAccessToken: string } | null> {
  for (const page of pages) {
    const linkResponse = await fetch(
      `${FACEBOOK_GRAPH_BASE}/${page.id}?fields=instagram_business_account&access_token=${encodeURIComponent(page.access_token)}`,
      { headers: { Accept: "application/json" } },
    );
    if (!linkResponse.ok) continue;
    const linkParse = PageInstagramLink.safeParse(await linkResponse.json());
    const igId = linkParse.success ? linkParse.data.instagram_business_account?.id : undefined;
    if (igId) return { igAccountId: igId, pageAccessToken: page.access_token };
  }
  return null;
}

export const instagramPlugin: Plugin = {
  manifest: {
    id: "instagram",
    name: "Instagram",
    description:
      "Prove you administer a Facebook Page with a linked Instagram Business or Creator " +
      "account. Issues an `oauth-account` badge recording the Instagram account's username. " +
      "Meta retired personal-account API access in 2024 — this does NOT prove control of a " +
      "plain personal Instagram account, only a Business/Creator account linked to a Page.",
    badgeTypes: ["oauth-account"],
    requiresExtension: false,
    iconKey: "link",
  },

  // Instagram OAuth is optional at deploy time. Without both credentials the
  // flow is dead, so the host hides the entry rather than routing into a
  // throwing wizard.
  isConfigured() {
    return hasEnvCreds(["INSTAGRAM_CLIENT_ID", "INSTAGRAM_CLIENT_SECRET"]);
  },

  async startWizard(ctx) {
    const creds = readClientCreds();
    if (!creds) {
      throw new Error(
        "Instagram plugin is not configured: set INSTAGRAM_CLIENT_ID and INSTAGRAM_CLIENT_SECRET",
      );
    }

    const state = randomState();
    const redirectUri = `${ctx.origin}/badges/new/instagram/callback`;
    const authorizeUrl = new URL(FACEBOOK_AUTHORIZE_URL);
    authorizeUrl.searchParams.set("client_id", creds.clientId);
    authorizeUrl.searchParams.set("redirect_uri", redirectUri);
    authorizeUrl.searchParams.set("scope", REQUESTED_SCOPES);
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("response_type", "code");

    await ctx.audit.log("plugin.instagram.authorize_initiated", {});

    return {
      pluginId: "instagram",
      userId: ctx.userId,
      currentStep: {
        id: STEP_AUTHORIZE,
        kind: "redirect",
        payload: {
          url: authorizeUrl.toString(),
          description:
            "We'll send you to Facebook to authorize this badge against a Facebook Page you " +
            "administer with a linked Instagram Business or Creator account. After you " +
            "approve, you'll bounce back here and Minister will issue the credential.",
          expectedState: state,
        },
      },
      // redirectUri must match at the token endpoint.
      data: { redirectUri },
    };
  },

  async handleStep(state, input, ctx) {
    if (state.currentStep.id !== STEP_AUTHORIZE) {
      return { kind: "error", message: `Unknown wizard step: ${state.currentStep.id}` };
    }

    const parsed = CallbackInput.safeParse(input);
    if (!parsed.success) {
      return { kind: "error", message: "Missing Instagram callback code" };
    }

    const creds = readClientCreds();
    if (!creds) {
      return {
        kind: "error",
        message: "Instagram plugin missing INSTAGRAM_CLIENT_ID / INSTAGRAM_CLIENT_SECRET",
      };
    }

    const redirectUri = typeof state.data.redirectUri === "string" ? state.data.redirectUri : "";
    if (!redirectUri) {
      return { kind: "error", message: "Wizard state missing redirect URI — restart the flow" };
    }

    const tokenUrl = new URL(FACEBOOK_TOKEN_URL);
    tokenUrl.searchParams.set("client_id", creds.clientId);
    tokenUrl.searchParams.set("client_secret", creds.clientSecret);
    tokenUrl.searchParams.set("redirect_uri", redirectUri);
    tokenUrl.searchParams.set("code", parsed.data.code);

    let tokenResponse: Response;
    try {
      tokenResponse = await fetch(tokenUrl.toString(), { headers: { Accept: "application/json" } });
    } catch (err) {
      return {
        kind: "error",
        message: `Failed to reach Facebook: ${err instanceof Error ? err.message : err}`,
      };
    }
    if (!tokenResponse.ok) {
      return { kind: "error", message: `Facebook token endpoint returned ${tokenResponse.status}` };
    }
    const tokenJson = (await tokenResponse.json()) as {
      access_token?: unknown;
      error?: unknown;
    };
    if (tokenJson.error) {
      return { kind: "error", message: `Facebook: ${JSON.stringify(tokenJson.error)}` };
    }
    if (typeof tokenJson.access_token !== "string") {
      return { kind: "error", message: "Facebook did not return an access_token" };
    }

    const pagesResponse = await fetch(
      `${FACEBOOK_GRAPH_BASE}/me/accounts?access_token=${encodeURIComponent(tokenJson.access_token)}`,
      { headers: { Accept: "application/json" } },
    );
    if (!pagesResponse.ok) {
      return { kind: "error", message: `Facebook Pages endpoint returned ${pagesResponse.status}` };
    }
    const pagesParse = FacebookPagesResponse.safeParse(await pagesResponse.json());
    if (!pagesParse.success) {
      return { kind: "error", message: "Facebook returned an unexpected Pages shape" };
    }

    const linked = await findLinkedInstagramAccount(pagesParse.data.data);
    if (!linked) {
      return {
        kind: "error",
        message:
          "No Instagram Business or Creator account found linked to a Facebook Page you " +
          "administer. This badge requires a Business or Creator Instagram account linked to " +
          "a Facebook Page — a plain personal account cannot be verified.",
      };
    }

    const igResponse = await fetch(
      `${FACEBOOK_GRAPH_BASE}/${linked.igAccountId}?fields=id,username&access_token=${encodeURIComponent(linked.pageAccessToken)}`,
      { headers: { Accept: "application/json" } },
    );
    if (!igResponse.ok) {
      return { kind: "error", message: `Instagram account lookup returned ${igResponse.status}` };
    }
    const igParse = InstagramAccount.safeParse(await igResponse.json());
    if (!igParse.success) {
      return { kind: "error", message: "Instagram returned an unexpected account shape" };
    }
    const ig = igParse.data;

    // The immutable Instagram Business Account id is the Sybil anchor:
    // nullified and discarded. Only the renameable username is disclosed.
    const claims: Record<string, unknown> = { provider: "instagram" };
    if (ig.username) claims.handle = ig.username;
    const badge: IssuedBadge = {
      type: "oauth-account",
      attributes: { ...claims },
      claims,
      sybilAnchor: ig.id,
    };

    // Audit the issued types only — neither the anchor nor the handle is
    // logged, matching the other oauth providers.
    await ctx.audit.log("plugin.instagram.verified", {
      issuedTypes: ["oauth-account"],
    });

    return { kind: "complete", badges: [badge] };
  },
};
