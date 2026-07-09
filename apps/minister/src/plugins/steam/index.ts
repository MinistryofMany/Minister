import { z } from "zod";

import type { IssuedBadge, Plugin } from "@minister/plugin-sdk";

import { randomToken } from "../oauth-common";
import {
  STEAM_OPENID_ENDPOINT,
  assertionIsValid,
  buildCheckAuthParams,
  parseSteamId,
  signedFieldsCoverRequired,
} from "./verify";

const STEP_AUTHORIZE = "steam-openid";

const OPENID_NS = "http://specs.openid.net/auth/2.0";
const OPENID_IDENTIFIER_SELECT = "http://specs.openid.net/auth/2.0/identifier_select";

// Steam's optional Web API key buys only the display persona name. The core
// ownership proof (OpenID assertion) needs NO secret, so this plugin is ALWAYS
// available — there is nothing to fail closed on.
function personaApiKey(): string | null {
  return process.env.STEAM_WEB_API_KEY || null;
}

const CallbackInput = z.object({
  // Every openid.* param the callback received, echoed verbatim for the
  // check_authentication post-back.
  openid: z.record(z.string(), z.string()),
});

async function fetchPersona(steamId: string): Promise<string | undefined> {
  const key = personaApiKey();
  if (!key) return undefined;
  try {
    const url = new URL("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/");
    url.searchParams.set("key", key);
    url.searchParams.set("steamids", steamId);
    const res = await fetch(url.toString());
    if (!res.ok) return undefined;
    const json = (await res.json()) as {
      response?: { players?: Array<{ personaname?: unknown }> };
    };
    const name = json.response?.players?.[0]?.personaname;
    return typeof name === "string" && name.length > 0 ? name : undefined;
  } catch {
    // Persona is a nice-to-have; a lookup failure must not sink the badge.
    return undefined;
  }
}

export const steamPlugin: Plugin = {
  manifest: {
    id: "steam",
    name: "Steam",
    description:
      "Prove you control a Steam account via Steam's OpenID sign-in. Issues an `oauth-account` " +
      "badge. Your public persona name is included only if the server has a Steam Web API key; " +
      "the badge never records anything beyond that.",
    badgeTypes: ["oauth-account"],
    requiresExtension: false,
    iconKey: "link",
  },

  // No isConfigured probe: the core proof needs no credentials, so Steam is
  // always offered.

  async startWizard(ctx) {
    const state = randomToken();
    // Steam echoes the return_to URL back verbatim, so our correlation token
    // rides as its `state` query param; the callback resolves the wizard session
    // by it. Steam does not preserve an arbitrary top-level `state`, only
    // return_to, so it must live inside the URL.
    const returnTo = `${ctx.origin}/badges/new/steam/callback?state=${encodeURIComponent(state)}`;

    const authorizeUrl = new URL(STEAM_OPENID_ENDPOINT);
    authorizeUrl.searchParams.set("openid.ns", OPENID_NS);
    authorizeUrl.searchParams.set("openid.mode", "checkid_setup");
    authorizeUrl.searchParams.set("openid.return_to", returnTo);
    authorizeUrl.searchParams.set("openid.realm", ctx.origin);
    authorizeUrl.searchParams.set("openid.identity", OPENID_IDENTIFIER_SELECT);
    authorizeUrl.searchParams.set("openid.claimed_id", OPENID_IDENTIFIER_SELECT);

    await ctx.audit.log("plugin.steam.authorize_initiated", {});

    return {
      pluginId: "steam",
      userId: ctx.userId,
      currentStep: {
        id: STEP_AUTHORIZE,
        kind: "redirect",
        payload: {
          url: authorizeUrl.toString(),
          description:
            "We'll send you to Steam to sign in. After you approve, you'll bounce back here and Minister will issue the credential.",
          expectedState: state,
        },
      },
      // Bind the assertion to the exact return_to we sent (defense in depth on
      // top of the state/pendingToken match).
      data: { expectedReturnTo: returnTo },
    };
  },

  async handleStep(state, input, ctx) {
    if (state.currentStep.id !== STEP_AUTHORIZE) {
      return { kind: "error", message: `Unknown wizard step: ${state.currentStep.id}` };
    }

    const parsed = CallbackInput.safeParse(input);
    if (!parsed.success) {
      return { kind: "error", message: "Missing Steam OpenID response" };
    }
    const openid = parsed.data.openid;

    // Steam signals a successful assertion with mode=id_res.
    if (openid["openid.mode"] !== "id_res") {
      return { kind: "error", message: "Steam did not return a positive assertion" };
    }

    // The return_to Steam echoes must match what we sent — else this assertion
    // belongs to a different request.
    const expectedReturnTo =
      typeof state.data.expectedReturnTo === "string" ? state.data.expectedReturnTo : "";
    if (!expectedReturnTo || openid["openid.return_to"] !== expectedReturnTo) {
      return { kind: "error", message: "Steam assertion did not match this request — restart it" };
    }

    // OpenID 2.0 signature-coverage check: unless the fields we trust are all in
    // `openid.signed`, a `is_valid:true` from check_authentication proves nothing
    // about claimed_id / return_to — they could be unsigned and attacker-swapped.
    if (!signedFieldsCoverRequired(openid["openid.signed"])) {
      return {
        kind: "error",
        message: "Steam assertion did not sign the required fields — restart it",
      };
    }

    // Pin the OP endpoint. `op_endpoint` is one of the signed fields (checked
    // above), so requiring it to equal Steam's endpoint stops a signature minted
    // by a different OpenID provider from being replayed here.
    if (openid["openid.op_endpoint"] !== STEAM_OPENID_ENDPOINT) {
      return {
        kind: "error",
        message: "Steam assertion came from an unexpected OpenID endpoint — restart it",
      };
    }

    const claimedId = openid["openid.claimed_id"] ?? "";
    const steamId = parseSteamId(claimedId);
    if (!steamId) {
      return { kind: "error", message: "Steam returned an unexpected identity" };
    }

    // Verify the assertion by posting it back to Steam (check_authentication).
    // We trust the identity ONLY after Steam confirms is_valid:true.
    let verifyResponse: Response;
    try {
      verifyResponse = await fetch(STEAM_OPENID_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: buildCheckAuthParams(openid).toString(),
      });
    } catch (err) {
      return {
        kind: "error",
        message: `Failed to reach Steam: ${err instanceof Error ? err.message : err}`,
      };
    }
    if (!verifyResponse.ok) {
      return { kind: "error", message: `Steam verification returned ${verifyResponse.status}` };
    }
    if (!assertionIsValid(await verifyResponse.text())) {
      return { kind: "error", message: "Steam rejected the assertion — it may be forged or stale" };
    }

    const handle = await fetchPersona(steamId);

    // The immutable steamid64 is the Sybil anchor: nullified and discarded by the
    // runtime. Only the renameable persona (when available) is disclosed.
    const claims: Record<string, unknown> = { provider: "steam" };
    if (handle) claims.handle = handle;
    const badge: IssuedBadge = {
      type: "oauth-account",
      attributes: { ...claims },
      claims,
      sybilAnchor: steamId,
    };

    await ctx.audit.log("plugin.steam.verified", {
      // The steamid64 is the raw anchor and never logged; the persona (if any) is
      // already public and is what the badge discloses.
      handle: handle ?? null,
      issuedTypes: ["oauth-account"],
    });

    return { kind: "complete", badges: [badge] };
  },
};
