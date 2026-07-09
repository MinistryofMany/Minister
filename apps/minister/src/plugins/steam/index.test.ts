import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

import { steamPlugin } from "./index";

function ctx(): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
  };
}

const RETURN_TO = "http://localhost:3000/badges/new/steam/callback?state=STATE";
const CLAIMED = "https://steamcommunity.com/openid/id/76561198000000000";
const OP_ENDPOINT = "https://steamcommunity.com/openid/login";
// The full signed-field set Steam covers on a genuine assertion.
const SIGNED_ALL = "signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle";

describe("steamPlugin.startWizard", () => {
  it("redirects to steam OpenID with return_to carrying our state token", async () => {
    const state = await steamPlugin.startWizard(ctx());
    expect(state.currentStep.kind).toBe("redirect");
    if (state.currentStep.kind !== "redirect") throw new Error("kind");
    const url = new URL(state.currentStep.payload.url);
    expect(url.origin + url.pathname).toBe("https://steamcommunity.com/openid/login");
    expect(url.searchParams.get("openid.mode")).toBe("checkid_setup");
    const returnTo = url.searchParams.get("openid.return_to")!;
    const token = state.currentStep.payload.expectedState!;
    expect(returnTo).toContain(`state=${encodeURIComponent(token)}`);
    expect(state.data.expectedReturnTo).toBe(returnTo);
  });
});

describe("steamPlugin.handleStep validation", () => {
  function authState(): WizardState {
    return {
      pluginId: "steam",
      userId: "user_test",
      currentStep: {
        id: "steam-openid",
        kind: "redirect",
        payload: { url: "https://steamcommunity.com/openid/login?...", expectedState: "STATE" },
      },
      data: { expectedReturnTo: RETURN_TO },
    };
  }

  it("rejects a non-id_res mode", async () => {
    const result = await steamPlugin.handleStep(
      authState(),
      { openid: { "openid.mode": "cancel" } },
      ctx(),
    );
    expect(result.kind).toBe("error");
  });

  it("rejects a return_to that does not match the request", async () => {
    const result = await steamPlugin.handleStep(
      authState(),
      {
        openid: {
          "openid.mode": "id_res",
          "openid.return_to": "http://localhost:3000/badges/new/steam/callback?state=OTHER",
          "openid.claimed_id": CLAIMED,
        },
      },
      ctx(),
    );
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("did not match");
  });

  it("rejects a malformed claimed_id", async () => {
    const result = await steamPlugin.handleStep(
      authState(),
      {
        openid: {
          "openid.mode": "id_res",
          "openid.return_to": RETURN_TO,
          "openid.signed": SIGNED_ALL,
          "openid.op_endpoint": OP_ENDPOINT,
          "openid.claimed_id": "https://evil.example.com/openid/id/76561198000000000",
        },
      },
      ctx(),
    );
    expect(result.kind).toBe("error");
  });

  it("rejects an assertion whose signed list omits claimed_id", async () => {
    const result = await steamPlugin.handleStep(
      authState(),
      {
        openid: {
          "openid.mode": "id_res",
          "openid.return_to": RETURN_TO,
          // claimed_id absent from the signed set — check_authentication would
          // still say is_valid:true, but the RP must refuse.
          "openid.signed": "op_endpoint,identity,return_to,response_nonce,assoc_handle",
          "openid.op_endpoint": OP_ENDPOINT,
          "openid.claimed_id": CLAIMED,
        },
      },
      ctx(),
    );
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("did not sign the required fields");
  });

  it("rejects an assertion whose signed list omits return_to", async () => {
    const result = await steamPlugin.handleStep(
      authState(),
      {
        openid: {
          "openid.mode": "id_res",
          "openid.return_to": RETURN_TO,
          "openid.signed": "op_endpoint,claimed_id,identity,response_nonce,assoc_handle",
          "openid.op_endpoint": OP_ENDPOINT,
          "openid.claimed_id": CLAIMED,
        },
      },
      ctx(),
    );
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("did not sign the required fields");
  });

  it("rejects an assertion whose op_endpoint is not Steam's", async () => {
    const result = await steamPlugin.handleStep(
      authState(),
      {
        openid: {
          "openid.mode": "id_res",
          "openid.return_to": RETURN_TO,
          "openid.signed": SIGNED_ALL,
          "openid.op_endpoint": "https://evil.example.com/openid/login",
          "openid.claimed_id": CLAIMED,
        },
      },
      ctx(),
    );
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("unexpected OpenID endpoint");
  });
});

describe("steamPlugin.handleStep verification", () => {
  const fetchSpy = vi.spyOn(globalThis, "fetch");
  beforeEach(() => {
    fetchSpy.mockReset();
    // Fail loudly on any unexpected fetch — these tests are fully offline.
    fetchSpy.mockRejectedValue(new Error("unexpected fetch"));
  });
  afterEach(() => {
    fetchSpy.mockReset();
    delete process.env.STEAM_WEB_API_KEY;
  });

  function authState(): WizardState {
    return {
      pluginId: "steam",
      userId: "user_test",
      currentStep: {
        id: "steam-openid",
        kind: "redirect",
        payload: { url: "https://steamcommunity.com/openid/login?...", expectedState: "STATE" },
      },
      data: { expectedReturnTo: RETURN_TO },
    };
  }

  const goodOpenid = {
    "openid.mode": "id_res",
    "openid.return_to": RETURN_TO,
    "openid.claimed_id": CLAIMED,
    "openid.signed": SIGNED_ALL,
    "openid.op_endpoint": OP_ENDPOINT,
    "openid.sig": "sig",
  };

  it("issues oauth-account with the steamid64 anchor when Steam validates the assertion", async () => {
    fetchSpy.mockResolvedValueOnce(new Response("ns:...\nis_valid:true\n", { status: 200 }));
    const result = await steamPlugin.handleStep(authState(), { openid: goodOpenid }, ctx());
    expect(result.kind).toBe("complete");
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges).toHaveLength(1);
    const badge = result.badges[0]!;
    expect(badge.type).toBe("oauth-account");
    // No persona key ⇒ no handle disclosed.
    expect(badge.claims).toEqual({ provider: "steam" });
    expect(badge.sybilAnchor).toBe("76561198000000000");

    // We post the check_authentication back to steamcommunity, not to any
    // op_endpoint the callback carried.
    const [url] = fetchSpy.mock.calls[0]!;
    expect(url).toBe("https://steamcommunity.com/openid/login");
  });

  it("refuses when Steam says is_valid:false", async () => {
    fetchSpy.mockResolvedValueOnce(new Response("is_valid:false\n", { status: 200 }));
    const result = await steamPlugin.handleStep(authState(), { openid: goodOpenid }, ctx());
    expect(result.kind).toBe("error");
  });

  it("includes the persona handle when a Web API key is set", async () => {
    process.env.STEAM_WEB_API_KEY = "k";
    fetchSpy
      .mockResolvedValueOnce(new Response("is_valid:true\n", { status: 200 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ response: { players: [{ personaname: "Gaben" }] } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    const result = await steamPlugin.handleStep(authState(), { openid: goodOpenid }, ctx());
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges[0]!.claims).toEqual({ provider: "steam", handle: "Gaben" });
  });
});
