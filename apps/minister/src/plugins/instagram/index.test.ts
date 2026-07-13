import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

import { instagramPlugin } from "./index";

function ctx(): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
  };
}

const ORIG_ID = process.env.INSTAGRAM_CLIENT_ID;
const ORIG_SECRET = process.env.INSTAGRAM_CLIENT_SECRET;
beforeAll(() => {
  process.env.INSTAGRAM_CLIENT_ID = "iid";
  process.env.INSTAGRAM_CLIENT_SECRET = "isecret";
});
afterAll(() => {
  if (ORIG_ID === undefined) delete process.env.INSTAGRAM_CLIENT_ID;
  else process.env.INSTAGRAM_CLIENT_ID = ORIG_ID;
  if (ORIG_SECRET === undefined) delete process.env.INSTAGRAM_CLIENT_SECRET;
  else process.env.INSTAGRAM_CLIENT_SECRET = ORIG_SECRET;
});

describe("instagramPlugin.startWizard", () => {
  it("requests pages_show_list + instagram_basic against Facebook's authorize endpoint", async () => {
    const state = await instagramPlugin.startWizard(ctx());
    if (state.currentStep.kind !== "redirect") throw new Error("kind");
    const url = new URL(state.currentStep.payload.url);
    expect(url.origin + url.pathname).toBe("https://www.facebook.com/v21.0/dialog/oauth");
    expect(url.searchParams.get("scope")).toBe("pages_show_list,instagram_basic");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "http://localhost:3000/badges/new/instagram/callback",
    );
    expect(url.searchParams.get("state")).toBeTruthy();
  });
});

describe("instagramPlugin.handleStep", () => {
  const fetchSpy = vi.spyOn(globalThis, "fetch");
  beforeEach(() => {
    fetchSpy.mockReset();
    fetchSpy.mockRejectedValue(new Error("unexpected fetch"));
  });
  afterEach(() => fetchSpy.mockReset());

  function authState(): WizardState {
    return {
      pluginId: "instagram",
      userId: "user_test",
      currentStep: {
        id: "instagram-authorize",
        kind: "redirect",
        payload: { url: "https://www.facebook.com/...", expectedState: "STATE" },
      },
      data: { redirectUri: "http://localhost:3000/badges/new/instagram/callback" },
    };
  }

  function mockOk(json: unknown): Response {
    return new Response(JSON.stringify(json), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  it("walks the user's Pages to find a linked Instagram Business account, anchors on its id", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "usertok" })) // token exchange
      .mockResolvedValueOnce(mockOk({ data: [{ id: "PAGE1", access_token: "pagetok1" }] })) // /me/accounts
      .mockResolvedValueOnce(mockOk({ instagram_business_account: { id: "IG123" } })) // page link lookup
      .mockResolvedValueOnce(mockOk({ id: "IG123", username: "my_ig_handle" })); // ig account lookup
    const result = await instagramPlugin.handleStep(authState(), { code: "C" }, ctx());
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges[0]!.claims).toEqual({ provider: "instagram", handle: "my_ig_handle" });
    expect(result.badges[0]!.sybilAnchor).toBe("IG123");
  });

  it("skips pages with no linked Instagram account and uses the first one that has it", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "usertok" }))
      .mockResolvedValueOnce(
        mockOk({
          data: [
            { id: "PAGE_NOLINK", access_token: "tok_a" },
            { id: "PAGE_LINKED", access_token: "tok_b" },
          ],
        }),
      )
      .mockResolvedValueOnce(mockOk({})) // PAGE_NOLINK: no instagram_business_account
      .mockResolvedValueOnce(mockOk({ instagram_business_account: { id: "IG777" } })) // PAGE_LINKED
      .mockResolvedValueOnce(mockOk({ id: "IG777", username: "linked_handle" }));
    const result = await instagramPlugin.handleStep(authState(), { code: "C" }, ctx());
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges[0]!.sybilAnchor).toBe("IG777");
  });

  it("errors when no Page has a linked Instagram Business/Creator account", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "usertok" }))
      .mockResolvedValueOnce(mockOk({ data: [{ id: "PAGE1", access_token: "tok" }] }))
      .mockResolvedValueOnce(mockOk({}));
    const result = await instagramPlugin.handleStep(authState(), { code: "C" }, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("No Instagram Business or Creator account");
  });

  it("errors when the user administers no Facebook Pages", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "usertok" }))
      .mockResolvedValueOnce(mockOk({ data: [] }));
    const result = await instagramPlugin.handleStep(authState(), { code: "C" }, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("No Instagram Business or Creator account");
  });

  it("never logs the immutable Instagram account id anchor", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "usertok" }))
      .mockResolvedValueOnce(mockOk({ data: [{ id: "PAGE1", access_token: "tok" }] }))
      .mockResolvedValueOnce(mockOk({ instagram_business_account: { id: "IG_SECRET_ID" } }))
      .mockResolvedValueOnce(mockOk({ id: "IG_SECRET_ID", username: "handle" }));
    const c = ctx();
    await instagramPlugin.handleStep(authState(), { code: "C" }, c);
    for (const call of vi.mocked(c.audit.log).mock.calls) {
      expect(JSON.stringify(call)).not.toContain("IG_SECRET_ID");
    }
  });
});
