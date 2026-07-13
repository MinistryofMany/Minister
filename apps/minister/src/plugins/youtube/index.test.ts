import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

import { youtubePlugin } from "./index";

function ctx(): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
  };
}

const ORIG_ID = process.env.GOOGLE_CLIENT_ID;
const ORIG_SECRET = process.env.GOOGLE_CLIENT_SECRET;
beforeAll(() => {
  process.env.GOOGLE_CLIENT_ID = "gid";
  process.env.GOOGLE_CLIENT_SECRET = "gsecret";
});
afterAll(() => {
  if (ORIG_ID === undefined) delete process.env.GOOGLE_CLIENT_ID;
  else process.env.GOOGLE_CLIENT_ID = ORIG_ID;
  if (ORIG_SECRET === undefined) delete process.env.GOOGLE_CLIENT_SECRET;
  else process.env.GOOGLE_CLIENT_SECRET = ORIG_SECRET;
});

describe("youtubePlugin.startWizard", () => {
  it("requests the sensitive youtube.readonly scope against Google's authorize endpoint", async () => {
    const state = await youtubePlugin.startWizard(ctx());
    if (state.currentStep.kind !== "redirect") throw new Error("kind");
    const url = new URL(state.currentStep.payload.url);
    expect(url.origin + url.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(url.searchParams.get("scope")).toBe("https://www.googleapis.com/auth/youtube.readonly");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "http://localhost:3000/badges/new/youtube/callback",
    );
    // PKCE S256 on the authorize redirect; the verifier is stashed server-side.
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBeTruthy();
    expect(typeof state.data.codeVerifier).toBe("string");
  });
});

describe("youtubePlugin.handleStep", () => {
  const fetchSpy = vi.spyOn(globalThis, "fetch");
  beforeEach(() => {
    fetchSpy.mockReset();
    fetchSpy.mockRejectedValue(new Error("unexpected fetch"));
  });
  afterEach(() => fetchSpy.mockReset());

  function authState(): WizardState {
    return {
      pluginId: "youtube",
      userId: "user_test",
      currentStep: {
        id: "youtube-authorize",
        kind: "redirect",
        payload: { url: "https://accounts.google.com/...", expectedState: "STATE" },
      },
      data: {
        redirectUri: "http://localhost:3000/badges/new/youtube/callback",
        codeVerifier: "verifier-abc",
      },
    };
  }

  function mockOk(json: unknown): Response {
    return new Response(JSON.stringify(json), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  it("prefers the channel's @handle customUrl over its display title, anchors on channel id", async () => {
    fetchSpy.mockResolvedValueOnce(mockOk({ access_token: "tok" })).mockResolvedValueOnce(
      mockOk({
        items: [{ id: "UC12345", snippet: { title: "My Channel", customUrl: "@mychannel" } }],
      }),
    );
    const result = await youtubePlugin.handleStep(authState(), { code: "C" }, ctx());
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges[0]!.claims).toEqual({ provider: "youtube", handle: "@mychannel" });
    expect(result.badges[0]!.sybilAnchor).toBe("UC12345");
  });

  it("falls back to the display title when there is no claimed customUrl", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "tok" }))
      .mockResolvedValueOnce(mockOk({ items: [{ id: "UC1", snippet: { title: "My Channel" } }] }));
    const result = await youtubePlugin.handleStep(authState(), { code: "C" }, ctx());
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges[0]!.claims).toEqual({ provider: "youtube", handle: "My Channel" });
  });

  it("errors when the Google account has no YouTube channel", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "tok" }))
      .mockResolvedValueOnce(mockOk({ items: [] }));
    const result = await youtubePlugin.handleStep(authState(), { code: "C" }, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("No YouTube channel");
  });

  it("errors when the wizard state is missing the PKCE verifier", async () => {
    const noPkce: WizardState = {
      ...authState(),
      data: { redirectUri: "http://localhost:3000/badges/new/youtube/callback" },
    };
    const result = await youtubePlugin.handleStep(noPkce, { code: "C" }, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("PKCE");
  });

  it("sends the PKCE code_verifier on the token exchange", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "tok" }))
      .mockResolvedValueOnce(mockOk({ items: [{ id: "UC1", snippet: { title: "T" } }] }));
    await youtubePlugin.handleStep(authState(), { code: "C" }, ctx());
    const [tokenUrl, init] = fetchSpy.mock.calls[0]!;
    expect(tokenUrl).toBe("https://oauth2.googleapis.com/token");
    const body = new URLSearchParams(init?.body as string);
    expect(body.get("code_verifier")).toBe("verifier-abc");
    expect(body.get("grant_type")).toBe("authorization_code");
  });

  it("never logs the immutable channel id anchor", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "tok" }))
      .mockResolvedValueOnce(mockOk({ items: [{ id: "UC_SECRET_ID", snippet: { title: "T" } }] }));
    const c = ctx();
    await youtubePlugin.handleStep(authState(), { code: "C" }, c);
    for (const call of vi.mocked(c.audit.log).mock.calls) {
      expect(JSON.stringify(call)).not.toContain("UC_SECRET_ID");
    }
  });
});
