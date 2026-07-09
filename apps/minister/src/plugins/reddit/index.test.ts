import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

import { redditPlugin } from "./index";

function ctx(): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
  };
}

const ORIG_ID = process.env.REDDIT_CLIENT_ID;
const ORIG_SECRET = process.env.REDDIT_CLIENT_SECRET;
beforeAll(() => {
  process.env.REDDIT_CLIENT_ID = "rid";
  process.env.REDDIT_CLIENT_SECRET = "rsecret";
});
afterAll(() => {
  if (ORIG_ID === undefined) delete process.env.REDDIT_CLIENT_ID;
  else process.env.REDDIT_CLIENT_ID = ORIG_ID;
  if (ORIG_SECRET === undefined) delete process.env.REDDIT_CLIENT_SECRET;
  else process.env.REDDIT_CLIENT_SECRET = ORIG_SECRET;
});

describe("redditPlugin.isConfigured", () => {
  it("is false when either cred is missing", () => {
    delete process.env.REDDIT_CLIENT_SECRET;
    expect(redditPlugin.isConfigured?.()).toBe(false);
    process.env.REDDIT_CLIENT_SECRET = "rsecret";
    expect(redditPlugin.isConfigured?.()).toBe(true);
  });
});

describe("redditPlugin.startWizard", () => {
  it("builds an authorize redirect with identity scope + state", async () => {
    const state = await redditPlugin.startWizard(ctx());
    expect(state.currentStep.kind).toBe("redirect");
    if (state.currentStep.kind !== "redirect") throw new Error("kind");
    const url = new URL(state.currentStep.payload.url);
    expect(url.origin + url.pathname).toBe("https://www.reddit.com/api/v1/authorize");
    expect(url.searchParams.get("scope")).toBe("identity");
    expect(url.searchParams.get("duration")).toBe("temporary");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "http://localhost:3000/badges/new/reddit/callback",
    );
    expect(state.currentStep.payload.expectedState).toBe(url.searchParams.get("state"));
    expect(state.data.redirectUri).toBe("http://localhost:3000/badges/new/reddit/callback");
    // PKCE S256 on the authorize redirect; the verifier is stashed server-side.
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBeTruthy();
    expect(typeof state.data.codeVerifier).toBe("string");
  });
});

describe("redditPlugin.handleStep", () => {
  const fetchSpy = vi.spyOn(globalThis, "fetch");
  beforeEach(() => {
    fetchSpy.mockReset();
    // Fail loudly on any unexpected fetch — these tests are fully offline.
    fetchSpy.mockRejectedValue(new Error("unexpected fetch"));
  });
  afterEach(() => fetchSpy.mockReset());

  function authState(): WizardState {
    return {
      pluginId: "reddit",
      userId: "user_test",
      currentStep: {
        id: "reddit-authorize",
        kind: "redirect",
        payload: { url: "https://www.reddit.com/api/v1/authorize?...", expectedState: "STATE" },
      },
      data: {
        redirectUri: "http://localhost:3000/badges/new/reddit/callback",
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

  it("rejects a missing callback code", async () => {
    const result = await redditPlugin.handleStep(authState(), {}, ctx());
    expect(result.kind).toBe("error");
  });

  it("completes with oauth-account + account-age and Basic-auths the token call", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "tok" }))
      .mockResolvedValueOnce(mockOk({ id: "abc123", name: "spez", created_utc: 1275350400 }));

    const result = await redditPlugin.handleStep(authState(), { code: "CODE" }, ctx());
    expect(result.kind).toBe("complete");
    if (result.kind !== "complete") throw new Error("kind");
    const byType = new Map(result.badges.map((b) => [b.type, b] as const));
    expect(byType.get("oauth-account")?.claims).toEqual({ provider: "reddit", handle: "spez" });
    expect(byType.get("oauth-account")?.sybilAnchor).toBe("t2_abc123");
    expect(byType.get("account-age")).toBeDefined();

    // Token call uses HTTP Basic + a User-Agent, body has no client_secret.
    const [tokenUrl, init] = fetchSpy.mock.calls[0]!;
    expect(tokenUrl).toBe("https://www.reddit.com/api/v1/access_token");
    const headers = init?.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Basic ${Buffer.from("rid:rsecret").toString("base64")}`);
    expect(headers["User-Agent"]).toContain("Minister");
    const body = new URLSearchParams(init?.body as string);
    expect(body.get("client_secret")).toBeNull();
    expect(body.get("grant_type")).toBe("authorization_code");
    // PKCE verifier completes the exchange.
    expect(body.get("code_verifier")).toBe("verifier-abc");
  });

  it("never logs the immutable fullname anchor", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "tok" }))
      .mockResolvedValueOnce(mockOk({ id: "abc123", name: "spez" }));
    const c = ctx();
    await redditPlugin.handleStep(authState(), { code: "CODE" }, c);
    for (const call of vi.mocked(c.audit.log).mock.calls) {
      expect(JSON.stringify(call)).not.toContain("t2_abc123");
    }
  });
});
