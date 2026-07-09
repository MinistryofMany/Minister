import { createHash } from "node:crypto";

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

import { xPlugin } from "./index";

function ctx(): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
  };
}

const ORIG_ID = process.env.X_CLIENT_ID;
const ORIG_SECRET = process.env.X_CLIENT_SECRET;
beforeAll(() => {
  process.env.X_CLIENT_ID = "xid";
  process.env.X_CLIENT_SECRET = "xsecret";
});
afterAll(() => {
  if (ORIG_ID === undefined) delete process.env.X_CLIENT_ID;
  else process.env.X_CLIENT_ID = ORIG_ID;
  if (ORIG_SECRET === undefined) delete process.env.X_CLIENT_SECRET;
  else process.env.X_CLIENT_SECRET = ORIG_SECRET;
});

describe("xPlugin.startWizard PKCE", () => {
  it("sends an S256 challenge and stashes the matching verifier server-side", async () => {
    const state = await xPlugin.startWizard(ctx());
    if (state.currentStep.kind !== "redirect") throw new Error("kind");
    const url = new URL(state.currentStep.payload.url);
    expect(url.origin + url.pathname).toBe("https://twitter.com/i/oauth2/authorize");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    const challenge = url.searchParams.get("code_challenge")!;
    const verifier = state.data.codeVerifier as string;
    expect(challenge).toBe(createHash("sha256").update(verifier).digest("base64url"));
    expect(url.searchParams.get("scope")).toBe("users.read tweet.read");
  });
});

describe("xPlugin.handleStep", () => {
  const fetchSpy = vi.spyOn(globalThis, "fetch");
  beforeEach(() => {
    fetchSpy.mockReset();
    // Fail loudly on any unexpected fetch — these tests are fully offline.
    fetchSpy.mockRejectedValue(new Error("unexpected fetch"));
  });
  afterEach(() => fetchSpy.mockReset());

  function authState(): WizardState {
    return {
      pluginId: "x",
      userId: "user_test",
      currentStep: {
        id: "x-authorize",
        kind: "redirect",
        payload: { url: "https://twitter.com/i/oauth2/authorize?...", expectedState: "STATE" },
      },
      data: {
        redirectUri: "http://localhost:3000/badges/new/x/callback",
        codeVerifier: "VERIFIER",
      },
    };
  }

  function mockOk(json: unknown): Response {
    return new Response(JSON.stringify(json), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  it("completes the PKCE exchange and issues oauth-account + account-age", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "tok" }))
      .mockResolvedValueOnce(
        mockOk({ data: { id: "42", username: "jack", created_at: "2015-01-01T00:00:00Z" } }),
      );
    const result = await xPlugin.handleStep(authState(), { code: "C" }, ctx());
    if (result.kind !== "complete") throw new Error("kind");
    const byType = new Map(result.badges.map((b) => [b.type, b] as const));
    expect(byType.get("oauth-account")?.claims).toEqual({ provider: "x", handle: "jack" });
    expect(byType.get("oauth-account")?.sybilAnchor).toBe("42");
    expect(byType.get("account-age")).toBeDefined();

    // Token call sends the PKCE verifier and Basic-auths the client.
    const [tokenUrl, init] = fetchSpy.mock.calls[0]!;
    expect(tokenUrl).toBe("https://api.twitter.com/2/oauth2/token");
    const headers = init?.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Basic ${Buffer.from("xid:xsecret").toString("base64")}`);
    const body = new URLSearchParams(init?.body as string);
    expect(body.get("code_verifier")).toBe("VERIFIER");
    expect(body.get("grant_type")).toBe("authorization_code");
  });

  it("rejects missing PKCE state", async () => {
    const state = authState();
    state.data = {};
    const result = await xPlugin.handleStep(state, { code: "C" }, ctx());
    expect(result.kind).toBe("error");
  });
});
