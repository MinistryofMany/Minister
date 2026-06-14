import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

import { githubPlugin } from "./index";

function ctx(): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
  };
}

const ORIGINAL_ID = process.env.GITHUB_CLIENT_ID;
const ORIGINAL_SECRET = process.env.GITHUB_CLIENT_SECRET;
beforeAll(() => {
  process.env.GITHUB_CLIENT_ID = "test_client_id";
  process.env.GITHUB_CLIENT_SECRET = "test_client_secret";
});
afterAll(() => {
  if (ORIGINAL_ID === undefined) delete process.env.GITHUB_CLIENT_ID;
  else process.env.GITHUB_CLIENT_ID = ORIGINAL_ID;
  if (ORIGINAL_SECRET === undefined) delete process.env.GITHUB_CLIENT_SECRET;
  else process.env.GITHUB_CLIENT_SECRET = ORIGINAL_SECRET;
});

describe("githubPlugin.startWizard", () => {
  it("issues a redirect step pointing at github.com/login/oauth/authorize", async () => {
    const state = await githubPlugin.startWizard(ctx());
    expect(state.currentStep.kind).toBe("redirect");
    if (state.currentStep.kind !== "redirect") throw new Error("kind");
    const url = new URL(state.currentStep.payload.url);
    expect(url.origin + url.pathname).toBe(
      "https://github.com/login/oauth/authorize",
    );
    expect(url.searchParams.get("client_id")).toBe("test_client_id");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "http://localhost:3000/badges/new/github/callback",
    );
    expect(url.searchParams.get("scope")).toBe("read:user");
    const state_ = url.searchParams.get("state");
    expect(state_).toBeTruthy();
    expect(state_!.length).toBeGreaterThan(16);
    expect(state.currentStep.payload.expectedState).toBe(state_);
  });

  it("stashes the redirect URI in wizard.data for the exchange step", async () => {
    const state = await githubPlugin.startWizard(ctx());
    expect(state.data.redirectUri).toBe(
      "http://localhost:3000/badges/new/github/callback",
    );
  });

  it("throws when GitHub creds are unconfigured", async () => {
    const id = process.env.GITHUB_CLIENT_ID;
    const secret = process.env.GITHUB_CLIENT_SECRET;
    delete process.env.GITHUB_CLIENT_ID;
    delete process.env.GITHUB_CLIENT_SECRET;
    await expect(githubPlugin.startWizard(ctx())).rejects.toThrow(
      /GITHUB_CLIENT_ID/,
    );
    process.env.GITHUB_CLIENT_ID = id;
    process.env.GITHUB_CLIENT_SECRET = secret;
  });
});

describe("githubPlugin.handleStep — code exchange + /user fetch", () => {
  const fetchSpy = vi.spyOn(globalThis, "fetch");

  beforeEach(() => {
    fetchSpy.mockReset();
  });
  afterEach(() => {
    fetchSpy.mockReset();
  });

  function authState(): WizardState {
    return {
      pluginId: "github",
      userId: "user_test",
      currentStep: {
        id: "github-authorize",
        kind: "redirect",
        payload: {
          url: "https://github.com/login/oauth/authorize?...",
          expectedState: "STATE",
        },
      },
      data: { redirectUri: "http://localhost:3000/badges/new/github/callback" },
    };
  }

  function mockOk(json: unknown): Response {
    return new Response(JSON.stringify(json), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  it("completes with an oauth-account IssuedBadge on a happy path", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "gho_test" }))
      .mockResolvedValueOnce(mockOk({ id: 42, login: "octocat" }));

    const result = await githubPlugin.handleStep(
      authState(),
      { code: "GH_CODE" },
      ctx(),
    );
    expect(result.kind).toBe("complete");
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges).toEqual([
      {
        type: "oauth-account",
        attributes: { provider: "github", accountId: "42", handle: "octocat" },
        claims: { provider: "github", accountId: "42", handle: "octocat" },
      },
    ]);

    // Token-exchange call shape.
    const [tokenUrl, tokenInit] = fetchSpy.mock.calls[0]!;
    expect(tokenUrl).toBe("https://github.com/login/oauth/access_token");
    expect(tokenInit?.method).toBe("POST");
    const body = new URLSearchParams(tokenInit?.body as string);
    expect(body.get("code")).toBe("GH_CODE");
    expect(body.get("client_id")).toBe("test_client_id");
    expect(body.get("client_secret")).toBe("test_client_secret");
    expect(body.get("redirect_uri")).toBe(
      "http://localhost:3000/badges/new/github/callback",
    );

    // /user call shape.
    const [userUrl, userInit] = fetchSpy.mock.calls[1]!;
    expect(userUrl).toBe("https://api.github.com/user");
    expect((userInit?.headers as Record<string, string>).Authorization).toBe(
      "Bearer gho_test",
    );
  });

  it("propagates a github-side error from the token endpoint", async () => {
    fetchSpy.mockResolvedValueOnce(
      mockOk({
        error: "bad_verification_code",
        error_description: "Code expired",
      }),
    );
    const result = await githubPlugin.handleStep(
      authState(),
      { code: "BAD" },
      ctx(),
    );
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("Code expired");
  });

  it("errors when github returns a non-2xx on /user", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "gho_test" }))
      .mockResolvedValueOnce(new Response("Unauthorized", { status: 401 }));
    const result = await githubPlugin.handleStep(
      authState(),
      { code: "X" },
      ctx(),
    );
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toMatch(/401/);
  });

  it("errors when github returns an unexpected user shape", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "gho_test" }))
      .mockResolvedValueOnce(mockOk({ id: "not-a-number", login: 123 }));
    const result = await githubPlugin.handleStep(
      authState(),
      { code: "X" },
      ctx(),
    );
    expect(result.kind).toBe("error");
  });

  it("errors when called on an unexpected step", async () => {
    const state: WizardState = {
      ...authState(),
      currentStep: {
        id: "totally-different",
        kind: "info",
        payload: { title: "x", body: "y" },
      },
    };
    const result = await githubPlugin.handleStep(
      state,
      { code: "X" },
      ctx(),
    );
    expect(result.kind).toBe("error");
  });
});
