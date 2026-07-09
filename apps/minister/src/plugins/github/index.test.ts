import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

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
    expect(url.origin + url.pathname).toBe("https://github.com/login/oauth/authorize");
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
    expect(state.data.redirectUri).toBe("http://localhost:3000/badges/new/github/callback");
  });

  it("throws when GitHub creds are unconfigured", async () => {
    const id = process.env.GITHUB_CLIENT_ID;
    const secret = process.env.GITHUB_CLIENT_SECRET;
    delete process.env.GITHUB_CLIENT_ID;
    delete process.env.GITHUB_CLIENT_SECRET;
    await expect(githubPlugin.startWizard(ctx())).rejects.toThrow(/GITHUB_CLIENT_ID/);
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

    const result = await githubPlugin.handleStep(authState(), { code: "GH_CODE" }, ctx());
    expect(result.kind).toBe("complete");
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges).toEqual([
      {
        type: "oauth-account",
        // No accountId anywhere in attributes/claims — the numeric id rides
        // ONLY as the in-memory sybilAnchor, which the wizard runtime nullifies
        // and discards.
        attributes: { provider: "github", handle: "octocat" },
        claims: { provider: "github", handle: "octocat" },
        sybilAnchor: "42",
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
    expect(body.get("redirect_uri")).toBe("http://localhost:3000/badges/new/github/callback");

    // /user call shape.
    const [userUrl, userInit] = fetchSpy.mock.calls[1]!;
    expect(userUrl).toBe("https://api.github.com/user");
    expect((userInit?.headers as Record<string, string>).Authorization).toBe("Bearer gho_test");
  });

  it("audits the verified event with ONLY the handle + issued types — never the numeric id", async () => {
    // The numeric github id is the raw Sybil anchor. It must be nullified and
    // discarded, and the AuditLog is one of the at-rest stores it must never
    // reach — this call USED to log { accountId }. Pin the exact metadata shape
    // so re-adding the id (or any other key) fails the typecheck-free way here.
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "gho_test" }))
      .mockResolvedValueOnce(mockOk({ id: 998877665544, login: "octocat" }));

    const c = ctx();
    const result = await githubPlugin.handleStep(authState(), { code: "GH_CODE" }, c);
    expect(result.kind).toBe("complete");

    // Exact-object match: any extra key (a re-added accountId or the handle)
    // breaks it. The AuditLog keeps no account-identifying value.
    expect(c.audit.log).toHaveBeenCalledWith("plugin.github.verified", {
      issuedTypes: ["oauth-account"],
    });
    // Belt-and-suspenders: neither the numeric id nor the handle appears in any
    // serialized audit call.
    for (const call of vi.mocked(c.audit.log).mock.calls) {
      expect(JSON.stringify(call)).not.toContain("998877665544");
      expect(JSON.stringify(call)).not.toContain("octocat");
    }
  });

  it("derives account-age and social-following from a full /user response", async () => {
    // created_at ~11 years before now, 1500 followers.
    fetchSpy.mockResolvedValueOnce(mockOk({ access_token: "gho_test" })).mockResolvedValueOnce(
      mockOk({
        id: 7,
        login: "power",
        created_at: "2015-01-01T00:00:00Z",
        followers: 1500,
      }),
    );

    const result = await githubPlugin.handleStep(authState(), { code: "GH_CODE" }, ctx());
    expect(result.kind).toBe("complete");
    if (result.kind !== "complete") throw new Error("kind");

    const byType = new Map(result.badges.map((b) => [b.type, b] as const));
    expect(byType.get("oauth-account")?.claims).toEqual({
      provider: "github",
      handle: "power",
    });
    // Every github badge carries the same numeric-id anchor under its own type.
    expect(byType.get("oauth-account")?.sybilAnchor).toBe("7");
    expect(byType.get("account-age")?.sybilAnchor).toBe("7");
    expect(byType.get("social-following")?.sybilAnchor).toBe("7");
    // Coarse threshold only — the raw created_at never becomes a claim.
    expect(byType.get("account-age")?.claims).toEqual({
      provider: "github",
      olderThanMonths: 60,
    });
    expect(byType.get("social-following")?.claims).toEqual({
      provider: "github",
      followersAtLeast: 1000,
    });
  });

  it("issues only oauth-account when the derived signals are absent/low", async () => {
    fetchSpy.mockResolvedValueOnce(mockOk({ access_token: "gho_test" })).mockResolvedValueOnce(
      mockOk({
        id: 8,
        login: "fresh",
        created_at: "2026-06-01T00:00:00Z",
        followers: 2,
      }),
    );
    const result = await githubPlugin.handleStep(authState(), { code: "X" }, ctx());
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges.map((b) => b.type)).toEqual(["oauth-account"]);
  });

  it("propagates a github-side error from the token endpoint", async () => {
    fetchSpy.mockResolvedValueOnce(
      mockOk({
        error: "bad_verification_code",
        error_description: "Code expired",
      }),
    );
    const result = await githubPlugin.handleStep(authState(), { code: "BAD" }, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("Code expired");
  });

  it("errors when github returns a non-2xx on /user", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "gho_test" }))
      .mockResolvedValueOnce(new Response("Unauthorized", { status: 401 }));
    const result = await githubPlugin.handleStep(authState(), { code: "X" }, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toMatch(/401/);
  });

  it("errors when github returns an unexpected user shape", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "gho_test" }))
      .mockResolvedValueOnce(mockOk({ id: "not-a-number", login: 123 }));
    const result = await githubPlugin.handleStep(authState(), { code: "X" }, ctx());
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
    const result = await githubPlugin.handleStep(state, { code: "X" }, ctx());
    expect(result.kind).toBe("error");
  });
});
