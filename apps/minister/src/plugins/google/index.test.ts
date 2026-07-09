import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

import { googlePlugin } from "./index";

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

describe("googlePlugin.startWizard", () => {
  it("requests the non-sensitive openid email scope", async () => {
    const state = await googlePlugin.startWizard(ctx());
    if (state.currentStep.kind !== "redirect") throw new Error("kind");
    const url = new URL(state.currentStep.payload.url);
    expect(url.origin + url.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(url.searchParams.get("scope")).toBe("openid email");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "http://localhost:3000/badges/new/google/callback",
    );
  });
});

describe("googlePlugin.handleStep", () => {
  const fetchSpy = vi.spyOn(globalThis, "fetch");
  beforeEach(() => {
    fetchSpy.mockReset();
    // Fail loudly on any unexpected fetch — these tests are fully offline.
    fetchSpy.mockRejectedValue(new Error("unexpected fetch"));
  });
  afterEach(() => fetchSpy.mockReset());

  function authState(): WizardState {
    return {
      pluginId: "google",
      userId: "user_test",
      currentStep: {
        id: "google-authorize",
        kind: "redirect",
        payload: { url: "https://accounts.google.com/...", expectedState: "STATE" },
      },
      data: { redirectUri: "http://localhost:3000/badges/new/google/callback" },
    };
  }

  function mockOk(json: unknown): Response {
    return new Response(JSON.stringify(json), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  it("discloses a verified email as the handle, anchors on sub", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "tok" }))
      .mockResolvedValueOnce(mockOk({ sub: "1029384756", email: "a@b.com", email_verified: true }));
    const result = await googlePlugin.handleStep(authState(), { code: "C" }, ctx());
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges[0]!.claims).toEqual({ provider: "google", handle: "a@b.com" });
    expect(result.badges[0]!.sybilAnchor).toBe("1029384756");
  });

  it("omits the handle when the email is unverified", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "tok" }))
      .mockResolvedValueOnce(mockOk({ sub: "1", email: "a@b.com", email_verified: false }));
    const result = await googlePlugin.handleStep(authState(), { code: "C" }, ctx());
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges[0]!.claims).toEqual({ provider: "google" });
  });

  it("never logs the immutable sub anchor", async () => {
    fetchSpy
      .mockResolvedValueOnce(mockOk({ access_token: "tok" }))
      .mockResolvedValueOnce(mockOk({ sub: "SECRETSUB", email: "a@b.com", email_verified: true }));
    const c = ctx();
    await googlePlugin.handleStep(authState(), { code: "C" }, c);
    for (const call of vi.mocked(c.audit.log).mock.calls) {
      expect(JSON.stringify(call)).not.toContain("SECRETSUB");
    }
  });
});
