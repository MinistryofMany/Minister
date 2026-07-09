import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

import { hackernewsPlugin } from "./index";

function ctx(): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
  };
}

function mockOk(json: unknown): Response {
  return new Response(JSON.stringify(json), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("hackernewsPlugin form step", () => {
  it("rejects a junk username", async () => {
    const start = await hackernewsPlugin.startWizard(ctx());
    const result = await hackernewsPlugin.handleStep(start, { username: "not a name!!" }, ctx());
    expect(result.kind).toBe("error");
  });

  it("advances to an info step carrying a challenge token", async () => {
    const start = await hackernewsPlugin.startWizard(ctx());
    const result = await hackernewsPlugin.handleStep(start, { username: "pg" }, ctx());
    expect(result.kind).toBe("continue");
    if (result.kind !== "continue") throw new Error("kind");
    expect(result.state.currentStep.kind).toBe("info");
    expect(result.state.data.username).toBe("pg");
    expect(typeof result.state.data.token).toBe("string");
    // The token is shown in the info body so the user can paste it.
    if (result.state.currentStep.kind !== "info") throw new Error("kind");
    expect(result.state.currentStep.payload.body).toContain(String(result.state.data.token));
  });
});

describe("hackernewsPlugin verify step", () => {
  const fetchSpy = vi.spyOn(globalThis, "fetch");
  beforeEach(() => {
    fetchSpy.mockReset();
    // Fail loudly on any unexpected fetch — these tests are fully offline.
    fetchSpy.mockRejectedValue(new Error("unexpected fetch"));
  });
  afterEach(() => fetchSpy.mockReset());

  async function verifyState(): Promise<WizardState> {
    const start = await hackernewsPlugin.startWizard(ctx());
    const cont = await hackernewsPlugin.handleStep(start, { username: "pg" }, ctx());
    if (cont.kind !== "continue") throw new Error("expected continue");
    return cont.state;
  }

  it("completes when the token is present in the about field", async () => {
    const state = await verifyState();
    const token = String(state.data.token);
    fetchSpy.mockResolvedValueOnce(
      mockOk({ id: "pg", created: 1160418111, about: `hello ${token} bye` }),
    );

    const result = await hackernewsPlugin.handleStep(state, {}, ctx());
    expect(result.kind).toBe("complete");
    if (result.kind !== "complete") throw new Error("kind");
    const oauth = result.badges.find((b) => b.type === "oauth-account")!;
    expect(oauth.claims).toEqual({ provider: "hackernews", handle: "pg" });
    expect(oauth.sybilAnchor).toBe("pg");
    expect(oauth.revealsAnchor).toBe(true);
  });

  it("returns a retryable error (keeping the step) when the token is not found yet", async () => {
    const state = await verifyState();
    fetchSpy.mockResolvedValueOnce(mockOk({ id: "pg", created: 1160418111, about: "no token" }));
    const result = await hackernewsPlugin.handleStep(state, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("Verify again");
  });

  it("errors clearly when the HN user does not exist (null response)", async () => {
    const state = await verifyState();
    fetchSpy.mockResolvedValueOnce(new Response("null", { status: 200 }));
    const result = await hackernewsPlugin.handleStep(state, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("couldn't find");
  });
});
