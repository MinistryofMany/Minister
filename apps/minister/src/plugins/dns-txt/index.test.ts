import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

// Mock the DNS resolver so these tests are fully offline. resolveTxt is the only
// network call the plugin makes.
const resolveTxt = vi.fn<(host: string) => Promise<string[][]>>();
vi.mock("node:dns/promises", () => ({
  resolveTxt: (host: string) => resolveTxt(host),
}));

import { dnsTxtPlugin } from "./index";
import { challengeValue } from "./verify";

function ctx(): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
  };
}

// A DNS error carrying a node resolver error code.
function dnsError(code: string): NodeJS.ErrnoException {
  const err = new Error(`queryTxt ${code}`) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

beforeEach(() => {
  resolveTxt.mockReset();
  resolveTxt.mockRejectedValue(new Error("unexpected resolveTxt call"));
});

describe("dnsTxtPlugin form step", () => {
  it("rejects an invalid domain (a URL)", async () => {
    const start = await dnsTxtPlugin.startWizard(ctx());
    const result = await dnsTxtPlugin.handleStep(start, { domain: "https://example.com" }, ctx());
    expect(result.kind).toBe("error");
  });

  it("advances to an info step carrying a challenge token and the normalized domain", async () => {
    const start = await dnsTxtPlugin.startWizard(ctx());
    const result = await dnsTxtPlugin.handleStep(start, { domain: "Example.COM" }, ctx());
    expect(result.kind).toBe("continue");
    if (result.kind !== "continue") throw new Error("kind");
    expect(result.state.currentStep.kind).toBe("info");
    expect(result.state.data.domain).toBe("example.com");
    expect(typeof result.state.data.token).toBe("string");
    if (result.state.currentStep.kind !== "info") throw new Error("kind");
    // The token and challenge host are shown in the info body so the user can add the record.
    const body = result.state.currentStep.payload.body;
    expect(body).toContain(String(result.state.data.token));
    expect(body).toContain("_minister-challenge.example.com");
  });

  it("does not log the unproven domain on challenge issuance", async () => {
    const c = ctx();
    const start = await dnsTxtPlugin.startWizard(c);
    await dnsTxtPlugin.handleStep(start, { domain: "example.com" }, c);
    expect(c.audit.log).toHaveBeenCalledWith("plugin.dns_txt.challenge_issued", {});
  });
});

describe("dnsTxtPlugin verify step", () => {
  async function verifyState(): Promise<WizardState> {
    const start = await dnsTxtPlugin.startWizard(ctx());
    const cont = await dnsTxtPlugin.handleStep(start, { domain: "example.com" }, ctx());
    if (cont.kind !== "continue") throw new Error("expected continue");
    return cont.state;
  }

  it("issues a domain-control badge when the TXT record matches", async () => {
    const state = await verifyState();
    const token = String(state.data.token);
    resolveTxt.mockResolvedValueOnce([["v=spf1 -all"], [challengeValue(token)]]);

    const c = ctx();
    const result = await dnsTxtPlugin.handleStep(state, {}, c);
    expect(result.kind).toBe("complete");
    if (result.kind !== "complete") throw new Error("kind");
    const badge = result.badges[0]!;
    expect(badge.type).toBe("domain-control");
    expect(badge.claims).toEqual({ domain: "example.com" });
    expect(badge.sybilAnchor).toBe("example.com");
    expect(badge.revealsAnchor).toBe(true);
    // The verified event logs the now-proven domain (revealsAnchor exception).
    expect(c.audit.log).toHaveBeenCalledWith("plugin.dns_txt.verified", { domain: "example.com" });
    // The exact challenge host was queried.
    expect(resolveTxt).toHaveBeenCalledWith("_minister-challenge.example.com");
  });

  it("returns a retryable error (keeping the step) when the record is present but wrong", async () => {
    const state = await verifyState();
    resolveTxt.mockResolvedValueOnce([[challengeValue("some-other-token")]]);
    const result = await dnsTxtPlugin.handleStep(state, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("Verify again");
  });

  it("gives an add-the-record message on NXDOMAIN", async () => {
    const state = await verifyState();
    resolveTxt.mockRejectedValueOnce(dnsError("ENOTFOUND"));
    const result = await dnsTxtPlugin.handleStep(state, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("couldn't find the TXT record");
    expect(result.message).toContain("Verify again");
  });

  it("gives an add-the-record message when the host has no TXT records (ENODATA)", async () => {
    const state = await verifyState();
    resolveTxt.mockRejectedValueOnce(dnsError("ENODATA"));
    const result = await dnsTxtPlugin.handleStep(state, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("couldn't find the TXT record");
  });

  it("gives a generic retry message on a transient resolver failure", async () => {
    const state = await verifyState();
    resolveTxt.mockRejectedValueOnce(dnsError("ESERVFAIL"));
    const result = await dnsTxtPlugin.handleStep(state, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("DNS lookup failed");
    expect(result.message).toContain("Verify again");
  });

  it("errors (does not resolve) when the flow lost its token", async () => {
    const state = await verifyState();
    const stripped: WizardState = { ...state, data: {} };
    const result = await dnsTxtPlugin.handleStep(stripped, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("lost its challenge token");
    expect(resolveTxt).not.toHaveBeenCalled();
  });
});
