import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

// Mock the DNS resolver so these tests are fully offline. The plugin corroborates
// the challenge across two pinned public resolvers (1.1.1.1 and 8.8.8.8) via a
// fresh `Resolver` per lookup — `setServers([server])` then `resolveTxt(host)`.
// We stand in a fake Resolver that dispatches to a per-server mock, so each test
// can script Cloudflare and Google independently (agree / disagree / error).
const resolveByServer = new Map<string, (host: string) => Promise<string[][]>>();
vi.mock("node:dns/promises", () => ({
  Resolver: class {
    private server = "";
    setServers(servers: string[]): void {
      this.server = servers[0] ?? "";
    }
    resolveTxt(host: string): Promise<string[][]> {
      const impl = resolveByServer.get(this.server);
      if (!impl) return Promise.reject(new Error(`no resolver mock for server ${this.server}`));
      return impl(host);
    }
  },
}));

// Script both corroborating resolvers at once. Pass a per-server implementation
// (records array to resolve, or an Error/rejection to throw).
function setResolvers(cf: () => Promise<string[][]>, google: () => Promise<string[][]>): void {
  resolveByServer.set("1.1.1.1", cf);
  resolveByServer.set("8.8.8.8", google);
}

// Convenience: both resolvers return the same TXT records.
function bothReturn(records: string[][]): void {
  setResolvers(
    () => Promise.resolve(records),
    () => Promise.resolve(records),
  );
}

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
  // Default: any un-scripted resolver lookup is an unexpected call and fails the
  // test loudly rather than silently resolving.
  resolveByServer.clear();
  const unexpected = () => Promise.reject(new Error("unexpected resolveTxt call"));
  setResolvers(unexpected, unexpected);
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

  it("issues a domain-control badge when BOTH resolvers return the token", async () => {
    const state = await verifyState();
    const token = String(state.data.token);
    const cf = vi.fn(() => Promise.resolve([["v=spf1 -all"], [challengeValue(token)]]));
    const google = vi.fn(() => Promise.resolve([[challengeValue(token)], ["other=thing"]]));
    setResolvers(cf, google);

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
    // The exact challenge host was queried on BOTH resolvers (corroboration).
    expect(cf).toHaveBeenCalledWith("_minister-challenge.example.com");
    expect(google).toHaveBeenCalledWith("_minister-challenge.example.com");
  });

  it("fails closed when only ONE resolver has the token (the other is missing it)", async () => {
    const state = await verifyState();
    const token = String(state.data.token);
    // Cloudflare sees it; Google does not (present-but-wrong / disagreement).
    setResolvers(
      () => Promise.resolve([[challengeValue(token)]]),
      () => Promise.resolve([["v=spf1 -all"]]),
    );
    const c = ctx();
    const result = await dnsTxtPlugin.handleStep(state, {}, c);
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("didn't match yet");
    expect(result.message).toContain("Verify again");
    // Fail-closed: no badge, no verified audit event.
    expect(c.audit.log).not.toHaveBeenCalledWith("plugin.dns_txt.verified", expect.anything());
  });

  it("fails closed when the two resolvers disagree (one has it, one NXDOMAIN)", async () => {
    const state = await verifyState();
    const token = String(state.data.token);
    // Cloudflare resolves the token; Google returns NXDOMAIN (not propagated).
    setResolvers(
      () => Promise.resolve([[challengeValue(token)]]),
      () => Promise.reject(dnsError("ENOTFOUND")),
    );
    const result = await dnsTxtPlugin.handleStep(state, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    // A not-yet-visible record wins the copy over the matching resolver.
    expect(result.message).toContain("couldn't find the TXT record");
    expect(result.message).toContain("Verify again");
  });

  it("fails closed (no crash) when ONE resolver throws, even if the other matches", async () => {
    const state = await verifyState();
    const token = String(state.data.token);
    // Cloudflare matches; Google throws a transient SERVFAIL. Error copy wins.
    setResolvers(
      () => Promise.resolve([[challengeValue(token)]]),
      () => Promise.reject(dnsError("ESERVFAIL")),
    );
    const result = await dnsTxtPlugin.handleStep(state, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("DNS lookup failed");
    expect(result.message).toContain("Verify again");
  });

  it("fails closed when BOTH resolvers error (NXDOMAIN) with the add-the-record copy", async () => {
    const state = await verifyState();
    setResolvers(
      () => Promise.reject(dnsError("ENOTFOUND")),
      () => Promise.reject(dnsError("ENODATA")),
    );
    const result = await dnsTxtPlugin.handleStep(state, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("couldn't find the TXT record");
  });

  it("gives a generic retry message when both resolvers transiently fail", async () => {
    const state = await verifyState();
    setResolvers(
      () => Promise.reject(dnsError("ESERVFAIL")),
      () => Promise.reject(dnsError("ETIMEOUT")),
    );
    const result = await dnsTxtPlugin.handleStep(state, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("DNS lookup failed");
    expect(result.message).toContain("Verify again");
  });

  it("returns a retryable error when both agree the record is present but wrong", async () => {
    const state = await verifyState();
    bothReturn([[challengeValue("some-other-token")]]);
    const result = await dnsTxtPlugin.handleStep(state, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("didn't match yet");
    expect(result.message).toContain("Verify again");
  });

  it("errors (does not resolve) when the flow lost its token", async () => {
    const state = await verifyState();
    const stripped: WizardState = { ...state, data: {} };
    // Any resolver lookup here is a bug: bail before touching DNS.
    let called = false;
    setResolvers(
      () => {
        called = true;
        return Promise.reject(new Error("should not query"));
      },
      () => {
        called = true;
        return Promise.reject(new Error("should not query"));
      },
    );
    const result = await dnsTxtPlugin.handleStep(stripped, {}, ctx());
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("lost its challenge token");
    expect(called).toBe(false);
  });
});
