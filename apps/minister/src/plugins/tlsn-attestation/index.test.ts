import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

import { tlsnAttestationPlugin } from "./index";

vi.mock("@/lib/tlsn-verifier", () => ({
  verifyPresentation: vi.fn(),
  TlsnVerifierError: class extends Error {},
}));

import { verifyPresentation } from "@/lib/tlsn-verifier";

function ctx(): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
  };
}

beforeEach(() => {
  vi.mocked(verifyPresentation).mockReset();
});
afterEach(() => {
  vi.mocked(verifyPresentation).mockReset();
});

describe("tlsnAttestationPlugin.startWizard", () => {
  it("opens with an extension-action step pointing at the local submit endpoint", async () => {
    const state = await tlsnAttestationPlugin.startWizard(ctx());
    expect(state.currentStep.kind).toBe("extension-action");
    if (state.currentStep.kind !== "extension-action") throw new Error("kind");
    const p = state.currentStep.payload;
    expect(p.action).toBe("tlsn-prove");
    expect(p.params.submitUrl).toBe("http://localhost:3000/api/tlsn/submit");
    expect(typeof p.expectedSubmissionToken).toBe("string");
    expect(p.expectedSubmissionToken!.length).toBeGreaterThan(16);
    // params.sessionToken must match expectedSubmissionToken — the
    // extension echoes one and we look up by the other.
    expect(p.params.sessionToken).toBe(p.expectedSubmissionToken);
  });

  it("stashes domain/url/needle in wizard.data for handleStep", async () => {
    const state = await tlsnAttestationPlugin.startWizard(ctx());
    expect(state.data.domain).toBe("example.com");
    expect(typeof state.data.needle).toBe("string");
  });
});

describe("tlsnAttestationPlugin.handleStep — verification path", () => {
  function proveState(): WizardState {
    return {
      pluginId: "tlsn-attestation",
      userId: "user_test",
      currentStep: {
        id: "tlsn-prove",
        kind: "extension-action",
        payload: {
          action: "tlsn-prove",
          params: {},
          expectedSubmissionToken: "TOKEN_x",
        },
      },
      data: {
        domain: "example.com",
        url: "https://example.com/",
        needle: "Example Domain",
      },
    };
  }

  it("completes with a tlsn-attestation IssuedBadge when verification passes and the needle is in the transcript", async () => {
    vi.mocked(verifyPresentation).mockResolvedValueOnce({
      sent: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
      received: "HTTP/1.1 200 OK\r\n\r\nExample Domain",
      serverName: "example.com",
    });

    const result = await tlsnAttestationPlugin.handleStep(
      proveState(),
      { presentation: "BASE64" },
      ctx(),
    );
    expect(result.kind).toBe("complete");
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges).toEqual([
      {
        type: "tlsn-attestation",
        attributes: { domain: "example.com", claim: "Example Domain" },
        claims: { domain: "example.com", claim: "Example Domain" },
      },
    ]);
  });

  it("errors when the verifier rejects the presentation", async () => {
    vi.mocked(verifyPresentation).mockRejectedValueOnce(new Error("server name mismatch"));
    const result = await tlsnAttestationPlugin.handleStep(
      proveState(),
      { presentation: "BASE64" },
      ctx(),
    );
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("server name mismatch");
  });

  it("errors when the verified transcript doesn't contain the expected needle", async () => {
    vi.mocked(verifyPresentation).mockResolvedValueOnce({
      sent: "GET / HTTP/1.1\r\n",
      received: "HTTP/1.1 200 OK\r\n\r\nSomething Else",
      serverName: "example.com",
    });
    const result = await tlsnAttestationPlugin.handleStep(
      proveState(),
      { presentation: "BASE64" },
      ctx(),
    );
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toMatch(/didn't|Expected/);
  });

  it("issues NO badge when the verifier rejects a keyless (passthrough) transcript", async () => {
    // verifyPresentation enforces notary-key presence and throws on a keyless
    // transcript; the plugin must surface that as an error, never a badge.
    vi.mocked(verifyPresentation).mockRejectedValueOnce(
      new Error("tlsn-verifier returned a transcript with no notary key (keyless/passthrough)"),
    );
    const result = await tlsnAttestationPlugin.handleStep(
      proveState(),
      { presentation: "BASE64" },
      ctx(),
    );
    expect(result.kind).toBe("error");
    if (result.kind !== "error") throw new Error("kind");
    expect(result.message).toContain("no notary key");
  });

  it("errors when input is missing presentation bytes", async () => {
    const result = await tlsnAttestationPlugin.handleStep(proveState(), {}, ctx());
    expect(result.kind).toBe("error");
    expect(vi.mocked(verifyPresentation)).not.toHaveBeenCalled();
  });

  it("errors when wizard state is corrupted", async () => {
    const state: WizardState = {
      ...proveState(),
      data: {}, // missing domain / needle
    };
    const result = await tlsnAttestationPlugin.handleStep(state, { presentation: "BASE64" }, ctx());
    expect(result.kind).toBe("error");
  });

  it("errors when called on an unexpected step", async () => {
    const state: WizardState = {
      ...proveState(),
      currentStep: {
        id: "unknown",
        kind: "info",
        payload: { title: "x", body: "y" },
      },
    };
    const result = await tlsnAttestationPlugin.handleStep(state, { presentation: "B" }, ctx());
    expect(result.kind).toBe("error");
  });
});

describe("tlsnAttestationPlugin manifest", () => {
  it("declares the tlsn-attestation badge type + requiresExtension", () => {
    expect(tlsnAttestationPlugin.manifest.badgeTypes).toEqual(["tlsn-attestation"]);
    expect(tlsnAttestationPlugin.manifest.requiresExtension).toBe(true);
  });
});
