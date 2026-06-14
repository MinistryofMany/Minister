import { describe, expect, it, vi } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

import { emailDomainPlugin } from "./index";

function ctx(overrides: Partial<PluginContext> = {}): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

describe("emailDomainPlugin.startWizard", () => {
  it("opens with a form step that collects an email", async () => {
    const state = await emailDomainPlugin.startWizard(ctx());
    expect(state.pluginId).toBe("email-domain");
    expect(state.userId).toBe("user_test");
    expect(state.currentStep.kind).toBe("form");
    if (state.currentStep.kind !== "form") throw new Error("kind narrowing");
    const fieldNames = state.currentStep.payload.fields.map((f) => f.name);
    expect(fieldNames).toContain("email");
    expect(state.data).toEqual({});
  });
});

describe("emailDomainPlugin.handleStep — collect-email → magic-link", () => {
  it("emits a magic-link step + sends an email containing the verify URL", async () => {
    const start = await emailDomainPlugin.startWizard(ctx());
    const c = ctx();
    const result = await emailDomainPlugin.handleStep(
      start,
      { email: "alice@example.com" },
      c,
    );
    expect(result.kind).toBe("continue");
    if (result.kind !== "continue") throw new Error("kind");
    expect(result.state.currentStep.kind).toBe("magic-link");
    if (result.state.currentStep.kind !== "magic-link") throw new Error("kind");
    const magic = result.state.currentStep.payload;
    expect(magic.sentTo).toBe("alice@example.com");
    expect(typeof magic.expectedToken).toBe("string");
    expect(magic.expectedToken!.length).toBeGreaterThanOrEqual(32);

    // The email body must carry the verify URL parameterized with the
    // same token the runtime will later lift onto pendingToken.
    expect(c.sendMail).toHaveBeenCalledOnce();
    const message = vi.mocked(c.sendMail).mock.calls[0]?.[0];
    expect(message?.to).toBe("alice@example.com");
    expect(message?.text).toContain(
      `${c.origin}/badges/new/email-domain/verify?token=`,
    );
    expect(message?.text).toContain(magic.expectedToken!);
  });

  it("stores only the domain, not the full email, in wizard state", async () => {
    const start = await emailDomainPlugin.startWizard(ctx());
    const result = await emailDomainPlugin.handleStep(
      start,
      { email: "Alice@Workmail.Test" },
      ctx(),
    );
    if (result.kind !== "continue") throw new Error("kind");
    expect(result.state.data).toEqual({ domain: "workmail.test" });
  });

  it("rejects malformed email input", async () => {
    const start = await emailDomainPlugin.startWizard(ctx());
    const result = await emailDomainPlugin.handleStep(
      start,
      { email: "not-an-email" },
      ctx(),
    );
    expect(result.kind).toBe("error");
  });
});

describe("emailDomainPlugin.handleStep — magic-link → complete", () => {
  function magicLinkState(token: string, domain = "example.com"): WizardState {
    return {
      pluginId: "email-domain",
      userId: "user_test",
      currentStep: {
        id: "wait-magic-link",
        kind: "magic-link",
        payload: { sentTo: `someone@${domain}`, expectedToken: token },
      },
      data: { domain },
    };
  }

  it("returns complete with an email-domain IssuedBadge", async () => {
    const result = await emailDomainPlugin.handleStep(
      magicLinkState("TOKEN_xyz", "workmail.test"),
      { token: "TOKEN_xyz" },
      ctx(),
    );
    expect(result.kind).toBe("complete");
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges).toHaveLength(1);
    expect(result.badges[0]).toEqual({
      type: "email-domain",
      attributes: { domain: "workmail.test" },
      claims: { domain: "workmail.test" },
    });
  });

  it("errors if wizard state is missing the domain", async () => {
    const state: WizardState = {
      pluginId: "email-domain",
      userId: "user_test",
      currentStep: {
        id: "wait-magic-link",
        kind: "magic-link",
        payload: { sentTo: "x@y", expectedToken: "T" },
      },
      data: {},
    };
    const result = await emailDomainPlugin.handleStep(
      state,
      { token: "T" },
      ctx(),
    );
    expect(result.kind).toBe("error");
  });
});

describe("emailDomainPlugin manifest", () => {
  it("declares the email-domain badge type and no extension dependency", () => {
    expect(emailDomainPlugin.manifest.badgeTypes).toEqual(["email-domain"]);
    expect(emailDomainPlugin.manifest.requiresExtension).toBe(false);
  });
});
