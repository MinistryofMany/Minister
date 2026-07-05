import { describe, expect, it, vi } from "vitest";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

import { emailExactPlugin } from "./index";

function ctx(overrides: Partial<PluginContext> = {}): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

describe("emailExactPlugin.startWizard", () => {
  it("opens with a form step that collects an email", async () => {
    const state = await emailExactPlugin.startWizard(ctx());
    expect(state.pluginId).toBe("email-exact");
    expect(state.userId).toBe("user_test");
    expect(state.currentStep.kind).toBe("form");
    if (state.currentStep.kind !== "form") throw new Error("kind narrowing");
    const fieldNames = state.currentStep.payload.fields.map((f) => f.name);
    expect(fieldNames).toContain("email");
    expect(state.data).toEqual({});
  });
});

describe("emailExactPlugin.handleStep — collect-email → magic-link", () => {
  it("emits a magic-link step + sends an email with the email-exact verify URL", async () => {
    const start = await emailExactPlugin.startWizard(ctx());
    const c = ctx();
    const result = await emailExactPlugin.handleStep(start, { email: "alice@example.com" }, c);
    expect(result.kind).toBe("continue");
    if (result.kind !== "continue") throw new Error("kind");
    expect(result.state.currentStep.kind).toBe("magic-link");
    if (result.state.currentStep.kind !== "magic-link") throw new Error("kind");
    const magic = result.state.currentStep.payload;
    expect(magic.sentTo).toBe("alice@example.com");
    expect(typeof magic.expectedToken).toBe("string");

    expect(c.sendMail).toHaveBeenCalledOnce();
    const message = vi.mocked(c.sendMail).mock.calls[0]?.[0];
    expect(message?.to).toBe("alice@example.com");
    expect(message?.text).toContain(`${c.origin}/badges/new/email-exact/verify?token=`);
    expect(message?.text).toContain(magic.expectedToken!);
  });

  it("carries the lowercased address in wizard state (anchor + claim computed at verify)", async () => {
    const start = await emailExactPlugin.startWizard(ctx());
    const result = await emailExactPlugin.handleStep(
      start,
      { email: "Alice@Workmail.Test" },
      ctx(),
    );
    if (result.kind !== "continue") throw new Error("kind");
    expect(result.state.data).toEqual({ email: "alice@workmail.test" });
  });

  it("audits the domain only, never the address", async () => {
    const c = ctx();
    const start = await emailExactPlugin.startWizard(c);
    await emailExactPlugin.handleStep(start, { email: "alice@workmail.test" }, c);
    const call = vi.mocked(c.audit.log).mock.calls[0];
    expect(call?.[0]).toBe("plugin.email_exact.verification_sent");
    expect(call?.[1]).toEqual({ domain: "workmail.test" });
    expect(JSON.stringify(call?.[1])).not.toContain("alice");
  });

  it("rejects malformed email input", async () => {
    const start = await emailExactPlugin.startWizard(ctx());
    const result = await emailExactPlugin.handleStep(start, { email: "not-an-email" }, ctx());
    expect(result.kind).toBe("error");
  });
});

describe("emailExactPlugin.handleStep — magic-link → complete", () => {
  function magicLinkState(token: string, email: string): WizardState {
    return {
      pluginId: "email-exact",
      userId: "user_test",
      currentStep: {
        id: "wait-magic-link",
        kind: "magic-link",
        payload: { sentTo: email, expectedToken: token },
      },
      data: { email },
    };
  }

  it("reveals the normalized full address as the claim and the same anchor", async () => {
    const result = await emailExactPlugin.handleStep(
      magicLinkState("TOKEN_xyz", "someone@workmail.test"),
      { token: "TOKEN_xyz" },
      ctx(),
    );
    expect(result.kind).toBe("complete");
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges).toHaveLength(1);
    expect(result.badges[0]).toEqual({
      type: "email-exact",
      attributes: { email: "someone@workmail.test" },
      claims: { email: "someone@workmail.test" },
      sybilAnchor: "someone@workmail.test",
      revealsAnchor: true,
    });
  });

  it("normalizes the revealed address (gmail dots + tag) so claim == anchor == canonical", async () => {
    const result = await emailExactPlugin.handleStep(
      magicLinkState("TOKEN_gmail1", "John.Doe+news@gmail.com"),
      { token: "TOKEN_gmail1" },
      ctx(),
    );
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges[0]?.claims).toEqual({ email: "johndoe@gmail.com" });
    expect(result.badges[0]?.sybilAnchor).toBe("johndoe@gmail.com");
  });

  it("shares the anchor with email-domain for the same mailbox", async () => {
    // email-exact and email-domain normalize identically; only the badge_type
    // (dedup namespace) differs. Confirm the anchor strings match.
    const result = await emailExactPlugin.handleStep(
      magicLinkState("TOKEN_gmail2", "j.o.hn+tag@gmail.com"),
      { token: "TOKEN_gmail2" },
      ctx(),
    );
    if (result.kind !== "complete") throw new Error("kind");
    expect(result.badges[0]?.sybilAnchor).toBe("john@gmail.com");
  });

  it("errors if wizard state is missing the verified address", async () => {
    const state: WizardState = {
      pluginId: "email-exact",
      userId: "user_test",
      currentStep: {
        id: "wait-magic-link",
        kind: "magic-link",
        payload: { sentTo: "x@y", expectedToken: "T" },
      },
      data: {},
    };
    const result = await emailExactPlugin.handleStep(state, { token: "T" }, ctx());
    expect(result.kind).toBe("error");
  });
});

describe("emailExactPlugin manifest", () => {
  it("declares the email-exact badge type and no extension dependency", () => {
    expect(emailExactPlugin.manifest.badgeTypes).toEqual(["email-exact"]);
    expect(emailExactPlugin.manifest.requiresExtension).toBe(false);
  });
});
