import { describe, expect, it } from "vitest";

import type { WizardState } from "@minister/plugin-sdk";

import { effectiveScopes, pendingTokenFor, toClientState } from "./wizard-helpers";

function makeState(step: WizardState["currentStep"]): WizardState {
  return {
    pluginId: "test",
    userId: "user_1",
    currentStep: step,
    data: {},
  };
}

describe("pendingTokenFor", () => {
  it("returns expectedToken on a magic-link step", () => {
    const state = makeState({
      id: "wait",
      kind: "magic-link",
      payload: { sentTo: "x@y", expectedToken: "TOKEN_123" },
    });
    expect(pendingTokenFor(state)).toBe("TOKEN_123");
  });

  it("returns expectedState on a redirect step", () => {
    const state = makeState({
      id: "go",
      kind: "redirect",
      payload: { url: "https://x.test/auth", expectedState: "STATE_456" },
    });
    expect(pendingTokenFor(state)).toBe("STATE_456");
  });

  it("returns expectedSubmissionToken on an extension-action step", () => {
    const state = makeState({
      id: "ext",
      kind: "extension-action",
      payload: {
        action: "tlsn-prove",
        params: {},
        expectedSubmissionToken: "SUBMIT_789",
      },
    });
    expect(pendingTokenFor(state)).toBe("SUBMIT_789");
  });

  it("returns null when magic-link omits expectedToken", () => {
    const state = makeState({
      id: "wait",
      kind: "magic-link",
      payload: { sentTo: "x@y" },
    });
    expect(pendingTokenFor(state)).toBe(null);
  });

  it("returns null when redirect omits expectedState", () => {
    const state = makeState({
      id: "go",
      kind: "redirect",
      payload: { url: "https://x.test/auth" },
    });
    expect(pendingTokenFor(state)).toBe(null);
  });

  it("returns null for non-round-trip step kinds", () => {
    const steps: WizardState["currentStep"][] = [
      { id: "f", kind: "form", payload: { title: "x", fields: [] } },
      { id: "i", kind: "info", payload: { title: "x", body: "y" } },
      {
        id: "e",
        kind: "extension-action",
        payload: { action: "tlsn-prove", params: {} },
      },
    ];
    for (const step of steps) {
      expect(pendingTokenFor(makeState(step))).toBe(null);
    }
  });
});

describe("toClientState — no pending-token secret or server-side data crosses the wire", () => {
  it("strips expectedToken (and data) from a magic-link step", () => {
    const state: WizardState = {
      pluginId: "email-domain",
      userId: "user_1",
      currentStep: {
        id: "wait",
        kind: "magic-link",
        payload: { sentTo: "victim@bigcorp.com", description: "d", expectedToken: "SECRET_TOK" },
      },
      data: { email: "victim@bigcorp.com", domain: "bigcorp.com" },
    };
    const client = toClientState(state);
    // capture-at-verify: the token the verify route trusts as inbox proof must
    // NOT be readable in the server-action response body.
    expect(client.currentStep.kind).toBe("magic-link");
    if (client.currentStep.kind !== "magic-link") throw new Error("kind");
    expect(client.currentStep.payload.expectedToken).toBeUndefined();
    // display fields survive
    expect(client.currentStep.payload.sentTo).toBe("victim@bigcorp.com");
    expect(client.currentStep.payload.description).toBe("d");
    // the raw address carried in server-side data does not cross
    expect(client.data).toEqual({});
    expect(JSON.stringify(client)).not.toContain("SECRET_TOK");
    // the original is untouched (still persisted with its token by the runtime)
    expect(state.currentStep.kind === "magic-link" && state.currentStep.payload.expectedToken).toBe(
      "SECRET_TOK",
    );
  });

  it("strips expectedState from a redirect step but keeps the url", () => {
    const client = toClientState({
      pluginId: "github",
      userId: "u",
      currentStep: {
        id: "go",
        kind: "redirect",
        payload: { url: "https://gh.test/auth?state=X", expectedState: "STATE_SECRET" },
      },
      data: {},
    });
    if (client.currentStep.kind !== "redirect") throw new Error("kind");
    expect(client.currentStep.payload.expectedState).toBeUndefined();
    expect(client.currentStep.payload.url).toBe("https://gh.test/auth?state=X");
  });

  it("strips expectedSubmissionToken from an extension-action step", () => {
    const client = toClientState({
      pluginId: "tlsn-attestation",
      userId: "u",
      currentStep: {
        id: "ext",
        kind: "extension-action",
        payload: { action: "tlsn-prove", params: {}, expectedSubmissionToken: "SUB_SECRET" },
      },
      data: {},
    });
    if (client.currentStep.kind !== "extension-action") throw new Error("kind");
    expect(client.currentStep.payload.expectedSubmissionToken).toBeUndefined();
    expect(client.currentStep.payload.action).toBe("tlsn-prove");
  });

  it("passes a form/info step through (no secret), still dropping data", () => {
    const client = toClientState({
      pluginId: "email-domain",
      userId: "u",
      currentStep: { id: "f", kind: "form", payload: { title: "t", fields: [] } },
      data: { scratch: "value" },
    });
    expect(client.currentStep.kind).toBe("form");
    expect(client.data).toEqual({});
  });
});

describe("effectiveScopes", () => {
  const userBadges = [
    { id: "b_1", type: "email-domain" },
    { id: "b_2", type: "oauth-account" },
  ];

  it("always preserves openid", () => {
    expect(
      effectiveScopes(["openid"], {
        approveProfile: false,
        approvedBadgeIds: [],
        userBadges: [],
      }),
    ).toEqual(["openid"]);
  });

  it("preserves profile only if approveProfile is true", () => {
    expect(
      effectiveScopes(["openid", "profile"], {
        approveProfile: true,
        approvedBadgeIds: [],
        userBadges: [],
      }),
    ).toEqual(["openid", "profile"]);
    expect(
      effectiveScopes(["openid", "profile"], {
        approveProfile: false,
        approvedBadgeIds: [],
        userBadges: [],
      }),
    ).toEqual(["openid"]);
  });

  it("keeps badge:<type> when at least one matching badge is approved", () => {
    expect(
      effectiveScopes(["openid", "badge:email-domain"], {
        approveProfile: false,
        approvedBadgeIds: ["b_1"],
        userBadges,
      }),
    ).toEqual(["openid", "badge:email-domain"]);
  });

  it("drops badge:<type> when no badge of that type is approved", () => {
    expect(
      effectiveScopes(["openid", "badge:email-domain"], {
        approveProfile: false,
        approvedBadgeIds: ["b_2"], // wrong type
        userBadges,
      }),
    ).toEqual(["openid"]);
  });

  it("drops badge:<type> when approvedBadgeIds is empty", () => {
    expect(
      effectiveScopes(["openid", "badge:email-domain"], {
        approveProfile: false,
        approvedBadgeIds: [],
        userBadges,
      }),
    ).toEqual(["openid"]);
  });

  it("handles mixed scopes and preserves request order", () => {
    expect(
      effectiveScopes(["openid", "profile", "badge:email-domain", "badge:oauth-account"], {
        approveProfile: true,
        approvedBadgeIds: ["b_2"],
        userBadges,
      }),
    ).toEqual(["openid", "profile", "badge:oauth-account"]);
  });

  it("defensively drops unknown scopes", () => {
    expect(
      effectiveScopes(["openid", "fancy_unknown_scope"], {
        approveProfile: false,
        approvedBadgeIds: [],
        userBadges: [],
      }),
    ).toEqual(["openid"]);
  });
});
