import { describe, expect, it } from "vitest";

import type { WizardState } from "@minister/plugin-sdk";

import { effectiveScopes, pendingTokenFor } from "./wizard-helpers";

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
