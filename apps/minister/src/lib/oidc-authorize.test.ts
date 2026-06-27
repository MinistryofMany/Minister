import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  buildErrorRedirect,
  buildSuccessRedirect,
  validateAuthorizeRequest,
} from "./oidc-authorize";

// Mock the DB-touching helpers from oidc-clients. The validation logic
// is the unit under test; the actual client lookup is exercised in
// integration via Playwright.
vi.mock("./oidc-clients", () => ({
  findClient: vi.fn(),
  isRegisteredRedirectUri: vi.fn(),
}));

// Re-import so we get the vi.fn-backed exports.
import { findClient, isRegisteredRedirectUri } from "./oidc-clients";

const VALID_PARAMS = {
  response_type: "code",
  client_id: "mc_demo",
  redirect_uri: "http://localhost:3100/cb",
  scope: "openid profile",
  state: "STATE_1",
  nonce: "NONCE_1",
  code_challenge: "CHAL_1",
  code_challenge_method: "S256",
};

const DEMO_CLIENT = {
  clientId: "mc_demo",
  name: "Demo",
  allowedScopes: ["openid", "profile", "badge:email-domain"],
  redirectUris: ["http://localhost:3100/cb"],
};

function build(overrides: Partial<Record<string, string>>): URLSearchParams {
  return new URLSearchParams({ ...VALID_PARAMS, ...overrides });
}

beforeEach(() => {
  vi.mocked(findClient).mockReset();
  vi.mocked(isRegisteredRedirectUri).mockReset();
});
afterEach(() => {
  vi.mocked(findClient).mockReset();
});

describe("validateAuthorizeRequest — pre-redirect_uri errors are FATAL", () => {
  it("missing client_id → fatal", async () => {
    const res = await validateAuthorizeRequest(
      new URLSearchParams({ ...VALID_PARAMS, client_id: "" }),
    );
    expect(res.kind).toBe("fatal");
  });

  it("unknown client_id → fatal (no open-redirect)", async () => {
    vi.mocked(findClient).mockResolvedValueOnce(null);
    const res = await validateAuthorizeRequest(build({}));
    expect(res.kind).toBe("fatal");
  });

  it("redirect_uri not registered → fatal (no open-redirect)", async () => {
    vi.mocked(findClient).mockResolvedValueOnce(DEMO_CLIENT as never);
    vi.mocked(isRegisteredRedirectUri).mockReturnValueOnce(false);
    const res = await validateAuthorizeRequest(build({}));
    expect(res.kind).toBe("fatal");
  });
});

describe("validateAuthorizeRequest — post-redirect_uri errors redirect back", () => {
  beforeEach(() => {
    vi.mocked(findClient).mockResolvedValue(DEMO_CLIENT as never);
    vi.mocked(isRegisteredRedirectUri).mockReturnValue(true);
  });

  it("wrong response_type → unsupported_response_type", async () => {
    const res = await validateAuthorizeRequest(build({ response_type: "token" }));
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("unsupported_response_type");
  });

  it("missing state → invalid_request", async () => {
    const res = await validateAuthorizeRequest(build({ state: "" }));
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_request");
    expect(res.description).toMatch(/state/);
  });

  it("missing nonce → invalid_request", async () => {
    const res = await validateAuthorizeRequest(build({ nonce: "" }));
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_request");
    expect(res.description).toMatch(/nonce/);
  });

  it("missing code_challenge → invalid_request", async () => {
    const res = await validateAuthorizeRequest(build({ code_challenge: "" }));
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_request");
    expect(res.description).toMatch(/code_challenge/);
  });

  it("code_challenge_method != S256 → invalid_request", async () => {
    const res = await validateAuthorizeRequest(build({ code_challenge_method: "plain" }));
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_request");
    expect(res.description).toMatch(/S256/);
  });

  it("scope missing 'openid' → invalid_scope", async () => {
    const res = await validateAuthorizeRequest(build({ scope: "profile" }));
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_scope");
  });

  it("scope outside client.allowedScopes → invalid_scope", async () => {
    const res = await validateAuthorizeRequest(build({ scope: "openid badge:not-allowed" }));
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_scope");
  });
});

describe("validateAuthorizeRequest — success", () => {
  it("returns ok with the validated, narrowed request", async () => {
    vi.mocked(findClient).mockResolvedValueOnce(DEMO_CLIENT as never);
    vi.mocked(isRegisteredRedirectUri).mockReturnValueOnce(true);
    const res = await validateAuthorizeRequest(build({}));
    if (res.kind !== "ok") throw new Error(`expected ok, got ${res.kind}`);
    expect(res.request).toEqual({
      clientId: "mc_demo",
      clientName: "Demo",
      allowedScopes: DEMO_CLIENT.allowedScopes,
      redirectUri: "http://localhost:3100/cb",
      scopes: ["openid", "profile"],
      state: "STATE_1",
      nonce: "NONCE_1",
      codeChallenge: "CHAL_1",
      codeChallengeMethod: "S256",
      policy: null,
    });
  });
});

function encodePolicy(policy: unknown): string {
  return Buffer.from(JSON.stringify(policy), "utf8").toString("base64url");
}

describe("validateAuthorizeRequest — minister_policy (Phase 2)", () => {
  // A client that allows the badge types used by the policy cases.
  const POLICY_CLIENT = {
    clientId: "mc_demo",
    name: "Demo",
    allowedScopes: ["openid", "profile", "badge:age-over-18", "badge:residency-country"],
    redirectUris: ["http://localhost:3100/cb"],
  };
  const POLICY_SCOPE = "openid profile badge:age-over-18 badge:residency-country";

  beforeEach(() => {
    vi.mocked(findClient).mockResolvedValue(POLICY_CLIENT as never);
    vi.mocked(isRegisteredRedirectUri).mockReturnValue(true);
  });

  it("absent param → policy: null (today's behavior)", async () => {
    const res = await validateAuthorizeRequest(build({ scope: POLICY_SCOPE }));
    if (res.kind !== "ok") throw new Error(`expected ok, got ${res.kind}`);
    expect(res.request.policy).toBeNull();
  });

  it("valid policy whose types are all in scope → policy populated", async () => {
    const policy = {
      anyOf: [{ badge: { type: "age-over-18" } }, { badge: { type: "residency-country" } }],
    };
    const res = await validateAuthorizeRequest(
      build({ scope: POLICY_SCOPE, minister_policy: encodePolicy(policy) }),
    );
    if (res.kind !== "ok") throw new Error(`expected ok, got ${res.kind}`);
    expect(res.request.policy).toEqual(policy);
  });

  it("malformed base64/JSON → invalid_request", async () => {
    const res = await validateAuthorizeRequest(
      build({ scope: POLICY_SCOPE, minister_policy: "!!!not-base64-json!!!" }),
    );
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_request");
    expect(res.description).toMatch(/minister_policy/);
  });

  it("valid JSON that is not a policy → invalid_scope", async () => {
    const res = await validateAuthorizeRequest(
      build({ scope: POLICY_SCOPE, minister_policy: encodePolicy({ not: "a policy" }) }),
    );
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_scope");
  });

  it("policy referencing a type not in scope → invalid_scope (can't widen the menu)", async () => {
    const policy = {
      anyOf: [
        { badge: { type: "age-over-18" } },
        { badge: { type: "oauth-account" } }, // not requested in scope
      ],
    };
    const res = await validateAuthorizeRequest(
      build({ scope: POLICY_SCOPE, minister_policy: encodePolicy(policy) }),
    );
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_scope");
    expect(res.description).toMatch(/oauth-account/);
  });

  it("over-deep policy → invalid_request", async () => {
    // Nest allOf well past MAX_POLICY_DEPTH (8). The deepest leaf is the
    // in-scope type, so this trips the depth guard, not the scope guard.
    let policy: unknown = { badge: { type: "age-over-18" } };
    for (let i = 0; i < 10; i++) policy = { allOf: [policy] };
    const res = await validateAuthorizeRequest(
      build({ scope: POLICY_SCOPE, minister_policy: encodePolicy(policy) }),
    );
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_request");
    expect(res.description).toMatch(/deep/);
  });

  it("oversized policy payload → invalid_request", async () => {
    // A leaf with a giant `where` value pushes the decoded JSON past 4 KB.
    const big = "x".repeat(5000);
    const policy = { badge: { type: "age-over-18", where: { pad: big } } };
    const res = await validateAuthorizeRequest(
      build({ scope: POLICY_SCOPE, minister_policy: encodePolicy(policy) }),
    );
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_request");
    expect(res.description).toMatch(/large/);
  });

  // Audit C-1: a wide `atLeast` (large n, many duplicate-type leaves) is a
  // BREADTH DoS — it stays shallow, under 4 KB, and passes the type-set
  // scope check (one distinct type), yet drives quartic+ combination
  // enumeration. The breadth guard must reject it at validate time.
  it("wide atLeast (large n + many duplicate leaves) → invalid_request (DoS guard)", async () => {
    // The proven payload class: atLeast{ n:156, of:[160 in-scope leaves] }.
    // Fits under 4 KB and references a single in-scope type, so only the
    // node-count / atLeast.n / child-count caps can stop it.
    const leaves = Array.from({ length: 160 }, () => ({ badge: { type: "age-over-18" } }));
    const policy = { atLeast: { n: 156, of: leaves } };
    const res = await validateAuthorizeRequest(
      build({ scope: POLICY_SCOPE, minister_policy: encodePolicy(policy) }),
    );
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_request");
    expect(res.description).toMatch(/too large/);
  });

  it("atLeast.n past the cap (small breadth) → invalid_request", async () => {
    const policy = {
      atLeast: { n: 32, of: [{ badge: { type: "age-over-18" } }] },
    };
    const res = await validateAuthorizeRequest(
      build({ scope: POLICY_SCOPE, minister_policy: encodePolicy(policy) }),
    );
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_request");
    expect(res.description).toMatch(/too large/);
  });

  it("a single node with too many children → invalid_request", async () => {
    const of = Array.from({ length: 40 }, () => ({ badge: { type: "age-over-18" } }));
    const policy = { anyOf: of };
    const res = await validateAuthorizeRequest(
      build({ scope: POLICY_SCOPE, minister_policy: encodePolicy(policy) }),
    );
    if (res.kind !== "redirect-error") throw new Error("expected redirect-error");
    expect(res.error).toBe("invalid_request");
    expect(res.description).toMatch(/too large/);
  });

  it("a realistic small atLeast (n=2, 3 distinct branches) is still ACCEPTED", async () => {
    const policy = {
      atLeast: {
        n: 2,
        of: [{ badge: { type: "age-over-18" } }, { badge: { type: "residency-country" } }],
      },
    };
    const res = await validateAuthorizeRequest(
      build({ scope: POLICY_SCOPE, minister_policy: encodePolicy(policy) }),
    );
    if (res.kind !== "ok") throw new Error(`expected ok, got ${res.kind}`);
    expect(res.request.policy).toEqual(policy);
  });
});

describe("buildErrorRedirect / buildSuccessRedirect", () => {
  it("error redirect carries error + description + state", () => {
    const url = buildErrorRedirect(
      "http://x.test/cb",
      "invalid_request",
      "missing state",
      "STATE_x",
    );
    const parsed = new URL(url);
    expect(parsed.origin + parsed.pathname).toBe("http://x.test/cb");
    expect(parsed.searchParams.get("error")).toBe("invalid_request");
    expect(parsed.searchParams.get("error_description")).toBe("missing state");
    expect(parsed.searchParams.get("state")).toBe("STATE_x");
  });

  it("error redirect omits state when caller passes null", () => {
    const url = buildErrorRedirect("http://x.test/cb", "invalid_request", "no state", null);
    expect(new URL(url).searchParams.has("state")).toBe(false);
  });

  it("success redirect carries code + state", () => {
    const url = buildSuccessRedirect("http://x.test/cb", "CODE_42", "STATE_y");
    const parsed = new URL(url);
    expect(parsed.searchParams.get("code")).toBe("CODE_42");
    expect(parsed.searchParams.get("state")).toBe("STATE_y");
  });

  it("preserves existing query on the redirect_uri", () => {
    const url = buildSuccessRedirect("http://x.test/cb?existing=1", "CODE", "STATE");
    const parsed = new URL(url);
    expect(parsed.searchParams.get("existing")).toBe("1");
    expect(parsed.searchParams.get("code")).toBe("CODE");
  });
});
