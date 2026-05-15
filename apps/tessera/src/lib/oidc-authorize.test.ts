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
  client_id: "tc_demo",
  redirect_uri: "http://localhost:3100/cb",
  scope: "openid profile",
  state: "STATE_1",
  nonce: "NONCE_1",
  code_challenge: "CHAL_1",
  code_challenge_method: "S256",
};

const DEMO_CLIENT = {
  clientId: "tc_demo",
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
    const res = await validateAuthorizeRequest(
      build({ code_challenge_method: "plain" }),
    );
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
    const res = await validateAuthorizeRequest(
      build({ scope: "openid badge:not-allowed" }),
    );
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
      clientId: "tc_demo",
      clientName: "Demo",
      allowedScopes: DEMO_CLIENT.allowedScopes,
      redirectUri: "http://localhost:3100/cb",
      scopes: ["openid", "profile"],
      state: "STATE_1",
      nonce: "NONCE_1",
      codeChallenge: "CHAL_1",
      codeChallengeMethod: "S256",
    });
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
    const url = buildErrorRedirect(
      "http://x.test/cb",
      "invalid_request",
      "no state",
      null,
    );
    expect(new URL(url).searchParams.has("state")).toBe(false);
  });

  it("success redirect carries code + state", () => {
    const url = buildSuccessRedirect("http://x.test/cb", "CODE_42", "STATE_y");
    const parsed = new URL(url);
    expect(parsed.searchParams.get("code")).toBe("CODE_42");
    expect(parsed.searchParams.get("state")).toBe("STATE_y");
  });

  it("preserves existing query on the redirect_uri", () => {
    const url = buildSuccessRedirect(
      "http://x.test/cb?existing=1",
      "CODE",
      "STATE",
    );
    const parsed = new URL(url);
    expect(parsed.searchParams.get("existing")).toBe("1");
    expect(parsed.searchParams.get("code")).toBe("CODE");
  });
});
