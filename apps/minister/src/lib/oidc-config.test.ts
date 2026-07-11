import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { badgeScopes, getOidcDiscovery, oidcIssuerUrl } from "./oidc-config";

describe("oidcIssuerUrl", () => {
  const ORIGINAL_AUTH_URL = process.env.AUTH_URL;
  const ORIGINAL_NEXTAUTH_URL = process.env.NEXTAUTH_URL;

  beforeEach(() => {
    delete process.env.AUTH_URL;
    delete process.env.NEXTAUTH_URL;
  });
  afterEach(() => {
    if (ORIGINAL_AUTH_URL === undefined) delete process.env.AUTH_URL;
    else process.env.AUTH_URL = ORIGINAL_AUTH_URL;
    if (ORIGINAL_NEXTAUTH_URL === undefined) delete process.env.NEXTAUTH_URL;
    else process.env.NEXTAUTH_URL = ORIGINAL_NEXTAUTH_URL;
  });

  it("reads AUTH_URL", () => {
    process.env.AUTH_URL = "http://localhost:3000";
    expect(oidcIssuerUrl()).toBe("http://localhost:3000");
  });

  it("falls back to NEXTAUTH_URL", () => {
    process.env.NEXTAUTH_URL = "https://example.com";
    expect(oidcIssuerUrl()).toBe("https://example.com");
  });

  it("strips a trailing slash so token issuance matches discovery", () => {
    process.env.AUTH_URL = "http://localhost:3000/";
    expect(oidcIssuerUrl()).toBe("http://localhost:3000");
  });

  it("throws when neither env var is set", () => {
    expect(() => oidcIssuerUrl()).toThrow(/AUTH_URL/);
  });
});

describe("badgeScopes", () => {
  it("returns one badge:<type> for each registered badge type", () => {
    const scopes = badgeScopes();
    expect(scopes.length).toBeGreaterThan(0);
    for (const scope of scopes) {
      expect(scope).toMatch(/^badge:[a-z0-9-]+$/);
    }
    expect(scopes).toContain("badge:email-domain");
    expect(scopes).toContain("badge:oauth-account");
  });
});

describe("getOidcDiscovery", () => {
  const ORIGINAL_AUTH_URL = process.env.AUTH_URL;
  beforeEach(() => {
    process.env.AUTH_URL = "http://localhost:3000";
  });
  afterEach(() => {
    if (ORIGINAL_AUTH_URL === undefined) delete process.env.AUTH_URL;
    else process.env.AUTH_URL = ORIGINAL_AUTH_URL;
  });

  it("emits issuer + all four endpoint URLs under that issuer", () => {
    const d = getOidcDiscovery();
    expect(d.issuer).toBe("http://localhost:3000");
    expect(d.authorization_endpoint).toBe("http://localhost:3000/oidc/authorize");
    expect(d.token_endpoint).toBe("http://localhost:3000/oidc/token");
    expect(d.userinfo_endpoint).toBe("http://localhost:3000/oidc/userinfo");
    expect(d.jwks_uri).toBe("http://localhost:3000/.well-known/jwks.json");
  });

  it("advertises only the choices we actually implement", () => {
    const d = getOidcDiscovery();
    expect(d.response_types_supported).toEqual(["code"]);
    expect(d.grant_types_supported).toEqual(["authorization_code"]);
    expect(d.subject_types_supported).toEqual(["pairwise"]);
    expect(d.id_token_signing_alg_values_supported).toEqual(["EdDSA"]);
    expect(d.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("lists openid + profile + at least one badge scope", () => {
    const d = getOidcDiscovery();
    expect(d.scopes_supported).toContain("openid");
    expect(d.scopes_supported).toContain("profile");
    expect(d.scopes_supported.some((s) => s.startsWith("badge:"))).toBe(true);
  });

  it("includes the minister_badges custom claim in claims_supported", () => {
    expect(getOidcDiscovery().claims_supported).toContain("minister_badges");
  });

  it("advertises the sybil-score scope and the sybil_bucket claim", () => {
    const d = getOidcDiscovery();
    expect(d.scopes_supported).toContain("sybil-score");
    expect(d.claims_supported).toContain("sybil_bucket");
  });
});
