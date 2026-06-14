import { describe, expect, it } from "vitest";

import {
  allOidcScopes,
  parseRedirectUris,
  validateClientScopes,
} from "./oidc-client-admin";

describe("parseRedirectUris", () => {
  it("accepts one https URI per line and dedupes", () => {
    const result = parseRedirectUris(
      "https://app.example.com/cb\n\n  https://app.example.com/cb  \nhttps://other.example.com/auth/callback",
    );
    expect(result).toEqual({
      ok: true,
      uris: [
        "https://app.example.com/cb",
        "https://other.example.com/auth/callback",
      ],
    });
  });

  it("accepts http on localhost and 127.0.0.1 only", () => {
    expect(
      parseRedirectUris("http://localhost:3100/api/auth/callback/minister").ok,
    ).toBe(true);
    expect(parseRedirectUris("http://127.0.0.1:8080/cb").ok).toBe(true);
    const rejected = parseRedirectUris("http://app.example.com/cb");
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) expect(rejected.error).toContain("https");
  });

  it("rejects fragments per RFC 6749", () => {
    const result = parseRedirectUris("https://app.example.com/cb#frag");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("fragment");
  });

  it("rejects relative and garbage URLs", () => {
    expect(parseRedirectUris("/relative/path").ok).toBe(false);
    expect(parseRedirectUris("not a url").ok).toBe(false);
  });

  it("requires at least one URI", () => {
    expect(parseRedirectUris("\n  \n").ok).toBe(false);
  });
});

describe("validateClientScopes", () => {
  it("accepts openid plus known scopes", () => {
    const result = validateClientScopes([
      "openid",
      "profile",
      "badge:email-domain",
    ]);
    expect(result).toEqual({
      ok: true,
      scopes: ["openid", "profile", "badge:email-domain"],
    });
  });

  it("requires openid", () => {
    const result = validateClientScopes(["profile"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("openid");
  });

  it("rejects unknown scopes", () => {
    const result = validateClientScopes(["openid", "badge:not-a-type"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("badge:not-a-type");
  });

  it("dedupes", () => {
    const result = validateClientScopes(["openid", "openid", "profile"]);
    expect(result).toEqual({ ok: true, scopes: ["openid", "profile"] });
  });

  it("allOidcScopes covers every registered badge type", () => {
    const scopes = allOidcScopes();
    expect(scopes).toContain("openid");
    expect(scopes).toContain("profile");
    expect(scopes).toContain("badge:email-domain");
    expect(scopes).toContain("badge:invite-code");
    expect(scopes).toContain("badge:age-over-21");
  });
});
