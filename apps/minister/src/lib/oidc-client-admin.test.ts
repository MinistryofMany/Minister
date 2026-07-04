import { describe, expect, it } from "vitest";

import {
  allOidcScopes,
  isValidClientId,
  parseRedirectUris,
  validateClientId,
  validateClientScopes,
} from "./oidc-client-admin";

describe("parseRedirectUris", () => {
  it("accepts one https URI per line and dedupes", () => {
    const result = parseRedirectUris(
      "https://app.example.com/cb\n\n  https://app.example.com/cb  \nhttps://other.example.com/auth/callback",
    );
    expect(result).toEqual({
      ok: true,
      uris: ["https://app.example.com/cb", "https://other.example.com/auth/callback"],
    });
  });

  it("accepts http on localhost and 127.0.0.1 only", () => {
    expect(parseRedirectUris("http://localhost:3100/api/auth/callback/minister").ok).toBe(true);
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
    const result = validateClientScopes(["openid", "profile", "badge:email-domain"]);
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

describe("validateClientId (frozen charset guard)", () => {
  it("accepts a Minister-generated mc_ + base64url id", () => {
    expect(isValidClientId("mc_abcDEF123_-")).toBe(true);
    const r = validateClientId("mc_abcDEF123_-");
    expect(r).toEqual({ ok: true, clientId: "mc_abcDEF123_-" });
  });

  it("rejects a colon-bearing clientId (the frozen-encoding delimiter risk)", () => {
    // A colon would collide the legacy `${userId}:${clientId}` pairwise input.
    const r = validateClientId("mc_evil:injected");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("^mc_[A-Za-z0-9_-]+$");
    expect(isValidClientId("mc_evil:injected")).toBe(false);
  });

  it("rejects ids without the mc_ prefix and other delimiters", () => {
    expect(isValidClientId("plain_client")).toBe(false);
    expect(isValidClientId("mc_")).toBe(false); // prefix only, no body
    expect(isValidClientId("mc_has space")).toBe(false);
    expect(isValidClientId("mc_has/slash")).toBe(false);
    expect(isValidClientId("mc_has.dot")).toBe(false);
  });

  it("allows the legacy demo_client id as an exact-match exception", () => {
    expect(isValidClientId("demo_client")).toBe(true);
    // but not a lookalike that merely contains it
    expect(isValidClientId("demo_client_2")).toBe(false);
    expect(isValidClientId("xdemo_client")).toBe(false);
  });
});
