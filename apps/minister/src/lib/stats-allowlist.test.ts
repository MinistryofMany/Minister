import { describe, expect, it } from "vitest";

import {
  allowlistedKeysFor,
  allowlistedTypeKeyPairs,
  FORBIDDEN_KEYS,
  isAllowlistedKey,
  isAllowlistedValue,
  PUBLISHABLE_KEYS,
} from "@/lib/stats-allowlist";

describe("stats attribute-value allowlist", () => {
  it("allows the closed-enum keys per their type", () => {
    expect(isAllowlistedKey("oauth-account", "provider")).toBe(true);
    expect(isAllowlistedKey("account-age", "provider")).toBe(true);
    expect(isAllowlistedKey("account-age", "olderThanMonths")).toBe(true);
    expect(isAllowlistedKey("social-following", "followersAtLeast")).toBe(true);
    expect(isAllowlistedKey("wallet-control", "chain")).toBe(true);
    expect(isAllowlistedKey("wallet-age", "olderThanMonths")).toBe(true);
    expect(isAllowlistedKey("onchain-event", "event")).toBe(true);
    expect(isAllowlistedKey("public-key", "kind")).toBe(true);
    expect(isAllowlistedKey("age-over-21", "threshold")).toBe(true);
    expect(isAllowlistedKey("residency-country", "country")).toBe(true);
  });

  it("NEVER allows a PII-bearing key, even when the type carries it", () => {
    for (const key of FORBIDDEN_KEYS) {
      for (const type of [
        "email-domain",
        "email-exact",
        "domain-control",
        "public-key",
        "oauth-account",
        "residency-state",
        "residency-city",
      ]) {
        expect(isAllowlistedKey(type, key)).toBe(false);
      }
    }
    // Spot-check the specific leaks the brief calls out.
    expect(isAllowlistedKey("email-domain", "domain")).toBe(false);
    expect(isAllowlistedKey("email-exact", "email")).toBe(false);
    expect(isAllowlistedKey("oauth-account", "handle")).toBe(false);
    expect(isAllowlistedKey("public-key", "fingerprint")).toBe(false);
  });

  it("allows residency-country but NOT residency-state / residency-city (type-level total only)", () => {
    expect(isAllowlistedKey("residency-country", "country")).toBe(true);
    expect(isAllowlistedKey("residency-state", "country")).toBe(false);
    expect(isAllowlistedKey("residency-state", "state")).toBe(false);
    expect(isAllowlistedKey("residency-city", "country")).toBe(false);
    expect(isAllowlistedKey("residency-city", "city")).toBe(false);
    expect(allowlistedKeysFor("residency-state")).toEqual([]);
    expect(allowlistedKeysFor("residency-city")).toEqual([]);
  });

  it("fails closed on an unknown type or an unlisted key", () => {
    expect(isAllowlistedKey("not-a-real-type", "provider")).toBe(false);
    expect(isAllowlistedKey("oauth-account", "olderThanMonths")).toBe(false);
    expect(allowlistedKeysFor("not-a-real-type")).toEqual([]);
  });

  it("closes the VALUE domain: accepts in-enum values, rejects out-of-domain ones", () => {
    // In-domain (values arrive as TEXT via attributes ->> key).
    expect(isAllowlistedValue("oauth-account", "provider", "github")).toBe(true);
    expect(isAllowlistedValue("account-age", "olderThanMonths", "24")).toBe(true);
    expect(isAllowlistedValue("social-following", "followersAtLeast", "100")).toBe(true);
    expect(isAllowlistedValue("wallet-control", "chain", "ethereum")).toBe(true);
    expect(isAllowlistedValue("onchain-event", "event", "eth2-genesis-depositor")).toBe(true);
    expect(isAllowlistedValue("age-over-21", "threshold", "21")).toBe(true);
    expect(isAllowlistedValue("public-key", "kind", "pgp")).toBe(true);
    expect(isAllowlistedValue("residency-country", "country", "US")).toBe(true);

    // Out-of-domain values under an ALLOWLISTED key — Badge.attributes is stored
    // verbatim, so a forged/free-text value must be rejected.
    expect(isAllowlistedValue("oauth-account", "provider", "evil-freetext")).toBe(false);
    expect(isAllowlistedValue("account-age", "olderThanMonths", "13")).toBe(false);
    expect(isAllowlistedValue("wallet-control", "chain", "dogecoin")).toBe(false);
    expect(isAllowlistedValue("age-over-21", "threshold", "20")).toBe(false);
    expect(isAllowlistedValue("public-key", "kind", "rsa")).toBe(false);
    expect(isAllowlistedValue("residency-country", "country", "usa")).toBe(false);

    // A non-allowlisted (type,key) is rejected regardless of value.
    expect(isAllowlistedValue("oauth-account", "handle", "github")).toBe(false);
    expect(isAllowlistedValue("email-domain", "domain", "example.com")).toBe(false);
  });

  it("every materialized (type,key) pair uses only publishable, non-forbidden keys", () => {
    const publishable = new Set<string>(PUBLISHABLE_KEYS);
    const forbidden = new Set<string>(FORBIDDEN_KEYS);
    for (const { key } of allowlistedTypeKeyPairs()) {
      expect(publishable.has(key)).toBe(true);
      expect(forbidden.has(key)).toBe(false);
    }
  });
});
