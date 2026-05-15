import { createHash } from "node:crypto";

import { describe, expect, it, beforeAll, afterAll } from "vitest";

import { pairwiseSub, verifyPkceS256 } from "./oidc-tokens";

describe("pairwiseSub", () => {
  const ORIGINAL_PAIRWISE = process.env.OIDC_PAIRWISE_SECRET;
  const ORIGINAL_AUTH = process.env.AUTH_SECRET;

  beforeAll(() => {
    process.env.OIDC_PAIRWISE_SECRET = "test-pairwise-secret-32-chars-min!!";
  });
  afterAll(() => {
    if (ORIGINAL_PAIRWISE === undefined) {
      delete process.env.OIDC_PAIRWISE_SECRET;
    } else {
      process.env.OIDC_PAIRWISE_SECRET = ORIGINAL_PAIRWISE;
    }
    if (ORIGINAL_AUTH === undefined) {
      delete process.env.AUTH_SECRET;
    } else {
      process.env.AUTH_SECRET = ORIGINAL_AUTH;
    }
  });

  it("returns a stable, base64url string for a given (userId, clientId)", () => {
    const a = pairwiseSub("user_1", "client_A");
    const b = pairwiseSub("user_1", "client_A");
    expect(a).toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("returns different subs for different clients (same user)", () => {
    expect(pairwiseSub("user_1", "client_A")).not.toBe(
      pairwiseSub("user_1", "client_B"),
    );
  });

  it("returns different subs for different users (same client)", () => {
    expect(pairwiseSub("user_1", "client_A")).not.toBe(
      pairwiseSub("user_2", "client_A"),
    );
  });

  it("output length matches HMAC-SHA-256 (32 bytes → 43 base64url chars)", () => {
    expect(pairwiseSub("u", "c").length).toBe(43);
  });

  it("falls back to AUTH_SECRET when OIDC_PAIRWISE_SECRET is unset", () => {
    delete process.env.OIDC_PAIRWISE_SECRET;
    process.env.AUTH_SECRET = "auth-fallback-secret-32-chars-min!!";
    expect(() => pairwiseSub("u", "c")).not.toThrow();
    process.env.OIDC_PAIRWISE_SECRET = "test-pairwise-secret-32-chars-min!!";
  });

  it("throws if neither secret is set", () => {
    delete process.env.OIDC_PAIRWISE_SECRET;
    delete process.env.AUTH_SECRET;
    expect(() => pairwiseSub("u", "c")).toThrow(/must be set/);
    process.env.OIDC_PAIRWISE_SECRET = "test-pairwise-secret-32-chars-min!!";
  });
});

describe("verifyPkceS256", () => {
  function challengeFor(verifier: string): string {
    return createHash("sha256").update(verifier).digest("base64url");
  }

  it("accepts a verifier whose SHA-256 matches the challenge", () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    expect(verifyPkceS256(verifier, challengeFor(verifier))).toBe(true);
  });

  it("rejects a verifier that doesn't match the challenge", () => {
    const correctVerifier = "abc123";
    const wrongVerifier = "xyz789";
    expect(verifyPkceS256(wrongVerifier, challengeFor(correctVerifier))).toBe(
      false,
    );
  });

  it("rejects a malformed challenge (not base64url)", () => {
    expect(verifyPkceS256("anything", "not!valid base64url ===")).toBe(false);
  });

  it("rejects a challenge of the wrong length", () => {
    // 32 bytes hashed → 43 b64url chars; pass something shorter.
    expect(verifyPkceS256("any-verifier", "AAAA")).toBe(false);
  });

  it("rejects an empty verifier vs a real challenge", () => {
    expect(verifyPkceS256("", challengeFor("real"))).toBe(false);
  });
});
