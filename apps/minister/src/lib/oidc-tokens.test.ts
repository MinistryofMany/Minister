import { createHash } from "node:crypto";

import { describe, expect, it, beforeAll, afterAll } from "vitest";

import { pairwiseJti, pairwiseSub, verifyPkceS256 } from "./oidc-tokens";

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
    expect(pairwiseSub("user_1", "client_A")).not.toBe(pairwiseSub("user_1", "client_B"));
  });

  it("returns different subs for different users (same client)", () => {
    expect(pairwiseSub("user_1", "client_A")).not.toBe(pairwiseSub("user_2", "client_A"));
  });

  it("output length matches HMAC-SHA-256 (32 bytes → 43 base64url chars)", () => {
    expect(pairwiseSub("u", "c").length).toBe(43);
  });

  it("fails fast when only AUTH_SECRET is set — no silent fallback", () => {
    // The AUTH_SECRET fallback was removed: leaning on it silently re-keys every
    // pairwise sub if OIDC_PAIRWISE_SECRET is ever unset. Must throw instead.
    delete process.env.OIDC_PAIRWISE_SECRET;
    process.env.AUTH_SECRET = "auth-fallback-secret-32-chars-min!!";
    expect(() => pairwiseSub("u", "c")).toThrow(/OIDC_PAIRWISE_SECRET must be set/);
    process.env.OIDC_PAIRWISE_SECRET = "test-pairwise-secret-32-chars-min!!";
  });

  it("throws if the secret is not set", () => {
    delete process.env.OIDC_PAIRWISE_SECRET;
    delete process.env.AUTH_SECRET;
    expect(() => pairwiseSub("u", "c")).toThrow(/must be set/);
    process.env.OIDC_PAIRWISE_SECRET = "test-pairwise-secret-32-chars-min!!";
  });
});

describe("pairwiseJti", () => {
  const ORIGINAL_PAIRWISE = process.env.OIDC_PAIRWISE_SECRET;
  const ORIGINAL_AUTH = process.env.AUTH_SECRET;

  beforeAll(() => {
    process.env.OIDC_PAIRWISE_SECRET = "test-pairwise-secret-32-chars-min!!";
  });
  afterAll(() => {
    if (ORIGINAL_PAIRWISE === undefined) delete process.env.OIDC_PAIRWISE_SECRET;
    else process.env.OIDC_PAIRWISE_SECRET = ORIGINAL_PAIRWISE;
    if (ORIGINAL_AUTH === undefined) delete process.env.AUTH_SECRET;
    else process.env.AUTH_SECRET = ORIGINAL_AUTH;
  });

  it("is stable per (badgeId, clientId) and base64url", () => {
    const a = pairwiseJti("badge_1", "client_A");
    expect(a).toBe(pairwiseJti("badge_1", "client_A"));
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(a.length).toBe(43); // HMAC-SHA-256, 32 bytes → 43 base64url chars
  });

  it("differs across relying parties for the same badge (cross-RP unlinkable jti)", () => {
    expect(pairwiseJti("badge_1", "client_A")).not.toBe(pairwiseJti("badge_1", "client_B"));
  });

  it("is never equal to the raw badge id (the stored jti = badge.id was the leak)", () => {
    const badgeId = "badge_cuid_abcdef";
    expect(pairwiseJti(badgeId, "client_A")).not.toBe(badgeId);
  });

  it("is domain-separated from pairwiseSub — no collision when the ids coincide", () => {
    // A userId and a badgeId are cuids from different tables; even if one
    // equalled the other, the "jti:" prefix keeps the two HMACs disjoint.
    const shared = "collision_candidate_id";
    expect(pairwiseJti(shared, "client_A")).not.toBe(pairwiseSub(shared, "client_A"));
  });

  it("throws if neither secret is set", () => {
    delete process.env.OIDC_PAIRWISE_SECRET;
    delete process.env.AUTH_SECRET;
    expect(() => pairwiseJti("b", "c")).toThrow(/must be set/);
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
    expect(verifyPkceS256(wrongVerifier, challengeFor(correctVerifier))).toBe(false);
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
