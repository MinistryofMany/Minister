import { describe, expect, it } from "vitest";

import { gravatarHash, gravatarUrl } from "@/lib/gravatar";

describe("gravatarHash", () => {
  // Known vector: Gravatar hashes the trimmed, lowercased address with SHA-256.
  const NORMALIZED = "myemailaddress@example.com";
  const SHA256 = "84059b07d4be67b806386c0aad8070a23f18836bbaae342275dc0a83414c32ee";

  it("hashes the normalized email per the Gravatar spec", () => {
    expect(gravatarHash(NORMALIZED)).toBe(SHA256);
  });

  it("trims surrounding whitespace before hashing", () => {
    expect(gravatarHash("  myemailaddress@example.com  ")).toBe(SHA256);
  });

  it("lowercases before hashing (case-insensitive addresses hash the same)", () => {
    expect(gravatarHash("MyEmailAddress@Example.com")).toBe(SHA256);
  });

  it("is stable across calls", () => {
    expect(gravatarHash("a@b.com")).toBe(gravatarHash("a@b.com"));
  });
});

describe("gravatarUrl", () => {
  it("builds an https gravatar URL with the d=404 fallback param", () => {
    expect(gravatarUrl("MyEmailAddress@Example.com")).toBe(
      "https://www.gravatar.com/avatar/84059b07d4be67b806386c0aad8070a23f18836bbaae342275dc0a83414c32ee?d=404",
    );
  });

  it("always produces an https URL", () => {
    expect(gravatarUrl("someone@else.org").startsWith("https://")).toBe(true);
  });
});
