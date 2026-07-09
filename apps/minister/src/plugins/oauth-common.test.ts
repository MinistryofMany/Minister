import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  accountAgeBadge,
  dateFromUnixSeconds,
  highestBucket,
  monthsBetween,
  pkcePair,
  randomToken,
} from "./oauth-common";

describe("monthsBetween", () => {
  it("counts whole calendar months", () => {
    expect(monthsBetween(new Date("2025-01-01T00:00:00Z"), new Date("2026-01-01T00:00:00Z"))).toBe(
      12,
    );
  });

  it("does not count a partial final month", () => {
    // 11 months and a few days short of a full year.
    expect(monthsBetween(new Date("2025-01-15T00:00:00Z"), new Date("2026-01-10T00:00:00Z"))).toBe(
      11,
    );
  });

  it("never goes negative for a future creation date", () => {
    expect(monthsBetween(new Date("2030-01-01T00:00:00Z"), new Date("2026-01-01T00:00:00Z"))).toBe(
      0,
    );
  });
});

describe("highestBucket", () => {
  it("returns the highest cleared bucket", () => {
    expect(highestBucket(1500, [10, 50, 100, 500, 1000])).toBe(1000);
  });
  it("returns null when nothing is cleared", () => {
    expect(highestBucket(5, [10, 50])).toBeNull();
  });
  it("is inclusive at the boundary", () => {
    expect(highestBucket(50, [10, 50, 100])).toBe(50);
  });
});

describe("dateFromUnixSeconds", () => {
  it("converts seconds to a Date", () => {
    expect(dateFromUnixSeconds(0)?.toISOString()).toBe("1970-01-01T00:00:00.000Z");
  });
  it("rejects non-finite input", () => {
    expect(dateFromUnixSeconds(Number.NaN)).toBeNull();
    expect(dateFromUnixSeconds(Number.POSITIVE_INFINITY)).toBeNull();
  });
});

describe("accountAgeBadge", () => {
  const now = new Date("2026-01-01T00:00:00Z");

  it("builds the highest-bucket account-age badge with the shared anchor", () => {
    const badge = accountAgeBadge("reddit", new Date("2015-01-01T00:00:00Z"), "t2_abc", now);
    expect(badge).toEqual({
      type: "account-age",
      attributes: { provider: "reddit", olderThanMonths: 60 },
      claims: { provider: "reddit", olderThanMonths: 60 },
      sybilAnchor: "t2_abc",
    });
  });

  it("returns null for an account too new to clear the lowest bucket", () => {
    expect(accountAgeBadge("github", new Date("2025-06-01T00:00:00Z"), "1", now)).toBeNull();
  });

  it("returns null for a missing date", () => {
    expect(accountAgeBadge("github", null, "1", now)).toBeNull();
  });
});

describe("pkcePair", () => {
  it("produces a verifier whose S256 hash is the challenge", () => {
    const { verifier, challenge } = pkcePair();
    expect(challenge).toBe(createHash("sha256").update(verifier).digest("base64url"));
    expect(verifier).not.toBe(challenge);
  });
  it("is random per call", () => {
    expect(pkcePair().verifier).not.toBe(pkcePair().verifier);
  });
});

describe("randomToken", () => {
  it("is url-safe and unique", () => {
    const a = randomToken();
    const b = randomToken();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/u);
  });
});
