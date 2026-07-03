import { describe, expect, it } from "vitest";

import { BADGE_TYPES } from "@minister/shared";

import { buildGithubBadges, highestBucket, monthsBetween } from "./derive";

// A fixed "now" so account-age math is deterministic.
const NOW = new Date("2026-07-01T00:00:00Z");

// Validate a produced badge's claims against its registry schema — mirrors
// what the wizard runtime does before signing. If a derive claim shape ever
// drifts from the badge type schema, these fail.
function assertClaimsValid(type: string, claims: Record<string, unknown>): void {
  const meta = BADGE_TYPES[type];
  expect(meta, `badge type ${type} in registry`).toBeDefined();
  expect(() => meta!.schema.parse(claims)).not.toThrow();
}

describe("monthsBetween", () => {
  it("counts whole calendar months", () => {
    expect(monthsBetween(new Date("2025-07-01"), new Date("2026-07-01"))).toBe(12);
    expect(monthsBetween(new Date("2024-01-15"), new Date("2026-07-14"))).toBe(29);
  });
  it("does not count a month until the day-of-month is reached", () => {
    expect(monthsBetween(new Date("2026-06-15"), new Date("2026-07-14"))).toBe(0);
    expect(monthsBetween(new Date("2026-06-15"), new Date("2026-07-15"))).toBe(1);
  });
  it("never returns negative for a future creation date", () => {
    expect(monthsBetween(new Date("2027-01-01"), NOW)).toBe(0);
  });
});

describe("highestBucket", () => {
  it("returns the highest ascending bucket cleared", () => {
    expect(highestBucket(0, [10, 50, 100])).toBeNull();
    expect(highestBucket(10, [10, 50, 100])).toBe(10);
    expect(highestBucket(99, [10, 50, 100])).toBe(50);
    expect(highestBucket(1000, [10, 50, 100])).toBe(100);
  });
});

describe("buildGithubBadges", () => {
  it("always issues oauth-account, even with no extra facts", () => {
    const badges = buildGithubBadges({ id: 42, login: "octocat" }, NOW);
    expect(badges).toHaveLength(1);
    expect(badges[0]!.type).toBe("oauth-account");
    expect(badges[0]!.claims).toEqual({
      provider: "github",
      accountId: "42",
      handle: "octocat",
    });
    assertClaimsValid("oauth-account", badges[0]!.claims);
  });

  it("derives the highest account-age bucket from created_at (5y => 60mo)", () => {
    const badges = buildGithubBadges(
      { id: 1, login: "old", createdAt: "2019-01-01T00:00:00Z" },
      NOW,
    );
    const age = badges.find((b) => b.type === "account-age");
    expect(age).toBeDefined();
    expect(age!.claims).toEqual({ provider: "github", olderThanMonths: 60 });
    assertClaimsValid("account-age", age!.claims);
  });

  it("picks the coarse bucket, not the exact age (2.5y => 24mo, not 30)", () => {
    const badges = buildGithubBadges({ id: 1, login: "u", createdAt: "2024-01-01T00:00:00Z" }, NOW);
    const age = badges.find((b) => b.type === "account-age");
    expect(age!.claims).toEqual({ provider: "github", olderThanMonths: 24 });
  });

  it("omits account-age when younger than the smallest bucket (< 12mo)", () => {
    const badges = buildGithubBadges({ id: 1, login: "u", createdAt: "2026-01-01T00:00:00Z" }, NOW);
    expect(badges.some((b) => b.type === "account-age")).toBe(false);
  });

  it("ignores an unparseable created_at", () => {
    const badges = buildGithubBadges({ id: 1, login: "u", createdAt: "not-a-date" }, NOW);
    expect(badges.some((b) => b.type === "account-age")).toBe(false);
  });

  it("issues two-factor only when the flag is exactly true", () => {
    expect(
      buildGithubBadges({ id: 1, login: "u", twoFactor: true }, NOW).some(
        (b) => b.type === "two-factor",
      ),
    ).toBe(true);
    expect(
      buildGithubBadges({ id: 1, login: "u", twoFactor: false }, NOW).some(
        (b) => b.type === "two-factor",
      ),
    ).toBe(false);
    expect(buildGithubBadges({ id: 1, login: "u" }, NOW).some((b) => b.type === "two-factor")).toBe(
      false,
    );
  });

  it("two-factor claims validate against the strict schema", () => {
    const badges = buildGithubBadges({ id: 1, login: "u", twoFactor: true }, NOW);
    const tf = badges.find((b) => b.type === "two-factor")!;
    expect(tf.claims).toEqual({ provider: "github" });
    assertClaimsValid("two-factor", tf.claims);
  });

  it("buckets followers to the highest tier cleared (742 => 500)", () => {
    const badges = buildGithubBadges({ id: 1, login: "u", followers: 742 }, NOW);
    const sf = badges.find((b) => b.type === "social-following");
    expect(sf!.claims).toEqual({ provider: "github", followersAtLeast: 500 });
    assertClaimsValid("social-following", sf!.claims);
  });

  it("omits social-following below the smallest bucket (< 10)", () => {
    const badges = buildGithubBadges({ id: 1, login: "u", followers: 3 }, NOW);
    expect(badges.some((b) => b.type === "social-following")).toBe(false);
  });

  it("issues the full set when every fact supports it, all schema-valid", () => {
    const badges = buildGithubBadges(
      {
        id: 99,
        login: "power",
        createdAt: "2015-05-01T00:00:00Z",
        twoFactor: true,
        followers: 1500,
      },
      NOW,
    );
    const types = badges.map((b) => b.type).sort();
    expect(types).toEqual(["account-age", "oauth-account", "social-following", "two-factor"]);
    for (const b of badges) assertClaimsValid(b.type, b.claims);
  });
});
