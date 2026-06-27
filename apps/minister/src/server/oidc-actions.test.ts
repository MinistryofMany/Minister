import { describe, expect, it } from "vitest";

import { evaluate, type PolicyNode, type UserBadge } from "@/lib/oidc-policy";
import { minimizeToPolicy } from "@/server/oidc-consent-minimize";

// Unit coverage for the server-side over-disclosure guard (Phase-2 F-5 /
// §8.3): given the submitted (already owned ∩ requested) badges, a present
// policy must trim the disclosure down to ONE minimal satisfying set.
// approveConsent's surrounding DB/session/redirect machinery is exercised
// by the Playwright e2e (M6); this isolates the minimization itself.

const NOW = 1_750_000_000;
const DAY = 86_400;

function ub(
  id: string,
  type: string,
  attributes: UserBadge["attributes"] = {},
  ageDays = 0,
): UserBadge {
  return { id, type, attributes, issuedAt: NOW - ageDays * DAY };
}

const COUNTS = new Map<string, number>([
  ["age-over-18", 5000],
  ["residency-country", 200],
  ["a", 10000],
  ["b", 8000],
  ["c", 50],
]);

function ids(badges: UserBadge[]): string[] {
  return badges.map((b) => b.id).sort();
}

describe("minimizeToPolicy (over-disclosure guard)", () => {
  it("no policy → identity (flat flow unchanged)", () => {
    const submitted = [ub("1", "a"), ub("2", "b")];
    expect(minimizeToPolicy(null, submitted, COUNTS, NOW)).toEqual(submitted);
  });

  it("anyOf: a POST ticking BOTH satisfying branches discloses exactly one", () => {
    const policy: PolicyNode = {
      anyOf: [{ badge: { type: "age-over-18" } }, { badge: { type: "residency-country" } }],
    };
    // Adversarial submission: both branches ticked.
    const submitted = [ub("over18", "age-over-18"), ub("resid", "residency-country")];
    const kept = minimizeToPolicy(policy, submitted, COUNTS, NOW);
    expect(kept.length).toBe(1);
    // The most-anonymous branch (age-over-18, 5000 > 200) survives.
    expect(ids(kept)).toEqual(["over18"]);
    // And it genuinely satisfies the policy.
    expect(evaluate(policy, kept, NOW)).toBe(true);
  });

  it("atLeast n: submitting MORE than n is trimmed to exactly n (the n most anonymous)", () => {
    const policy: PolicyNode = {
      atLeast: {
        n: 2,
        of: [{ badge: { type: "a" } }, { badge: { type: "b" } }, { badge: { type: "c" } }],
      },
    };
    // All three submitted; only the two most anonymous (a, b) should remain.
    const submitted = [ub("ba", "a"), ub("bb", "b"), ub("bc", "c")];
    const kept = minimizeToPolicy(policy, submitted, COUNTS, NOW);
    expect(kept.length).toBe(2);
    expect(ids(kept)).toEqual(["ba", "bb"]);
    expect(evaluate(policy, kept, NOW)).toBe(true);
  });

  it("non-satisfying-but-owned submission discloses nothing (no over-disclosure)", () => {
    const policy: PolicyNode = {
      anyOf: [{ badge: { type: "age-over-18" } }, { badge: { type: "residency-country" } }],
    };
    // User ticked an owned-but-irrelevant badge; it satisfies no branch.
    const submitted = [ub("x", "a")];
    const kept = minimizeToPolicy(policy, submitted, COUNTS, NOW);
    expect(kept).toEqual([]);
  });

  it("never discloses a badge that was not submitted (subset of input)", () => {
    const policy: PolicyNode = { badge: { type: "a" } };
    const submitted = [ub("ba", "a")];
    const kept = minimizeToPolicy(policy, submitted, COUNTS, NOW);
    for (const b of kept) {
      expect(submitted.some((s) => s.id === b.id)).toBe(true);
    }
  });

  it("respects maxAgeDays during minimization (stale instance dropped)", () => {
    const policy: PolicyNode = { badge: { type: "a", maxAgeDays: 5 } };
    const submitted = [ub("stale", "a", {}, 10), ub("fresh", "a", {}, 1)];
    const kept = minimizeToPolicy(policy, submitted, COUNTS, NOW);
    expect(ids(kept)).toEqual(["fresh"]);
  });
});
