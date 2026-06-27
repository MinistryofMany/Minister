import { describe, expect, it } from "vitest";

import {
  evaluate,
  parsePolicy,
  policyBadgeTypes,
  policyDepth,
  selectMinimalAnonymitySet,
  type PolicyNode,
  type UserBadge,
} from "./oidc-policy";

const NOW = 1_750_000_000; // fixed unix seconds for deterministic expiry tests
const DAY = 86_400;

function ub(
  id: string,
  type: string,
  attributes: UserBadge["attributes"] = {},
  ageDays = 0,
): UserBadge {
  return { id, type, attributes, issuedAt: NOW - ageDays * DAY };
}

// Holder-count fixture: larger = more anonymous.
const COUNTS = new Map<string, number>([
  ["age-over-18", 5000],
  ["residency-country", 200],
  ["oauth-account", 10000],
  ["email-domain", 8000],
  ["a", 10000],
  ["b", 8000],
  ["c", 50],
]);

// ---------------------------------------------------------------------------
// Schema (mirror of Discreetly schema.ts cases + strictness)
// ---------------------------------------------------------------------------

describe("parsePolicy (strict mirror)", () => {
  it("accepts a valid nested policy", () => {
    const policy = {
      allOf: [
        { anyOf: [{ badge: { type: "a" } }, { badge: { type: "b" } }] },
        { badge: { type: "c", where: { x: 1 }, maxAgeDays: 30 } },
      ],
    };
    expect(() => parsePolicy(policy)).not.toThrow();
  });

  it("rejects unknown keys (strict)", () => {
    expect(() => parsePolicy({ badge: { type: "a" }, extra: 1 })).toThrow();
    expect(() => parsePolicy({ badge: { type: "a", bogus: true } })).toThrow();
    expect(() => parsePolicy({ anyOf: [], surprise: 1 })).toThrow();
  });

  it("rejects malformed leaves", () => {
    expect(() => parsePolicy({ badge: { type: "" } })).toThrow();
    expect(() => parsePolicy({ badge: { type: "a", maxAgeDays: -1 } })).toThrow();
    expect(() => parsePolicy({ atLeast: { n: -1, of: [] } })).toThrow();
  });

  it("accepts degenerate empty nodes", () => {
    expect(() => parsePolicy({ allOf: [] })).not.toThrow();
    expect(() => parsePolicy({ anyOf: [] })).not.toThrow();
    expect(() => parsePolicy({ atLeast: { n: 0, of: [] } })).not.toThrow();
  });
});

describe("policyDepth / policyBadgeTypes", () => {
  it("computes structural depth", () => {
    expect(policyDepth({ badge: { type: "a" } })).toBe(1);
    expect(policyDepth({ allOf: [{ badge: { type: "a" } }] })).toBe(2);
    expect(policyDepth({ allOf: [{ anyOf: [{ badge: { type: "a" } }] }] })).toBe(3);
  });

  it("collects every mentioned badge type", () => {
    const policy: PolicyNode = {
      allOf: [
        { anyOf: [{ badge: { type: "a" } }, { badge: { type: "b" } }] },
        { atLeast: { n: 1, of: [{ badge: { type: "c" } }] } },
      ],
    };
    expect([...policyBadgeTypes(policy)].sort()).toEqual(["a", "b", "c"]);
  });
});

// ---------------------------------------------------------------------------
// Evaluate (ported from Discreetly evaluate.test.ts)
// ---------------------------------------------------------------------------

describe("evaluate (ported)", () => {
  it("matches a single badge leaf by type", () => {
    const policy: PolicyNode = { badge: { type: "email-domain" } };
    expect(evaluate(policy, [ub("1", "email-domain")], NOW)).toBe(true);
    expect(evaluate(policy, [ub("1", "oauth-account")], NOW)).toBe(false);
  });

  it("enforces attribute constraints", () => {
    const policy: PolicyNode = { badge: { type: "email-domain", where: { domain: "acme.com" } } };
    expect(evaluate(policy, [ub("1", "email-domain", { domain: "acme.com" })], NOW)).toBe(true);
    expect(evaluate(policy, [ub("1", "email-domain", { domain: "evil.com" })], NOW)).toBe(false);
  });

  it("enforces maxAgeDays expiry (inclusive boundary)", () => {
    const policy: PolicyNode = { badge: { type: "age-check", maxAgeDays: 30 } };
    expect(evaluate(policy, [ub("1", "age-check", {}, 10)], NOW)).toBe(true);
    expect(evaluate(policy, [ub("1", "age-check", {}, 30)], NOW)).toBe(true);
    expect(evaluate(policy, [ub("1", "age-check", {}, 31)], NOW)).toBe(false);
  });

  it("allOf requires every child; anyOf one; atLeast n", () => {
    expect(
      evaluate(
        { allOf: [{ badge: { type: "a" } }, { badge: { type: "b" } }] },
        [ub("1", "a")],
        NOW,
      ),
    ).toBe(false);
    expect(
      evaluate(
        { anyOf: [{ badge: { type: "a" } }, { badge: { type: "b" } }] },
        [ub("1", "b")],
        NOW,
      ),
    ).toBe(true);
    const atLeast: PolicyNode = {
      atLeast: {
        n: 2,
        of: [{ badge: { type: "a" } }, { badge: { type: "b" } }, { badge: { type: "c" } }],
      },
    };
    expect(evaluate(atLeast, [ub("1", "a"), ub("2", "b")], NOW)).toBe(true);
    expect(evaluate(atLeast, [ub("1", "a")], NOW)).toBe(false);
  });

  it("uses strict equality and fails closed on garbage", () => {
    expect(
      evaluate(
        { badge: { type: "g", where: { completed: true } } },
        [ub("1", "g", { completed: "true" })],
        NOW,
      ),
    ).toBe(false);
    // @ts-expect-error malformed
    expect(() => evaluate({}, [], NOW)).toThrow();
    // @ts-expect-error malformed
    expect(() => evaluate({ foo: 1 }, [], NOW)).toThrow();
  });

  it("documents degenerate-node behavior", () => {
    expect(evaluate({ allOf: [] }, [], NOW)).toBe(true);
    expect(evaluate({ anyOf: [] }, [], NOW)).toBe(false);
    expect(evaluate({ atLeast: { n: 0, of: [] } }, [], NOW)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// selectMinimalAnonymitySet
// ---------------------------------------------------------------------------

describe("selectMinimalAnonymitySet", () => {
  it("anyOf[A(5000),B(200)] with user holding both ⇒ picks the most-anonymous A", () => {
    const policy: PolicyNode = {
      anyOf: [{ badge: { type: "age-over-18" } }, { badge: { type: "residency-country" } }],
    };
    const badges = [ub("a", "age-over-18"), ub("r", "residency-country")];
    const res = selectMinimalAnonymitySet(policy, badges, COUNTS, NOW);
    expect(res.satisfiable).toBe(true);
    expect(res.selectedBadgeIds).toEqual(["a"]);
    // The residency-country branch is offered as an override alternative.
    expect(res.alternatives).toContainEqual(["r"]);
    expect(res.gaps).toEqual([]);
    // The chosen set genuinely satisfies.
    expect(
      evaluate(
        policy,
        badges.filter((b) => res.selectedBadgeIds.includes(b.id)),
        NOW,
      ),
    ).toBe(true);
  });

  it("atLeast{2,[A(10000),B(8000),C(50)]} ⇒ picks the two largest {A,B}", () => {
    const policy: PolicyNode = {
      atLeast: {
        n: 2,
        of: [{ badge: { type: "a" } }, { badge: { type: "b" } }, { badge: { type: "c" } }],
      },
    };
    const badges = [ub("ba", "a"), ub("bb", "b"), ub("bc", "c")];
    const res = selectMinimalAnonymitySet(policy, badges, COUNTS, NOW);
    expect(res.satisfiable).toBe(true);
    expect([...res.selectedBadgeIds].sort()).toEqual(["ba", "bb"]);
    // Swapping the weakest (B) for C is offered as an alternative.
    expect(
      res.alternatives.some((alt) => [...alt].sort().join() === ["ba", "bc"].sort().join()),
    ).toBe(true);
  });

  it("nested allOf[anyOf[A,B], C] ⇒ best inner branch ∪ C", () => {
    const policy: PolicyNode = {
      allOf: [
        { anyOf: [{ badge: { type: "a" } }, { badge: { type: "b" } }] },
        { badge: { type: "c" } },
      ],
    };
    const badges = [ub("ba", "a"), ub("bb", "b"), ub("bc", "c")];
    const res = selectMinimalAnonymitySet(policy, badges, COUNTS, NOW);
    expect(res.satisfiable).toBe(true);
    // a (10000) beats b (8000) for the inner anyOf; c is mandatory.
    expect([...res.selectedBadgeIds].sort()).toEqual(["ba", "bc"]);
    expect(
      evaluate(
        policy,
        badges.filter((b) => res.selectedBadgeIds.includes(b.id)),
        NOW,
      ),
    ).toBe(true);
  });

  it("user holds none ⇒ unsatisfiable, nothing selected, gaps reported", () => {
    const policy: PolicyNode = {
      anyOf: [{ badge: { type: "age-over-18" } }, { badge: { type: "residency-country" } }],
    };
    const res = selectMinimalAnonymitySet(policy, [ub("x", "email-domain")], COUNTS, NOW);
    expect(res.satisfiable).toBe(false);
    expect(res.selectedBadgeIds).toEqual([]);
    expect(res.alternatives).toEqual([]);
    expect(res.gaps.sort()).toEqual(["age-over-18", "residency-country"]);
  });

  it("user holds partial for atLeast ⇒ unsatisfiable, gaps for the missing branches", () => {
    const policy: PolicyNode = {
      atLeast: {
        n: 2,
        of: [{ badge: { type: "a" } }, { badge: { type: "b" } }, { badge: { type: "c" } }],
      },
    };
    const res = selectMinimalAnonymitySet(policy, [ub("ba", "a")], COUNTS, NOW);
    expect(res.satisfiable).toBe(false);
    expect(res.selectedBadgeIds).toEqual([]);
    // a is held; b and c are the unmet branches.
    expect(res.gaps.sort()).toEqual(["b", "c"]);
  });

  it("picks the single minimal set — never two satisfying anyOf branches at once", () => {
    const policy: PolicyNode = {
      anyOf: [{ badge: { type: "a" } }, { badge: { type: "b" } }],
    };
    const badges = [ub("ba", "a"), ub("bb", "b")];
    const res = selectMinimalAnonymitySet(policy, badges, COUNTS, NOW);
    // Exactly one branch is pre-selected, not both.
    expect(res.selectedBadgeIds.length).toBe(1);
  });

  it("respects maxAgeDays when forming selections", () => {
    const policy: PolicyNode = { badge: { type: "a", maxAgeDays: 5 } };
    // The fresh badge satisfies; the stale one does not.
    const res = selectMinimalAnonymitySet(
      policy,
      [ub("stale", "a", {}, 10), ub("fresh", "a", {}, 1)],
      COUNTS,
      NOW,
    );
    expect(res.satisfiable).toBe(true);
    expect(res.selectedBadgeIds).toEqual(["fresh"]);
  });
});
