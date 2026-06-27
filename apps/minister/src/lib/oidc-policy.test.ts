import { describe, expect, it } from "vitest";

import {
  evaluate,
  MAX_ATLEAST_N,
  MAX_NODE_CHILDREN,
  MAX_POLICY_NODES,
  parsePolicy,
  policyBadgeTypes,
  policyBoundsViolation,
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

// ---------------------------------------------------------------------------
// Breadth DoS bounds (audit C-1)
// ---------------------------------------------------------------------------

describe("policyBoundsViolation (breadth DoS guard)", () => {
  it("accepts a realistic small policy", () => {
    const policy: PolicyNode = {
      allOf: [
        { anyOf: [{ badge: { type: "a" } }, { badge: { type: "b" } }] },
        { atLeast: { n: 2, of: [{ badge: { type: "a" } }, { badge: { type: "b" } }] } },
      ],
    };
    expect(policyBoundsViolation(policy)).toBeNull();
  });

  it("rejects the proven attack: atLeast n=156 over 160 duplicate leaves", () => {
    const leaves = Array.from({ length: 160 }, () => ({ badge: { type: "a" } }));
    const policy: PolicyNode = { atLeast: { n: 156, of: leaves } };
    // Trips on a breadth bound (n cap and/or child/node count) — not null.
    expect(policyBoundsViolation(policy)).not.toBeNull();
  });

  it("rejects atLeast.n over the cap even with tiny breadth", () => {
    const policy: PolicyNode = {
      atLeast: { n: MAX_ATLEAST_N + 1, of: [{ badge: { type: "a" } }] },
    };
    expect(policyBoundsViolation(policy)).toMatch(/atLeast\.n/);
  });

  it("rejects a node with too many children", () => {
    const of = Array.from({ length: MAX_NODE_CHILDREN + 1 }, () => ({ badge: { type: "a" } }));
    expect(policyBoundsViolation({ anyOf: of })).toMatch(/children/);
  });

  it("rejects too many total nodes (breadth, depth stays shallow)", () => {
    // A wide-but-shallow tree: nested anyOf each within the per-node child
    // cap, but the TOTAL node count exceeds MAX_POLICY_NODES. Depth alone
    // would not catch this — the total-node cap must.
    const childPerNode = MAX_NODE_CHILDREN;
    let node: PolicyNode = { badge: { type: "a" } };
    // Build a tree that surely exceeds MAX_POLICY_NODES nodes total while
    // keeping each node within the child cap.
    const leaves = Array.from({ length: childPerNode }, () => ({ badge: { type: "a" } }));
    const level1: PolicyNode[] = Array.from(
      { length: Math.ceil(MAX_POLICY_NODES / childPerNode) + 1 },
      () => ({ anyOf: leaves }) as PolicyNode,
    );
    node = { allOf: level1.slice(0, MAX_NODE_CHILDREN) };
    expect(policyBoundsViolation(node)).toMatch(/too many nodes/);
  });
});

describe("selectMinimalAnonymitySet — bounded atLeast stays fast + correct", () => {
  it("a bounded-but-nontrivial atLeast picks a correct minimal set within a time bound", () => {
    // At the breadth ceiling: n = MAX_ATLEAST_N, of = MAX_NODE_CHILDREN
    // distinct in-scope leaves, user holds all of them. This is the largest
    // legitimate atLeast and must resolve quickly (the combinatorial
    // alternative path is short-circuited by MAX_ATLEAST_COMBINATIONS).
    const n = MAX_ATLEAST_N;
    const breadth = MAX_NODE_CHILDREN;
    const types = Array.from({ length: breadth }, (_, i) => `t${i}`);
    // Distinct, descending holder counts so the minimal set is well-defined.
    const counts = new Map<string, number>(types.map((t, i) => [t, 100000 - i * 100]));
    const policy: PolicyNode = {
      atLeast: { n, of: types.map((t) => ({ badge: { type: t } })) },
    };
    const badges = types.map((t, i) => ub(`b${i}`, t));

    const start = performance.now();
    const res = selectMinimalAnonymitySet(policy, badges, counts, NOW);
    const elapsedMs = performance.now() - start;

    // Bounded: well under a generous wall-clock ceiling (the unbounded bug
    // froze for seconds on far smaller n; this must be near-instant).
    expect(elapsedMs).toBeLessThan(250);
    expect(res.satisfiable).toBe(true);
    // The chosen minimal set is the n MOST-ANONYMOUS branches: the n
    // highest holder counts ⇒ types t0..t(n-1) ⇒ badges b0..b(n-1).
    const expected = Array.from({ length: n }, (_, i) => `b${i}`).sort();
    expect([...res.selectedBadgeIds].sort()).toEqual(expected);
    // And it genuinely satisfies the policy.
    expect(
      evaluate(
        policy,
        badges.filter((b) => res.selectedBadgeIds.includes(b.id)),
        NOW,
      ),
    ).toBe(true);
  });
});
