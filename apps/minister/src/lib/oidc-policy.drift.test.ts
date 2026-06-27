import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { evaluate, parsePolicy, type PolicyNode, type UserBadge } from "./oidc-policy";

// Drift-check for the deliberate policy-model copy in oidc-policy.ts.
// Minister mirrors Discreetly's @discreetly/policy types + schema +
// evaluate semantics (Phase-2 design F-7) rather than sharing a package,
// to avoid coupling the two repos' build graphs. This test is the guard
// that the copy stays faithful, mirroring the minister-client badge
// registry's "deliberate copy + drift-check" pattern.
//
// Two layers:
//  1. A behavioral corpus asserted against the Minister mirror — the
//     observable contract (which shapes parse, how they evaluate). This
//     runs everywhere, with or without the Discreetly sibling checkout.
//  2. When the Discreetly source is present as a sibling repo, its
//     schema/types/evaluate source files are content-pinned. A change to
//     any of them flips this assertion, forcing a human to re-review the
//     mirror and re-pin. CI without the sibling skips layer 2 (the
//     behavioral corpus still protects the contract).

// Pinned SHA-256 of the upstream Discreetly policy source files this
// mirror was last reconciled against. Update deliberately, alongside a
// re-review of oidc-policy.ts, when the upstream files legitimately
// change.
const PINNED_DISCREETLY_SOURCE_SHA: Record<string, string> = {
  "types.ts": "96c776e5b00dad5cec1ada402c94a8b318040fc3e2395ff8d9d868cb2e7e614d",
  "schema.ts": "8907ec89a38dddc75cfbc1bfc2594227d9038b57d6d2769664d45c9ff4265a6f",
  "evaluate.ts": "d2fadecbd5de094fb470dc051a9c0942a88e952447a2dacb35a4bdaa7ea8e920",
};

// Discreetly lives as a sibling repo of Minister in the workspace folder:
//   MinistryOfMany/{Minister,Discreetly}
// This test file is at Minister/apps/minister/src/lib, so the sibling
// policy source is five levels up then into Discreetly.
const DISCREETLY_POLICY_SRC = path.resolve(
  __dirname,
  "../../../../../Discreetly/packages/policy/src",
);

function readDiscreetlySource(file: string): string | null {
  try {
    return readFileSync(path.join(DISCREETLY_POLICY_SRC, file), "utf8");
  } catch {
    return null;
  }
}

const NOW = 1_750_000_000;
const DAY = 86_400;

interface EvalCase {
  policy: PolicyNode;
  badges: UserBadge[];
  expected: boolean;
}

function b(
  id: string,
  type: string,
  attributes: UserBadge["attributes"] = {},
  ageDays = 0,
): UserBadge {
  return { id, type, attributes, issuedAt: NOW - ageDays * DAY };
}

// Shared behavioral corpus. These are the cases the mirror MUST agree
// with Discreetly's evaluate on; they encode the contract.
const EVAL_CORPUS: EvalCase[] = [
  { policy: { badge: { type: "a" } }, badges: [b("1", "a")], expected: true },
  { policy: { badge: { type: "a" } }, badges: [b("1", "x")], expected: false },
  {
    policy: { badge: { type: "a", where: { k: "v" } } },
    badges: [b("1", "a", { k: "v" })],
    expected: true,
  },
  {
    policy: { badge: { type: "a", where: { k: "v" } } },
    badges: [b("1", "a", { k: "w" })],
    expected: false,
  },
  {
    policy: { badge: { type: "a", maxAgeDays: 30 } },
    badges: [b("1", "a", {}, 30)],
    expected: true,
  },
  {
    policy: { badge: { type: "a", maxAgeDays: 30 } },
    badges: [b("1", "a", {}, 31)],
    expected: false,
  },
  {
    policy: { allOf: [{ badge: { type: "a" } }, { badge: { type: "b" } }] },
    badges: [b("1", "a")],
    expected: false,
  },
  {
    policy: { anyOf: [{ badge: { type: "a" } }, { badge: { type: "b" } }] },
    badges: [b("1", "b")],
    expected: true,
  },
  {
    policy: {
      atLeast: {
        n: 2,
        of: [{ badge: { type: "a" } }, { badge: { type: "b" } }, { badge: { type: "c" } }],
      },
    },
    badges: [b("1", "a"), b("2", "c")],
    expected: true,
  },
  { policy: { allOf: [] }, badges: [], expected: true },
  { policy: { anyOf: [] }, badges: [], expected: false },
  { policy: { atLeast: { n: 0, of: [] } }, badges: [], expected: true },
];

describe("oidc-policy drift: behavioral contract", () => {
  it("evaluate agrees with the pinned corpus", () => {
    for (const c of EVAL_CORPUS) {
      expect(evaluate(c.policy, c.badges, NOW)).toBe(c.expected);
    }
  });

  it("strict schema accepts valid and rejects unknown-key shapes", () => {
    expect(() => parsePolicy({ anyOf: [{ badge: { type: "a" } }] })).not.toThrow();
    expect(() => parsePolicy({ badge: { type: "a" }, extra: 1 })).toThrow();
  });
});

describe("oidc-policy drift: upstream source pin", () => {
  const present = readDiscreetlySource("schema.ts") !== null;

  // Only runs when the Discreetly sibling repo is checked out. In a
  // Minister-only CI checkout the behavioral corpus above is the guard.
  it.runIf(present)("Discreetly policy source matches the pinned reconciliation point", () => {
    for (const [file, sha] of Object.entries(PINNED_DISCREETLY_SOURCE_SHA)) {
      const src = readDiscreetlySource(file);
      expect(src, `Discreetly ${file} should be readable`).not.toBeNull();
      const actual = createHash("sha256").update(src!).digest("hex");
      expect(
        actual,
        `Discreetly policy ${file} changed upstream — re-review oidc-policy.ts against it ` +
          `and update PINNED_DISCREETLY_SOURCE_SHA.`,
      ).toBe(sha);
    }
  });
});
