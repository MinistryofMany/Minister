import { describe, expect, it } from "vitest";

import { buildAlreadyGrantedView, buildPolicyConsentView } from "./oidc-policy-view";
import type { DisplayBadge } from "./badges";
import type { PolicyNode, UserBadge } from "./oidc-policy";

const NOW = 1_750_000_000;

// Minimal DisplayBadge factory — only the fields the view-builder reads.
function db(id: string, type: string, attributes: Record<string, unknown> = {}): DisplayBadge {
  return {
    id,
    type,
    attributes,
    issuer: "did:web:minister.local",
    issuedAt: new Date(NOW * 1000),
    expiresAt: null,
    isPublic: false,
    sortOrder: 0,
    importedFrom: null,
    pluginId: null,
    meta: { type, label: type, description: `desc ${type}`, iconKey: "mail" },
  } as DisplayBadge;
}

function ub(id: string, type: string, attributes: UserBadge["attributes"] = {}): UserBadge {
  return { id, type, attributes, issuedAt: NOW };
}

const COUNTS = new Map<string, number>([
  ["age-over-18", 5000], // large bucket
  ["residency-country", 200], // medium bucket
  ["a", 10000],
  ["b", 8000],
  ["c", 50], // small bucket
]);

describe("buildPolicyConsentView", () => {
  it("anyOf → one-of group, pre-selects the most-anonymous branch, coarse hints", () => {
    const policy: PolicyNode = {
      anyOf: [{ badge: { type: "age-over-18" } }, { badge: { type: "residency-country" } }],
    };
    const badges = [db("a18", "age-over-18"), db("rc", "residency-country")];
    const userBadges = [ub("a18", "age-over-18"), ub("rc", "residency-country")];

    const view = buildPolicyConsentView(policy, badges, userBadges, COUNTS, NOW);
    expect(view.group.kind).toBe("one-of");
    expect(view.group.required).toBe(1);
    expect(view.satisfiable).toBe(true);
    // age-over-18 (5000) is the most anonymous → pre-selected.
    expect(view.preselectedBadgeIds).toEqual(["a18"]);
    // Each leaf carries a coarse bucket (never an integer).
    const a18Leaf = view.group.leaves.find((l) => l.type === "age-over-18");
    const rcLeaf = view.group.leaves.find((l) => l.type === "residency-country");
    expect(a18Leaf?.anonymityBucket).toBe("large");
    expect(rcLeaf?.anonymityBucket).toBe("medium");
    // The integer count never appears on the view.
    expect(JSON.stringify(view)).not.toContain("5000");
    expect(JSON.stringify(view)).not.toContain("200");
  });

  it("atLeast → n-of group with required = n, pre-selects the n most anonymous", () => {
    const policy: PolicyNode = {
      atLeast: {
        n: 2,
        of: [{ badge: { type: "a" } }, { badge: { type: "b" } }, { badge: { type: "c" } }],
      },
    };
    const badges = [db("ba", "a"), db("bb", "b"), db("bc", "c")];
    const userBadges = [ub("ba", "a"), ub("bb", "b"), ub("bc", "c")];

    const view = buildPolicyConsentView(policy, badges, userBadges, COUNTS, NOW);
    expect(view.group.kind).toBe("n-of");
    expect(view.group.required).toBe(2);
    expect([...view.preselectedBadgeIds].sort()).toEqual(["ba", "bb"]);
  });

  it("user holds none → unsatisfiable, no preselect, gaps populated", () => {
    const policy: PolicyNode = {
      anyOf: [{ badge: { type: "age-over-18" } }, { badge: { type: "residency-country" } }],
    };
    const view = buildPolicyConsentView(
      policy,
      [db("x", "email-domain")],
      [ub("x", "email-domain")],
      COUNTS,
      NOW,
    );
    expect(view.satisfiable).toBe(false);
    expect(view.preselectedBadgeIds).toEqual([]);
    expect(view.gaps.sort()).toEqual(["age-over-18", "residency-country"]);
    // Both leaves flagged unmet.
    expect(view.group.leaves.every((l) => l.unmet)).toBe(true);
  });

  it("single leaf → single group", () => {
    const policy: PolicyNode = { badge: { type: "a" } };
    const view = buildPolicyConsentView(policy, [db("ba", "a")], [ub("ba", "a")], COUNTS, NOW);
    expect(view.group.kind).toBe("single");
    expect(view.preselectedBadgeIds).toEqual(["ba"]);
  });

  it("leaf options list only the user's matching holdings", () => {
    const policy: PolicyNode = { badge: { type: "a" } };
    const badges = [db("ba1", "a"), db("ba2", "a"), db("other", "b")];
    const userBadges = [ub("ba1", "a"), ub("ba2", "a"), ub("other", "b")];
    const view = buildPolicyConsentView(policy, badges, userBadges, COUNTS, NOW);
    const leaf = view.group.leaves[0]!;
    expect(leaf.options.map((o) => o.id).sort()).toEqual(["ba1", "ba2"]);
  });

  it("excludeTypes drops the already-granted leaf from the pickable group", () => {
    // anyOf{age-over-18, residency-country}; age-over-18 already granted →
    // group 3 (pickable) shows only residency-country; the granted leaf's
    // preselected id is removed (it is shown locked in group 2 instead).
    const policy: PolicyNode = {
      anyOf: [{ badge: { type: "age-over-18" } }, { badge: { type: "residency-country" } }],
    };
    const badges = [db("a18", "age-over-18"), db("rc", "residency-country")];
    const userBadges = [ub("a18", "age-over-18"), ub("rc", "residency-country")];
    const view = buildPolicyConsentView(
      policy,
      badges,
      userBadges,
      COUNTS,
      NOW,
      new Set(["age-over-18"]),
    );
    expect(view.group.leaves.map((l) => l.type)).toEqual(["residency-country"]);
    // The locked badge id must not be pre-selected in the pickable group.
    expect(view.preselectedBadgeIds).not.toContain("a18");
  });
});

// buildAlreadyGrantedView now takes the SPECIFIC previously-disclosed badge
// INSTANCE ids (audit W1), not types — so it shows only the instances the
// user actually proved, grouped by type, never every held instance of a
// granted type.
describe("buildAlreadyGrantedView", () => {
  it("one row per granted type, listing only the disclosed instances", () => {
    const badges = [db("a18", "age-over-18"), db("rc", "residency-country")];
    const view = buildAlreadyGrantedView(["a18"], badges);
    expect(view).toHaveLength(1);
    expect(view[0]!.type).toBe("age-over-18");
    expect(view[0]!.badges.map((b) => b.id)).toEqual(["a18"]);
  });

  it("W1: a sibling instance of a granted type that was never disclosed is NOT shown", () => {
    // Two oauth-account badges held; only github was disclosed. The locked
    // section must show github alone — google stays pickable elsewhere.
    const badges = [db("github", "oauth-account"), db("google", "oauth-account")];
    const view = buildAlreadyGrantedView(["github"], badges);
    expect(view).toHaveLength(1);
    expect(view[0]!.type).toBe("oauth-account");
    expect(view[0]!.badges.map((b) => b.id)).toEqual(["github"]);
  });

  it("groups multiple disclosed instances of the same type into one row", () => {
    const badges = [db("github", "oauth-account"), db("google", "oauth-account")];
    const view = buildAlreadyGrantedView(["github", "google"], badges);
    expect(view).toHaveLength(1);
    expect(view[0]!.badges.map((b) => b.id).sort()).toEqual(["github", "google"]);
  });

  it("skips a granted id the user no longer holds (nothing to lock)", () => {
    const badges = [db("rc", "residency-country")];
    // The disclosed instance was deleted → not in `badges` → omitted.
    expect(buildAlreadyGrantedView(["a18"], badges)).toEqual([]);
  });

  it("empty granted set → empty section", () => {
    expect(buildAlreadyGrantedView([], [db("a18", "age-over-18")])).toEqual([]);
  });
});
