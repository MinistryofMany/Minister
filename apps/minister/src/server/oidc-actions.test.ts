import { describe, expect, it } from "vitest";

import { grantedRelevantBadgeIds, type GrantState } from "@/lib/oidc-grants";
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

// Phase-3 (F-2): approveConsent folds the already-granted, room-relevant
// badges into the candidate set BEFORE minimizeToPolicy. The guard must
// STILL trim the union to one minimal satisfying set — i.e. forcing the
// granted set in never widens disclosure past the room's minimal need.
// These tests model that fold-then-minimize at the guard level (the
// surrounding DB/session machinery is covered by the Playwright e2e).
describe("minimizeToPolicy with the already-granted set folded in (F-2)", () => {
  // Mirror oidc-actions.unionBadgesById: granted-relevant badges appended
  // after the submitted ones, deduped by id, order-stable.
  function fold(submitted: UserBadge[], granted: UserBadge[]): UserBadge[] {
    const seen = new Set(submitted.map((b) => b.id));
    return [...submitted, ...granted.filter((b) => !seen.has(b.id))];
  }

  it("a granted type the room's minimal set does NOT need is trimmed away", () => {
    // Room requires ONLY age-over-18 (single leaf). residency-country was
    // granted by a DIFFERENT room and is forced in — but the guard trims it.
    const policy: PolicyNode = { badge: { type: "age-over-18" } };
    const submitted: UserBadge[] = []; // user re-selected nothing
    const granted = [ub("over18", "age-over-18"), ub("resid", "residency-country")];
    const candidate = fold(submitted, granted);
    const kept = minimizeToPolicy(policy, candidate, COUNTS, NOW);
    // Only the room-needed type is disclosed; the granted-but-unneeded type
    // is NOT on the wire (per-room minimal disclosure).
    expect(ids(kept)).toEqual(["over18"]);
    expect(evaluate(policy, kept, NOW)).toBe(true);
  });

  it("a granted badge satisfying the requirement is disclosed even when not re-submitted", () => {
    // Room requires age-over-18; user re-selected nothing, but it is in the
    // grant → the fold supplies it and the guard keeps it (the locked
    // section's promise: included when this room needs it).
    const policy: PolicyNode = { badge: { type: "age-over-18" } };
    const submitted: UserBadge[] = [];
    const granted = [ub("over18", "age-over-18")];
    const candidate = fold(submitted, granted);
    const kept = minimizeToPolicy(policy, candidate, COUNTS, NOW);
    expect(ids(kept)).toEqual(["over18"]);
  });

  it("forcing the granted set in never exceeds one minimal satisfying set (anyOf)", () => {
    // Room: age-over-18 OR residency-country. Both are granted and both
    // forced in — the guard still discloses exactly ONE (the most anonymous).
    const policy: PolicyNode = {
      anyOf: [{ badge: { type: "age-over-18" } }, { badge: { type: "residency-country" } }],
    };
    const candidate = fold([], [ub("over18", "age-over-18"), ub("resid", "residency-country")]);
    const kept = minimizeToPolicy(policy, candidate, COUNTS, NOW);
    expect(kept.length).toBe(1);
    expect(ids(kept)).toEqual(["over18"]); // 5000 > 200, most anonymous
  });
});

// Audit W1: on the flat / no-policy path minimizeToPolicy is the identity, so
// the granted fold is the ONLY over-disclosure guard. The old fold loaded
// every instance of an already-granted TYPE; a user with two oauth-account
// badges who first disclosed only github silently leaked google on the next
// visit. The fix records disclosed INSTANCE ids and force-includes only those
// specific instances. These model that no-policy fold end-to-end (the
// DB/session machinery is covered by the Playwright e2e).
describe("flat / no-policy granted fold — W1 over-disclosure", () => {
  // Mirror oidc-actions.unionBadgesById: submitted first, granted appended,
  // deduped by id, order-stable.
  function fold(submitted: UserBadge[], granted: UserBadge[]): UserBadge[] {
    const seen = new Set(submitted.map((b) => b.id));
    return [...submitted, ...granted.filter((b) => !seen.has(b.id))];
  }

  const github = ub("github", "oauth-account", { provider: "github" });
  const google = ub("google", "oauth-account", { provider: "google" });
  const owned = [
    { id: github.id, type: github.type },
    { id: google.id, type: google.type },
  ];
  const requestedTypes = new Set(["oauth-account"]);

  it("a user who disclosed ONLY github does NOT re-ship google on the next authorize", () => {
    // The grant recorded the disclosed instance id (github), not just the type.
    const grant: GrantState = {
      badgeTypes: ["oauth-account"],
      badgeIds: ["github"],
      profileName: false,
      profileAvatar: false,
    };
    // The room re-requests oauth-account with NO policy; the user re-ticks
    // nothing (the locked box shows only github).
    const foldedIds = grantedRelevantBadgeIds(grant, requestedTypes, owned);
    expect(foldedIds).toEqual(["github"]); // NOT ["github","google"]

    const grantedBadges = [github, google].filter((b) => foldedIds.includes(b.id));
    const candidate = fold([], grantedBadges);
    const kept = minimizeToPolicy(null, candidate, new Map(), NOW); // no policy → identity
    expect(ids(kept)).toEqual(["github"]);
    expect(kept.some((b) => b.id === "google")).toBe(false);

    // Contrast: the OLD type-based fold force-loaded EVERY instance of the
    // granted type — this is exactly the leak the id-based fold closes.
    const oldTypeFold = [github, google].filter((b) => grant.badgeTypes.includes(b.type));
    expect(ids(oldTypeFold)).toEqual(["github", "google"]);
  });

  it("a badge the user actively re-ticks is still disclosed (not over-disclosure)", () => {
    const grant: GrantState = {
      badgeTypes: ["oauth-account"],
      badgeIds: ["github"],
      profileName: false,
      profileAvatar: false,
    };
    // User this time chooses to also disclose google (submitted explicitly).
    const foldedIds = grantedRelevantBadgeIds(grant, requestedTypes, owned);
    const grantedBadges = [github, google].filter((b) => foldedIds.includes(b.id));
    const candidate = fold([google], grantedBadges);
    const kept = minimizeToPolicy(null, candidate, new Map(), NOW);
    expect(ids(kept)).toEqual(["github", "google"]);
  });

  it("a tampered POST that unticks the locked github still force-includes github (only)", () => {
    const grant: GrantState = {
      badgeTypes: ["oauth-account"],
      badgeIds: ["github"],
      profileName: false,
      profileAvatar: false,
    };
    // Submitted is empty (the locked box was stripped client-side); the fold
    // re-adds github from the grant, but never google.
    const foldedIds = grantedRelevantBadgeIds(grant, requestedTypes, owned);
    const grantedBadges = [github, google].filter((b) => foldedIds.includes(b.id));
    const candidate = fold([], grantedBadges);
    const kept = minimizeToPolicy(null, candidate, new Map(), NOW);
    expect(ids(kept)).toEqual(["github"]);
  });
});
