import { describe, expect, it } from "vitest";

import { grantedRelevantBadgeIds, unionTypes, type GrantState } from "./oidc-grants";

// Unit coverage for the pure grant helpers driving the "already proven to
// this platform" transparency section. The DB round-trip (loadGrant /
// upsertGrant) is exercised by the e2e; this isolates the set logic.

describe("unionTypes", () => {
  it("merges and deduplicates, preserving first-seen order", () => {
    expect(unionTypes(["a", "b"], ["b", "c"])).toEqual(["a", "b", "c"]);
  });

  it("is monotone-accumulating (a superset of both inputs)", () => {
    const out = unionTypes(["x"], ["y", "z"]);
    for (const t of ["x", "y", "z"]) expect(out).toContain(t);
  });

  it("empty inputs → empty", () => {
    expect(unionTypes([], [])).toEqual([]);
  });

  it("is a generic string-set union (reused to accumulate disclosed badge ids)", () => {
    expect(unionTypes(["id-1"], ["id-1", "id-2"])).toEqual(["id-1", "id-2"]);
  });
});

// grantedRelevantBadgeIds is the id-based replacement for the old type-based
// fold (audit W1). It force-includes only the SPECIFIC badge instances the
// user previously disclosed to this client whose type the room still
// requests — never every instance of a granted TYPE.
describe("grantedRelevantBadgeIds", () => {
  const grant: GrantState = {
    badgeTypes: ["oauth-account", "residency-country", "email-domain"],
    badgeIds: ["github", "resid", "email"],
    profileName: false,
    profileAvatar: false,
    sybilScore: false,
  };
  const owned = [
    { id: "github", type: "oauth-account" },
    { id: "google", type: "oauth-account" }, // held but NEVER disclosed
    { id: "resid", type: "residency-country" },
    { id: "email", type: "email-domain" },
  ];

  it("W1: returns only the disclosed instance, not every instance of a granted TYPE", () => {
    // Room re-requests oauth-account. The user holds github + google, but only
    // github was ever disclosed → only github is forced in. google (never
    // ticked) must NOT be swept in by the shared type.
    const requested = new Set(["oauth-account"]);
    expect(grantedRelevantBadgeIds(grant, requested, owned)).toEqual(["github"]);
  });

  it("a previously-disclosed instance of a type the room does NOT request is excluded (F-2)", () => {
    // resid + email were disclosed to other rooms; this room only requests
    // oauth-account → they must not appear (per-room minimal disclosure).
    const requested = new Set(["oauth-account"]);
    const relevant = grantedRelevantBadgeIds(grant, requested, owned);
    expect(relevant).not.toContain("resid");
    expect(relevant).not.toContain("email");
    expect(relevant).toEqual(["github"]);
  });

  it("drops a granted id the user no longer owns (fail-safe)", () => {
    // The badge was deleted / re-issued under a new id → the stale granted id
    // is not in `owned` and is silently dropped.
    const requested = new Set(["oauth-account", "email-domain"]);
    const ownedMinusEmail = owned.filter((b) => b.id !== "email");
    expect(grantedRelevantBadgeIds(grant, requested, ownedMinusEmail)).toEqual(["github"]);
  });

  it("accepts an array of requested types as well as a Set", () => {
    expect(grantedRelevantBadgeIds(grant, ["email-domain"], owned)).toEqual(["email"]);
  });

  it("empty grant → empty set", () => {
    const empty: GrantState = {
      badgeTypes: [],
      badgeIds: [],
      profileName: false,
      profileAvatar: false,
      sybilScore: false,
    };
    expect(grantedRelevantBadgeIds(empty, new Set(["oauth-account"]), owned)).toEqual([]);
  });

  it("no overlap with requested types → empty", () => {
    expect(grantedRelevantBadgeIds(grant, new Set(["age-over-21"]), owned)).toEqual([]);
  });
});
