import { describe, expect, it } from "vitest";

import { grantedRelevantTypes, unionTypes, type GrantState } from "./oidc-grants";

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
});

describe("grantedRelevantTypes", () => {
  const grant: GrantState = {
    badgeTypes: ["age-over-18", "residency-country", "email-domain"],
    profileName: false,
    profileAvatar: false,
  };

  it("intersects the granted set with the room's requested types", () => {
    // Room requests age-over-18 + something not granted.
    const requested = new Set(["age-over-18", "github-contributor"]);
    expect(grantedRelevantTypes(grant, requested)).toEqual(["age-over-18"]);
  });

  it("a previously-granted type the room does NOT request is excluded (F-2 per-room minimal)", () => {
    // residency-country + email-domain are granted but this room does not
    // request them → they must NOT appear (and so are not disclosed here).
    const requested = new Set(["age-over-18"]);
    const relevant = grantedRelevantTypes(grant, requested);
    expect(relevant).not.toContain("residency-country");
    expect(relevant).not.toContain("email-domain");
    expect(relevant).toEqual(["age-over-18"]);
  });

  it("accepts an array of requested types as well as a Set", () => {
    expect(grantedRelevantTypes(grant, ["email-domain"])).toEqual(["email-domain"]);
  });

  it("empty grant → empty relevant set", () => {
    const empty: GrantState = { badgeTypes: [], profileName: false, profileAvatar: false };
    expect(grantedRelevantTypes(empty, new Set(["age-over-18"]))).toEqual([]);
  });

  it("no overlap → empty", () => {
    expect(grantedRelevantTypes(grant, new Set(["github-contributor"]))).toEqual([]);
  });
});
