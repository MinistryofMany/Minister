import { describe, expect, it } from "vitest";

import { resolveUserClaims, type ClaimsUser } from "@/lib/oidc-claims";

const curatedUser: ClaimsUser = {
  displayName: "Curated Name",
  avatarUrl: "https://cdn/avatar.png",
};

const GRANT_NONE = { name: false, avatar: false };
const GRANT_NAME = { name: true, avatar: false };
const GRANT_AVATAR = { name: false, avatar: true };
const GRANT_BOTH = { name: true, avatar: true };

describe("resolveUserClaims", () => {
  it("omits name/picture when neither profile claim is granted (default OFF)", () => {
    const resolved = resolveUserClaims(curatedUser, GRANT_NONE, [], null, false, null);
    expect(resolved).not.toHaveProperty("name");
    expect(resolved).not.toHaveProperty("picture");
    expect(resolved.ministerBadges).toEqual([]);
  });

  it("emits name but NOT picture when only the name claim is granted", () => {
    const resolved = resolveUserClaims(curatedUser, GRANT_NAME, [], null, false, null);
    expect(resolved.name).toBe("Curated Name");
    expect(resolved).not.toHaveProperty("picture");
  });

  it("emits picture but NOT name when only the avatar claim is granted", () => {
    const resolved = resolveUserClaims(curatedUser, GRANT_AVATAR, [], null, false, null);
    expect(resolved.picture).toBe("https://cdn/avatar.png");
    expect(resolved).not.toHaveProperty("name");
  });

  it("emits both name and picture when both claims are granted", () => {
    const resolved = resolveUserClaims(curatedUser, GRANT_BOTH, [], null, false, null);
    expect(resolved.name).toBe("Curated Name");
    expect(resolved.picture).toBe("https://cdn/avatar.png");
  });

  it("discloses ONLY curated values — there is no upstream identity to leak", () => {
    // `ClaimsUser` has no `name`/`image` field by construction, so the
    // upstream auth identity cannot reach the resolver at all. The disclosed
    // values are exactly the curated ones.
    const resolved = resolveUserClaims(curatedUser, GRANT_BOTH, [], null, false, null);
    expect(resolved.name).toBe("Curated Name");
    expect(resolved.picture).toBe("https://cdn/avatar.png");
  });

  it("omits a granted claim that has no curated value (no fallback, no misleading value)", () => {
    const user: ClaimsUser = { displayName: null, avatarUrl: null };
    const resolved = resolveUserClaims(user, GRANT_BOTH, [], null, false, null);
    // Granted, but nothing curated to share: omit the claim entirely rather
    // than emit null or an upstream value.
    expect(resolved).not.toHaveProperty("name");
    expect(resolved).not.toHaveProperty("picture");
  });

  it("omits name when granted-but-null while still emitting a granted, present picture", () => {
    const user: ClaimsUser = { displayName: null, avatarUrl: "https://cdn/avatar.png" };
    const resolved = resolveUserClaims(user, GRANT_BOTH, [], null, false, null);
    expect(resolved).not.toHaveProperty("name");
    expect(resolved.picture).toBe("https://cdn/avatar.png");
  });

  it("passes through the approved badge JWTs verbatim", () => {
    const resolved = resolveUserClaims(
      curatedUser,
      GRANT_BOTH,
      ["jwt-a", "jwt-b"],
      null,
      false,
      null,
    );
    expect(resolved.ministerBadges).toEqual(["jwt-a", "jwt-b"]);
  });

  // --- Per-RP persona override precedence ---------------------------------

  it("prefers the per-RP override name over the global curated name", () => {
    const override = { displayName: "Persona Name", avatarUrl: null };
    const resolved = resolveUserClaims(curatedUser, GRANT_NAME, [], override, false, null);
    expect(resolved.name).toBe("Persona Name");
  });

  it("prefers the per-RP override avatar over the global curated avatar", () => {
    const override = { displayName: null, avatarUrl: "https://cdn/persona.png" };
    const resolved = resolveUserClaims(curatedUser, GRANT_AVATAR, [], override, false, null);
    expect(resolved.picture).toBe("https://cdn/persona.png");
  });

  it("prefers the per-RP override for both fields when both are set", () => {
    const override = { displayName: "Persona Name", avatarUrl: "https://cdn/persona.png" };
    const resolved = resolveUserClaims(curatedUser, GRANT_BOTH, [], override, false, null);
    expect(resolved.name).toBe("Persona Name");
    expect(resolved.picture).toBe("https://cdn/persona.png");
  });

  it("OMITS name when the override row's name field is null, even though the global name is set", () => {
    // Override row PRESENT (the user set a persona avatar) but its name field
    // is null: a null field on a present row means "share nothing for this
    // field with this app" — it must NOT upgrade to the global real name.
    const override = { displayName: null, avatarUrl: "https://cdn/persona.png" };
    const resolved = resolveUserClaims(curatedUser, GRANT_BOTH, [], override, false, null);
    expect(resolved).not.toHaveProperty("name");
    expect(resolved.picture).toBe("https://cdn/persona.png");
  });

  it("OMITS avatar when the override row's avatar field is null, even though the global avatar is set", () => {
    const override = { displayName: "Persona Name", avatarUrl: null };
    const resolved = resolveUserClaims(curatedUser, GRANT_BOTH, [], override, false, null);
    expect(resolved.name).toBe("Persona Name");
    expect(resolved).not.toHaveProperty("picture");
  });

  it("falls back to the global values when there is NO override row (legacy grant, null)", () => {
    // Only a missing row falls back to the global curated value.
    const resolved = resolveUserClaims(curatedUser, GRANT_BOTH, [], null, false, null);
    expect(resolved.name).toBe("Curated Name");
    expect(resolved.picture).toBe("https://cdn/avatar.png");
  });

  it("omits both claims when the override row is present but both fields are null", () => {
    // Present row, both null: share nothing — independent of the global value.
    const override = { displayName: null, avatarUrl: null };
    const resolved = resolveUserClaims(curatedUser, GRANT_BOTH, [], override, false, null);
    expect(resolved).not.toHaveProperty("name");
    expect(resolved).not.toHaveProperty("picture");
  });

  it("still omits an ungranted claim even when the override has a value for it", () => {
    // The grant gate is checked first: a per-RP override value for a field the
    // user did NOT consent to this round must never be disclosed.
    const override = { displayName: "Persona Name", avatarUrl: "https://cdn/persona.png" };
    const resolved = resolveUserClaims(curatedUser, GRANT_NONE, [], override, false, null);
    expect(resolved).not.toHaveProperty("name");
    expect(resolved).not.toHaveProperty("picture");
  });

  // --- Sybil-score bucket disclosure (snapshot gate) ----------------------
  // The bucket is snapshotted at consent (grant boolean + stamped bucket) and
  // passed in; the resolver only gates emission. Never recomputed here.

  it("emits sybil_bucket when the grant is true AND the bucket is non-null", () => {
    const resolved = resolveUserClaims(curatedUser, GRANT_NONE, [], null, true, 3);
    expect(resolved.sybilBucket).toBe(3);
  });

  it("omits sybil_bucket when the grant is false (even if a bucket is present)", () => {
    const resolved = resolveUserClaims(curatedUser, GRANT_NONE, [], null, false, 3);
    expect(resolved).not.toHaveProperty("sybilBucket");
  });

  it("omits sybil_bucket when the bucket is null (compute failed / omitted at consent)", () => {
    const resolved = resolveUserClaims(curatedUser, GRANT_NONE, [], null, true, null);
    expect(resolved).not.toHaveProperty("sybilBucket");
  });

  it("emits sybil_bucket = 0 when granted (0 is a real value, must NOT be dropped)", () => {
    // Bucket 0 ("no anti-sybil strength") is a genuine disclosed value. The
    // gate is `!== null`, never falsy, so 0 survives.
    const resolved = resolveUserClaims(curatedUser, GRANT_NONE, [], null, true, 0);
    expect(resolved).toHaveProperty("sybilBucket", 0);
  });

  it("sybil_bucket disclosure is independent of the profile gate", () => {
    // Granting the bucket must not require or affect name/picture, and vice
    // versa: the two disclosures are orthogonal.
    const resolved = resolveUserClaims(curatedUser, GRANT_NONE, [], null, true, 2);
    expect(resolved.sybilBucket).toBe(2);
    expect(resolved).not.toHaveProperty("name");
    expect(resolved).not.toHaveProperty("picture");
  });
});
