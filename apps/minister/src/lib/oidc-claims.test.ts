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
    const resolved = resolveUserClaims(curatedUser, GRANT_NONE, []);
    expect(resolved).not.toHaveProperty("name");
    expect(resolved).not.toHaveProperty("picture");
    expect(resolved.ministerBadges).toEqual([]);
  });

  it("emits name but NOT picture when only the name claim is granted", () => {
    const resolved = resolveUserClaims(curatedUser, GRANT_NAME, []);
    expect(resolved.name).toBe("Curated Name");
    expect(resolved).not.toHaveProperty("picture");
  });

  it("emits picture but NOT name when only the avatar claim is granted", () => {
    const resolved = resolveUserClaims(curatedUser, GRANT_AVATAR, []);
    expect(resolved.picture).toBe("https://cdn/avatar.png");
    expect(resolved).not.toHaveProperty("name");
  });

  it("emits both name and picture when both claims are granted", () => {
    const resolved = resolveUserClaims(curatedUser, GRANT_BOTH, []);
    expect(resolved.name).toBe("Curated Name");
    expect(resolved.picture).toBe("https://cdn/avatar.png");
  });

  it("discloses ONLY curated values — there is no upstream identity to leak", () => {
    // `ClaimsUser` has no `name`/`image` field by construction, so the
    // upstream auth identity cannot reach the resolver at all. The disclosed
    // values are exactly the curated ones.
    const resolved = resolveUserClaims(curatedUser, GRANT_BOTH, []);
    expect(resolved.name).toBe("Curated Name");
    expect(resolved.picture).toBe("https://cdn/avatar.png");
  });

  it("omits a granted claim that has no curated value (no fallback, no misleading value)", () => {
    const user: ClaimsUser = { displayName: null, avatarUrl: null };
    const resolved = resolveUserClaims(user, GRANT_BOTH, []);
    // Granted, but nothing curated to share: omit the claim entirely rather
    // than emit null or an upstream value.
    expect(resolved).not.toHaveProperty("name");
    expect(resolved).not.toHaveProperty("picture");
  });

  it("omits name when granted-but-null while still emitting a granted, present picture", () => {
    const user: ClaimsUser = { displayName: null, avatarUrl: "https://cdn/avatar.png" };
    const resolved = resolveUserClaims(user, GRANT_BOTH, []);
    expect(resolved).not.toHaveProperty("name");
    expect(resolved.picture).toBe("https://cdn/avatar.png");
  });

  it("passes through the approved badge JWTs verbatim", () => {
    const resolved = resolveUserClaims(curatedUser, GRANT_BOTH, ["jwt-a", "jwt-b"]);
    expect(resolved.ministerBadges).toEqual(["jwt-a", "jwt-b"]);
  });
});
