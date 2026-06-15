import { describe, expect, it } from "vitest";

import { resolveUserClaims, type ClaimsUser } from "@/lib/oidc-claims";

const fullUser: ClaimsUser = {
  displayName: "Curated Name",
  name: "Upstream Name",
  avatarUrl: "https://cdn/avatar.png",
  image: "https://cdn/image.png",
};

describe("resolveUserClaims", () => {
  it("omits name/picture when profile scope is absent", () => {
    const resolved = resolveUserClaims(fullUser, ["openid"], []);
    expect(resolved).not.toHaveProperty("name");
    expect(resolved).not.toHaveProperty("picture");
    expect(resolved.ministerBadges).toEqual([]);
  });

  it("prefers curated displayName/avatarUrl over upstream name/image", () => {
    const resolved = resolveUserClaims(fullUser, ["openid", "profile"], []);
    expect(resolved.name).toBe("Curated Name");
    expect(resolved.picture).toBe("https://cdn/avatar.png");
  });

  it("falls back to upstream name/image when curated fields are null", () => {
    const user: ClaimsUser = {
      displayName: null,
      name: "Upstream Name",
      avatarUrl: null,
      image: "https://cdn/image.png",
    };
    const resolved = resolveUserClaims(user, ["profile"], []);
    expect(resolved.name).toBe("Upstream Name");
    expect(resolved.picture).toBe("https://cdn/image.png");
  });

  it("emits null name/picture (not undefined) when every source is null", () => {
    const user: ClaimsUser = {
      displayName: null,
      name: null,
      avatarUrl: null,
      image: null,
    };
    const resolved = resolveUserClaims(user, ["profile"], []);
    // The ID token path passes these through to mintIdToken, which emits
    // the key for `null` but skips it for `undefined`. Keep it null.
    expect(resolved.name).toBeNull();
    expect(resolved.picture).toBeNull();
  });

  it("passes through the approved badge JWTs verbatim", () => {
    const resolved = resolveUserClaims(fullUser, ["profile"], ["jwt-a", "jwt-b"]);
    expect(resolved.ministerBadges).toEqual(["jwt-a", "jwt-b"]);
  });
});
