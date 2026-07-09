import { describe, expect, it } from "vitest";

import { avatarServePath, buildUploadedAvatarUrl, isUploadedAvatarUrl } from "@/lib/avatar-url";

const USER = "clu123abc";

describe("avatarServePath", () => {
  it("builds the internal serve path for a user", () => {
    expect(avatarServePath(USER)).toBe("/api/users/clu123abc/avatar");
  });
});

describe("buildUploadedAvatarUrl", () => {
  it("produces an absolute, cache-busted URL", () => {
    expect(buildUploadedAvatarUrl("https://ministry.id", USER, 1720000000000)).toBe(
      "https://ministry.id/api/users/clu123abc/avatar?v=1720000000000",
    );
  });

  it("does not double a trailing slash on the origin", () => {
    expect(buildUploadedAvatarUrl("https://ministry.id/", USER, 42)).toBe(
      "https://ministry.id/api/users/clu123abc/avatar?v=42",
    );
  });
});

describe("isUploadedAvatarUrl", () => {
  it("recognizes this user's serve URL (with a version query)", () => {
    const url = buildUploadedAvatarUrl("https://ministry.id", USER, 99);
    expect(isUploadedAvatarUrl(url, USER)).toBe(true);
  });

  it("is false for a different user's serve URL", () => {
    const url = buildUploadedAvatarUrl("https://ministry.id", "other", 99);
    expect(isUploadedAvatarUrl(url, USER)).toBe(false);
  });

  it("is false for a null avatar (the deterministic default)", () => {
    expect(isUploadedAvatarUrl(null, USER)).toBe(false);
  });

  it("is false for a Gravatar URL", () => {
    expect(isUploadedAvatarUrl("https://www.gravatar.com/avatar/abc123?d=404", USER)).toBe(false);
  });

  it("is false for an arbitrary custom link", () => {
    expect(isUploadedAvatarUrl("https://example.com/me.png", USER)).toBe(false);
  });

  it("is false for a non-URL value", () => {
    expect(isUploadedAvatarUrl("not a url", USER)).toBe(false);
  });
});
