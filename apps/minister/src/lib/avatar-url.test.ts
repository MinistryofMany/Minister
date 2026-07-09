import { describe, expect, it } from "vitest";

import { avatarServePath, buildUploadedAvatarUrl, isUploadedAvatarUrl } from "@/lib/avatar-url";

// An OPAQUE, random public handle — deliberately NOT the userId, so the serve
// path (and the disclosed picture claim) never carries the internal account id.
const PUBLIC_ID = "aVeryOpaqueRandomHandle";

describe("avatarServePath", () => {
  it("builds the internal serve path from the opaque publicId", () => {
    expect(avatarServePath(PUBLIC_ID)).toBe("/api/avatars/aVeryOpaqueRandomHandle");
  });
});

describe("buildUploadedAvatarUrl", () => {
  it("produces an absolute, cache-busted URL keyed on the publicId", () => {
    expect(buildUploadedAvatarUrl("https://ministry.id", PUBLIC_ID, 1720000000000)).toBe(
      "https://ministry.id/api/avatars/aVeryOpaqueRandomHandle?v=1720000000000",
    );
  });

  it("does not double a trailing slash on the origin", () => {
    expect(buildUploadedAvatarUrl("https://ministry.id/", PUBLIC_ID, 42)).toBe(
      "https://ministry.id/api/avatars/aVeryOpaqueRandomHandle?v=42",
    );
  });

  it("does not embed the userId anywhere in the URL", () => {
    const url = buildUploadedAvatarUrl("https://ministry.id", PUBLIC_ID, 1);
    expect(url).not.toContain("/api/users/");
  });
});

describe("isUploadedAvatarUrl", () => {
  it("recognizes an uploaded serve URL (with a version query)", () => {
    const url = buildUploadedAvatarUrl("https://ministry.id", PUBLIC_ID, 99);
    expect(isUploadedAvatarUrl(url)).toBe(true);
  });

  it("recognizes an uploaded serve URL regardless of which publicId it carries", () => {
    const url = buildUploadedAvatarUrl("https://ministry.id", "someOtherHandle", 99);
    expect(isUploadedAvatarUrl(url)).toBe(true);
  });

  it("is false for the serve prefix with no publicId segment", () => {
    expect(isUploadedAvatarUrl("https://ministry.id/api/avatars/")).toBe(false);
  });

  it("is false for a null avatar (the deterministic default)", () => {
    expect(isUploadedAvatarUrl(null)).toBe(false);
  });

  it("is false for a Gravatar URL", () => {
    expect(isUploadedAvatarUrl("https://www.gravatar.com/avatar/abc123?d=404")).toBe(false);
  });

  it("is false for an arbitrary custom link", () => {
    expect(isUploadedAvatarUrl("https://example.com/me.png")).toBe(false);
  });

  it("is false for a non-URL value", () => {
    expect(isUploadedAvatarUrl("not a url")).toBe(false);
  });
});
