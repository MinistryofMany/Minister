import { describe, expect, it } from "vitest";

import { buildRedditBadges, redditFullname } from "./derive";

describe("redditFullname", () => {
  it("prefixes the base36 id with t2_", () => {
    expect(redditFullname("abc123")).toBe("t2_abc123");
  });
});

describe("buildRedditBadges", () => {
  const now = new Date("2026-01-01T00:00:00Z");

  it("anchors on the t2_ fullname, discloses only the username", () => {
    const badges = buildRedditBadges({ id: "abc123", name: "spez" }, now);
    expect(badges).toHaveLength(1);
    const oauth = badges[0]!;
    expect(oauth.type).toBe("oauth-account");
    expect(oauth.claims).toEqual({ provider: "reddit", handle: "spez" });
    expect(oauth.attributes).toEqual({ provider: "reddit", handle: "spez" });
    // The anchor is the immutable fullname, NOT disclosed in claims/attributes.
    expect(oauth.sybilAnchor).toBe("t2_abc123");
  });

  it("adds account-age from created_utc when old enough", () => {
    // created_utc ~2010 → clears the 60-month bucket.
    const badges = buildRedditBadges({ id: "abc123", name: "spez", createdUtc: 1275350400 }, now);
    const byType = new Map(badges.map((b) => [b.type, b] as const));
    expect(byType.get("account-age")?.claims).toEqual({
      provider: "reddit",
      olderThanMonths: 60,
    });
    expect(byType.get("account-age")?.sybilAnchor).toBe("t2_abc123");
  });

  it("omits account-age for a fresh account", () => {
    const createdUtc = Math.floor(new Date("2025-12-01T00:00:00Z").getTime() / 1000);
    const badges = buildRedditBadges({ id: "abc123", name: "spez", createdUtc }, now);
    expect(badges.map((b) => b.type)).toEqual(["oauth-account"]);
  });
});
