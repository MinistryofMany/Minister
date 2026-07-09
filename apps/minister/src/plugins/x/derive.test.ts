import { describe, expect, it } from "vitest";

import { buildXBadges } from "./derive";

describe("buildXBadges", () => {
  const now = new Date("2026-01-01T00:00:00Z");

  it("anchors on the numeric id, discloses only the @handle", () => {
    const badges = buildXBadges({ id: "2244994945", username: "XDevelopers" }, now);
    expect(badges).toHaveLength(1);
    const oauth = badges[0]!;
    expect(oauth.claims).toEqual({ provider: "x", handle: "XDevelopers" });
    expect(oauth.sybilAnchor).toBe("2244994945");
  });

  it("adds account-age from an ISO created_at when old enough", () => {
    const badges = buildXBadges(
      { id: "1", username: "old", createdAt: "2015-01-01T00:00:00Z" },
      now,
    );
    const byType = new Map(badges.map((b) => [b.type, b] as const));
    expect(byType.get("account-age")?.claims).toEqual({ provider: "x", olderThanMonths: 60 });
    expect(byType.get("account-age")?.sybilAnchor).toBe("1");
  });

  it("ignores an unparseable created_at", () => {
    const badges = buildXBadges({ id: "1", username: "old", createdAt: "not-a-date" }, now);
    expect(badges.map((b) => b.type)).toEqual(["oauth-account"]);
  });
});
