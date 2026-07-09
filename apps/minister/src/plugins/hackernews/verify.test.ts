import { describe, expect, it } from "vitest";

import { aboutContainsToken, buildHackerNewsBadges, isValidHackerNewsUsername } from "./verify";

describe("isValidHackerNewsUsername", () => {
  it("accepts plausible HN usernames", () => {
    expect(isValidHackerNewsUsername("pg")).toBe(true);
    expect(isValidHackerNewsUsername("some_user-1")).toBe(true);
  });
  it("rejects a pasted profile URL or junk", () => {
    expect(isValidHackerNewsUsername("https://news.ycombinator.com/user?id=pg")).toBe(false);
    expect(isValidHackerNewsUsername("a")).toBe(false); // too short
    expect(isValidHackerNewsUsername("way_too_long_username")).toBe(false);
  });
});

describe("aboutContainsToken", () => {
  it("finds the token embedded in surrounding about text", () => {
    expect(aboutContainsToken("hi there minister-abc123 cheers", "minister-abc123")).toBe(true);
  });
  it("is false when the token is absent", () => {
    expect(aboutContainsToken("no token here", "minister-abc123")).toBe(false);
  });
  it("is false for empty about or empty token", () => {
    expect(aboutContainsToken(null, "minister-abc123")).toBe(false);
    expect(aboutContainsToken("minister-abc123", "")).toBe(false);
  });
});

describe("buildHackerNewsBadges", () => {
  const now = new Date("2026-01-01T00:00:00Z");

  it("issues oauth-account with revealsAnchor (username IS the anchor) + account-age", () => {
    // created ~2007 → clears the 60-month bucket.
    const badges = buildHackerNewsBadges({ id: "pg", created: 1175714200 }, now);
    const byType = new Map(badges.map((b) => [b.type, b] as const));

    const oauth = byType.get("oauth-account")!;
    expect(oauth.claims).toEqual({ provider: "hackernews", handle: "pg" });
    expect(oauth.sybilAnchor).toBe("pg");
    // The username is both the anchor and the disclosed handle, so the leak
    // guard must be opted out of, or issuance would refuse this badge.
    expect(oauth.revealsAnchor).toBe(true);

    expect(byType.get("account-age")?.claims).toEqual({
      provider: "hackernews",
      olderThanMonths: 60,
    });
    // account-age hides its anchor (no username in the claims), so it keeps the
    // guard on.
    expect(byType.get("account-age")?.revealsAnchor).toBeUndefined();
  });

  it("issues only oauth-account when the account is too new", () => {
    const badges = buildHackerNewsBadges(
      { id: "fresh", created: Math.floor(new Date("2025-12-01T00:00:00Z").getTime() / 1000) },
      now,
    );
    expect(badges.map((b) => b.type)).toEqual(["oauth-account"]);
  });
});
