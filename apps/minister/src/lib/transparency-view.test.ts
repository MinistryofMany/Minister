import { describe, expect, it } from "vitest";

import {
  buildPublicCohortRow,
  buildPublicTypeRows,
  publicCountDisplay,
  type BadgeStatInput,
} from "@/lib/transparency-view";

describe("publicCountDisplay — k-suppression then rounding", () => {
  it("suppresses a small non-zero count to the <5 sentinel", () => {
    expect(publicCountDisplay(3)).toBe("<5");
    expect(publicCountDisplay(1)).toBe("<5");
    expect(publicCountDisplay(4)).toBe("<5");
  });

  it("shows a true zero as 0 (an absence is not identifying)", () => {
    expect(publicCountDisplay(0)).toBe("0");
  });

  it("rounds a surviving count to the nearest 10", () => {
    expect(publicCountDisplay(47)).toBe("50");
    // Boundary: exactly k survives suppression, then rounds up to 10.
    expect(publicCountDisplay(5)).toBe("10");
    expect(publicCountDisplay(14)).toBe("10");
    expect(publicCountDisplay(15)).toBe("20");
  });

  it("never emits a raw exact count for any small or mid value", () => {
    for (let n = 1; n <= 4; n++) expect(publicCountDisplay(n)).toBe("<5");
    for (let n = 5; n <= 200; n++) {
      const out = publicCountDisplay(n);
      // The output is a rounded multiple of 10 (nearest-10 regime), never the raw n
      // unless n is already such a multiple.
      const rounded = Math.round(n / 10) * 10;
      expect(out).toBe(rounded.toLocaleString());
    }
  });
});

describe("buildPublicTypeRows — layer 1 allowlist re-check + suppression/rounding", () => {
  it("drops a non-allowlisted attribute key even if it reached the table", () => {
    const stats: BadgeStatInput[] = [
      { badgeType: "email-domain", attributeKey: "", attributeValue: "", count: 40 },
      // `domain` is FORBIDDEN — must never render, no matter the count.
      {
        badgeType: "email-domain",
        attributeKey: "domain",
        attributeValue: "corp.example.com",
        count: 40,
      },
    ];
    const rows = buildPublicTypeRows(stats);
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    expect(row.type).toBe("email-domain");
    expect(row.totalDisplay).toBe("40");
    // No attribute group survives — the forbidden key was dropped.
    expect(row.attributes).toHaveLength(0);
  });

  it("keeps an allowlisted key and suppresses/rounds its values", () => {
    const stats: BadgeStatInput[] = [
      { badgeType: "oauth-account", attributeKey: "", attributeValue: "", count: 123 },
      { badgeType: "oauth-account", attributeKey: "provider", attributeValue: "github", count: 88 },
      { badgeType: "oauth-account", attributeKey: "provider", attributeValue: "google", count: 33 },
      // rare provider: 2 holders -> must suppress, never expose "2"
      { badgeType: "oauth-account", attributeKey: "provider", attributeValue: "discord", count: 2 },
      // a non-allowlisted key mixed in -> dropped
      { badgeType: "oauth-account", attributeKey: "handle", attributeValue: "alice", count: 1 },
    ];
    const rows = buildPublicTypeRows(stats);
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    expect(row.totalDisplay).toBe("120");
    expect(row.attributes).toHaveLength(1);
    const group = row.attributes[0]!;
    expect(group.key).toBe("provider");
    // sorted by true count desc: github(88->90), google(33->30), discord(2->"<5")
    expect(group.values.map((v) => v.value)).toEqual(["github", "google", "discord"]);
    expect(group.values.map((v) => v.display)).toEqual(["90", "30", "<5"]);
    // The forbidden `handle` key produced no group.
    expect(row.attributes.some((g) => g.key === "handle")).toBe(false);
  });

  it("orders types by size but never renders the raw total", () => {
    const stats: BadgeStatInput[] = [
      { badgeType: "email-domain", attributeKey: "", attributeValue: "", count: 10 },
      { badgeType: "oauth-account", attributeKey: "", attributeValue: "", count: 200 },
    ];
    const rows = buildPublicTypeRows(stats);
    expect(rows.map((r) => r.type)).toEqual(["oauth-account", "email-domain"]);
    // The displayed total is rounded, not the raw 200/10 (here both are multiples of 10).
    expect(rows[0]!.totalDisplay).toBe("200");
  });
});

describe("buildPublicCohortRow — percentage never leaks a small count", () => {
  it("withholds the percentage when the denominator is small", () => {
    // numerator 1 of denominator 3 — a raw ratio would leak both.
    const row = buildPublicCohortRow("tiny cohort", 1, 3);
    expect(row.numeratorDisplay).toBe("<5");
    expect(row.denominatorDisplay).toBe("<5");
    expect(row.percentDisplay).toBeNull();
  });

  it("withholds the percentage when only the numerator is small", () => {
    // 3 of 50: a percent (6%) would reconstruct the exact numerator 3.
    const row = buildPublicCohortRow("small numerator", 3, 50);
    expect(row.numeratorDisplay).toBe("<5");
    expect(row.denominatorDisplay).toBe("50");
    expect(row.percentDisplay).toBeNull();
  });

  it("derives the percentage from ROUNDED values when both sides survive", () => {
    // 47 of 123 -> rounded 50 / 120 = 41.67% -> 42%.
    const row = buildPublicCohortRow("aged github", 47, 123);
    expect(row.numeratorDisplay).toBe("50");
    expect(row.denominatorDisplay).toBe("120");
    expect(row.percentDisplay).toBe("42%");
  });

  it("never produces a percentage above 100 and handles equal sides", () => {
    const row = buildPublicCohortRow("all of them", 50, 50);
    expect(row.percentDisplay).toBe("100%");
  });

  it("proves the percentage is a pure function of published counts (no raw leak)", () => {
    // Two different raw pairs that round to the same displayed counts must yield
    // the SAME percentage — so the percent reveals nothing beyond the rounded
    // counts already on the page.
    const a = buildPublicCohortRow("a", 46, 121);
    const b = buildPublicCohortRow("b", 54, 119);
    expect(a.numeratorDisplay).toBe(b.numeratorDisplay); // both "50"
    expect(a.denominatorDisplay).toBe(b.denominatorDisplay); // both "120"
    expect(a.percentDisplay).toBe(b.percentDisplay);
  });
});
