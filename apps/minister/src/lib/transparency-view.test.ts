import { describe, expect, it } from "vitest";

import {
  buildPublicCohortRow,
  buildPublicTypeRows,
  publicCountDisplay,
  type BadgeStatInput,
} from "@/lib/transparency-view";

describe("publicCountDisplay — honest range buckets (change C)", () => {
  it("shows a small non-zero count as the <5 range", () => {
    expect(publicCountDisplay(3)).toBe("<5");
    expect(publicCountDisplay(1)).toBe("<5");
    expect(publicCountDisplay(4)).toBe("<5");
  });

  it("shows a true zero as 0 (an absence is not identifying)", () => {
    expect(publicCountDisplay(0)).toBe("0");
  });

  it("maps a surviving count to its widening range", () => {
    expect(publicCountDisplay(5)).toBe("5–9");
    expect(publicCountDisplay(9)).toBe("5–9");
    expect(publicCountDisplay(14)).toBe("10–24");
    expect(publicCountDisplay(15)).toBe("10–24");
    expect(publicCountDisplay(47)).toBe("25–49");
    expect(publicCountDisplay(88)).toBe("50–99");
    expect(publicCountDisplay(200)).toBe("100–249");
    expect(publicCountDisplay(300)).toBe("250–499");
    expect(publicCountDisplay(750)).toBe("500–999");
  });

  it("floors large counts to the nearest 1,000 as an open N,000+ range", () => {
    expect(publicCountDisplay(1000)).toBe("1,000+");
    expect(publicCountDisplay(1999)).toBe("1,000+");
    expect(publicCountDisplay(2750)).toBe("2,000+");
    expect(publicCountDisplay(10_500)).toBe("10,000+");
  });

  it("never emits a raw exact count for any value", () => {
    for (let n = 1; n <= 4; n++) expect(publicCountDisplay(n)).toBe("<5");
    // Sub-1000 counts are always a range label (contains an en-dash or the "<5"
    // sentinel), never the bare integer.
    for (let n = 5; n <= 999; n++) {
      const out = publicCountDisplay(n);
      expect(out).not.toBe(String(n));
      expect(out).not.toBe(n.toLocaleString());
      expect(out.includes("–")).toBe(true);
    }
    // From 1000 up, only the floored thousand is shown (never the raw count).
    expect(publicCountDisplay(1234)).toBe("1,000+");
    expect(publicCountDisplay(1234)).not.toBe("1,234");
  });
});

describe("buildPublicTypeRows — layer 1 allowlist re-check + range bucketing", () => {
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
    expect(row.totalDisplay).toBe("25–49");
    // No attribute group survives — the forbidden key was dropped.
    expect(row.attributes).toHaveLength(0);
  });

  it("keeps an allowlisted key and buckets its values", () => {
    const stats: BadgeStatInput[] = [
      { badgeType: "oauth-account", attributeKey: "", attributeValue: "", count: 123 },
      { badgeType: "oauth-account", attributeKey: "provider", attributeValue: "github", count: 88 },
      { badgeType: "oauth-account", attributeKey: "provider", attributeValue: "google", count: 33 },
      // rare provider: 2 holders -> must bucket to "<5", never expose "2"
      { badgeType: "oauth-account", attributeKey: "provider", attributeValue: "discord", count: 2 },
      // a non-allowlisted key mixed in -> dropped
      { badgeType: "oauth-account", attributeKey: "handle", attributeValue: "alice", count: 1 },
    ];
    const rows = buildPublicTypeRows(stats);
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    expect(row.totalDisplay).toBe("100–249");
    expect(row.attributes).toHaveLength(1);
    const group = row.attributes[0]!;
    expect(group.key).toBe("provider");
    // sorted by lower bound desc: github(88), google(33), discord(2->"<5")
    expect(group.values.map((v) => v.value)).toEqual(["github", "google", "discord"]);
    expect(group.values.map((v) => v.display)).toEqual(["50–99", "25–49", "<5"]);
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
    expect(rows[0]!.totalDisplay).toBe("100–249");
    expect(rows[1]!.totalDisplay).toBe("10–24");
  });

  // W1: DOM order must be a pure function of the PUBLISHED bucket, not the raw
  // count — so two cells in the SAME printed range are ordered by name, never by
  // their distinct underlying counts (which a raw-count sort would leak).
  it("orders same-bucket attribute values by name, not by raw count", () => {
    const stats: BadgeStatInput[] = [
      { badgeType: "oauth-account", attributeKey: "", attributeValue: "", count: 300 },
      // Distinct raw counts that BOTH fall in "100–249". The larger raw count is on
      // the lexicographically-LATER name, so a raw-count sort would flip the order.
      {
        badgeType: "oauth-account",
        attributeKey: "provider",
        attributeValue: "github",
        count: 118,
      },
      {
        badgeType: "oauth-account",
        attributeKey: "provider",
        attributeValue: "google",
        count: 121,
      },
    ];
    const group = buildPublicTypeRows(stats)[0]!.attributes[0]!;
    expect(group.values.map((v) => v.display)).toEqual(["100–249", "100–249"]);
    // Name order (github < google), NOT raw-count order (google 121 > github 118).
    expect(group.values.map((v) => v.value)).toEqual(["github", "google"]);
  });

  it("orders same-<5 attribute values by name, not by raw count", () => {
    const stats: BadgeStatInput[] = [
      { badgeType: "oauth-account", attributeKey: "", attributeValue: "", count: 300 },
      // Both bucket to "<5"; larger raw count on the later name to expose a raw sort.
      { badgeType: "oauth-account", attributeKey: "provider", attributeValue: "discord", count: 2 },
      { badgeType: "oauth-account", attributeKey: "provider", attributeValue: "reddit", count: 4 },
    ];
    const group = buildPublicTypeRows(stats)[0]!.attributes[0]!;
    expect(group.values.map((v) => v.display)).toEqual(["<5", "<5"]);
    // Name order (discord < reddit), NOT raw-count order (reddit 4 > discord 2).
    expect(group.values.map((v) => v.value)).toEqual(["discord", "reddit"]);
  });

  it("orders same-bucket TYPE totals by name, not by raw count", () => {
    const stats: BadgeStatInput[] = [
      // Both totals fall in "100–249"; larger raw count on the later name.
      { badgeType: "email-domain", attributeKey: "", attributeValue: "", count: 118 },
      { badgeType: "oauth-account", attributeKey: "", attributeValue: "", count: 121 },
    ];
    const rows = buildPublicTypeRows(stats);
    expect(rows.map((r) => r.totalDisplay)).toEqual(["100–249", "100–249"]);
    // Name order (email-domain < oauth-account), NOT raw order (oauth-account 121 first).
    expect(rows.map((r) => r.type)).toEqual(["email-domain", "oauth-account"]);
  });

  // S1: the value space is closed too — a value outside its key's known enum is
  // dropped at render even under an allowlisted key, since Badge.attributes is
  // stored verbatim (only VC claims are Zod-validated).
  it("drops an out-of-domain value under an allowlisted key (never renders)", () => {
    const stats: BadgeStatInput[] = [
      { badgeType: "oauth-account", attributeKey: "", attributeValue: "", count: 90 },
      { badgeType: "oauth-account", attributeKey: "provider", attributeValue: "github", count: 88 },
      // `provider` is allowlisted, but "evil-freetext" is not an OAuth provider.
      {
        badgeType: "oauth-account",
        attributeKey: "provider",
        attributeValue: "evil-freetext",
        count: 40,
      },
    ];
    const rows = buildPublicTypeRows(stats);
    const group = rows[0]!.attributes[0]!;
    expect(group.values.map((v) => v.value)).toEqual(["github"]);
    expect(group.values.some((v) => v.value === "evil-freetext")).toBe(false);
  });
});

describe("buildPublicCohortRow — ranges + nearest-5% percentage", () => {
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
    expect(row.denominatorDisplay).toBe("50–99");
    expect(row.percentDisplay).toBeNull();
  });

  it("shows ranges and a nearest-5% percentage from the printed bucket bounds", () => {
    // 47 -> bucket "25–49" (lower 25); 123 -> "100–249" (lower 100). The percentage
    // is derived from the printed lower bounds: 25 / 100 = 25%.
    const row = buildPublicCohortRow("aged github", 47, 123);
    expect(row.numeratorDisplay).toBe("25–49");
    expect(row.denominatorDisplay).toBe("100–249");
    expect(row.percentDisplay).toBe("25%");
  });

  it("never produces a percentage above 100 and handles equal sides", () => {
    const row = buildPublicCohortRow("all of them", 50, 50);
    expect(row.percentDisplay).toBe("100%");
  });

  it("percentage is a pure function of the printed ranges (no within-bucket leak)", () => {
    // The leak this guards against: two numerators in the SAME printed bucket over
    // the SAME denominator bucket must yield the SAME percentage. 100 and 240 both
    // print "100–249"; over "2,000+" both must read 5%. Deriving the percentage from
    // a finer coarsening (e.g. roundPublic) would have shown 5% vs 10%, leaking that
    // the numerator crossed ~150 inside its printed bucket.
    const a = buildPublicCohortRow("a", 100, 2000);
    const b = buildPublicCohortRow("b", 240, 2000);
    expect(a.numeratorDisplay).toBe("100–249");
    expect(b.numeratorDisplay).toBe("100–249");
    expect(a.denominatorDisplay).toBe("2,000+");
    expect(b.denominatorDisplay).toBe("2,000+");
    expect(a.percentDisplay).toBe("5%");
    expect(b.percentDisplay).toBe("5%");
  });
});
