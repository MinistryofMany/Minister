import { describe, expect, it } from "vitest";

import {
  publicCountBucket,
  publicCountLowerBound,
  roundPublic,
  suppress,
} from "@/lib/stats-public";

describe("suppress (k-anonymity)", () => {
  it("suppresses small non-zero counts to '<k'", () => {
    expect(suppress(1)).toBe("<5");
    expect(suppress(3)).toBe("<5");
    expect(suppress(4)).toBe("<5");
  });

  it("keeps a true zero as 0 (absence is not identifying)", () => {
    expect(suppress(0)).toBe(0);
  });

  it("passes counts at or above k through unchanged", () => {
    expect(suppress(5)).toBe(5);
    expect(suppress(6)).toBe(6);
    expect(suppress(1000)).toBe(1000);
  });

  it("honors a custom k", () => {
    expect(suppress(9, 10)).toBe("<10");
    expect(suppress(10, 10)).toBe(10);
    expect(suppress(0, 10)).toBe(0);
  });

  it("treats negatives defensively as 0", () => {
    expect(suppress(-3)).toBe(0);
  });
});

describe("roundPublic (count coarsening)", () => {
  it("rounds small counts to the nearest 10", () => {
    expect(roundPublic(47)).toBe(50);
    expect(roundPublic(44)).toBe(40);
    expect(roundPublic(45)).toBe(50);
    expect(roundPublic(5)).toBe(10);
  });

  it("returns 0 for zero/negative", () => {
    expect(roundPublic(0)).toBe(0);
    expect(roundPublic(-10)).toBe(0);
  });

  it("coarsens large counts to two significant figures (~5% granularity)", () => {
    expect(roundPublic(1000)).toBe(1000);
    expect(roundPublic(12_345)).toBe(12_000);
    expect(roundPublic(12_678)).toBe(13_000);
    expect(roundPublic(987_654)).toBe(990_000);
  });
});

describe("publicCountBucket (range labels, change C)", () => {
  it("maps counts to the specified ranges", () => {
    expect(publicCountBucket(0)).toBe("0");
    expect(publicCountBucket(1)).toBe("<5");
    expect(publicCountBucket(4)).toBe("<5");
    expect(publicCountBucket(5)).toBe("5–9");
    expect(publicCountBucket(9)).toBe("5–9");
    expect(publicCountBucket(10)).toBe("10–24");
    expect(publicCountBucket(24)).toBe("10–24");
    expect(publicCountBucket(25)).toBe("25–49");
    expect(publicCountBucket(49)).toBe("25–49");
    expect(publicCountBucket(50)).toBe("50–99");
    expect(publicCountBucket(99)).toBe("50–99");
    expect(publicCountBucket(100)).toBe("100–249");
    expect(publicCountBucket(249)).toBe("100–249");
    expect(publicCountBucket(250)).toBe("250–499");
    expect(publicCountBucket(499)).toBe("250–499");
    expect(publicCountBucket(500)).toBe("500–999");
    expect(publicCountBucket(999)).toBe("500–999");
  });

  it("floors >=1000 to the nearest 1,000 as an open N,000+ range", () => {
    expect(publicCountBucket(1000)).toBe("1,000+");
    expect(publicCountBucket(1999)).toBe("1,000+");
    expect(publicCountBucket(2750)).toBe("2,000+");
    expect(publicCountBucket(10_500)).toBe("10,000+");
  });

  it("treats negatives defensively as 0", () => {
    expect(publicCountBucket(-1)).toBe("0");
  });
});

describe("publicCountLowerBound (bucket ordering key)", () => {
  it("is the inclusive lower bound of the printed range", () => {
    expect(publicCountLowerBound(0)).toBe(0);
    expect(publicCountLowerBound(1)).toBe(1);
    expect(publicCountLowerBound(4)).toBe(1);
    expect(publicCountLowerBound(5)).toBe(5);
    expect(publicCountLowerBound(24)).toBe(10);
    expect(publicCountLowerBound(49)).toBe(25);
    expect(publicCountLowerBound(999)).toBe(500);
  });

  it("uses the floored thousand for a N,000+ bucket", () => {
    expect(publicCountLowerBound(1500)).toBe(1000);
    expect(publicCountLowerBound(2750)).toBe(2000);
  });

  it("gives the SAME key to two counts in the same printed range", () => {
    // 88 and 55 both print "50–99" -> identical ordering key (no finer leak).
    expect(publicCountBucket(88)).toBe(publicCountBucket(55));
    expect(publicCountLowerBound(88)).toBe(publicCountLowerBound(55));
  });
});
