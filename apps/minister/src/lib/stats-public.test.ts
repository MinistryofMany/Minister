import { describe, expect, it } from "vitest";

import { roundPublic, suppress } from "@/lib/stats-public";

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
