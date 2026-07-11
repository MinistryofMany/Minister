import { describe, expect, it } from "vitest";

import {
  buildCohortCountSql,
  cohortFilterSchema,
  parseCohortFilter,
  safeParseCohortFilter,
  BUILTIN_COHORT_DEFS,
  type CohortFilter,
} from "@/lib/cohort-filter";

const NATIVE = "did:web:minister.local";
const NOW = new Date("2026-07-11T00:00:00Z");

describe("cohort-filter validation", () => {
  it("accepts a valid allowlisted conjunction", () => {
    const ok = parseCohortFilter({
      clauses: [
        { type: "account-age", where: { provider: "github" }, whereGte: { olderThanMonths: 24 } },
      ],
    });
    expect(ok.clauses).toHaveLength(1);
  });

  it("rejects an unknown badge type", () => {
    expect(() =>
      parseCohortFilter({ clauses: [{ type: "totally-made-up", where: { provider: "x" } }] }),
    ).toThrow(/Unknown badge type/);
  });

  it("rejects a non-allowlisted key for the type (the injection-hole close)", () => {
    // `handle` is a real oauth-account attribute but is FORBIDDEN (PII).
    expect(() =>
      parseCohortFilter({ clauses: [{ type: "oauth-account", where: { handle: "octocat" } }] }),
    ).toThrow(/not an allowlisted attribute/);
    // A right-type-wrong-type key.
    expect(() =>
      parseCohortFilter({ clauses: [{ type: "oauth-account", where: { olderThanMonths: "5" } }] }),
    ).toThrow(/not an allowlisted attribute/);
  });

  it("rejects a SQL-injection-shaped KEY at validation (never reaches SQL)", () => {
    const malicious = {
      clauses: [{ type: "oauth-account", where: { '"; DROP TABLE "Badge"; --': "x" } }],
    };
    expect(() => parseCohortFilter(malicious)).toThrow(/not an allowlisted attribute/);
    expect(safeParseCohortFilter(malicious)).toBeNull();
  });

  it("rejects PII keys the brief forbids outright", () => {
    for (const bad of [
      { type: "email-domain", where: { domain: "corp.example.com" } },
      { type: "email-exact", where: { email: "a@b.com" } },
      { type: "public-key", where: { fingerprint: "SHA256:x" } },
      { type: "residency-state", where: { state: "CA" } },
    ]) {
      expect(() => parseCohortFilter({ clauses: [bad] })).toThrow();
    }
  });

  it("enforces the 1..3 clause bound", () => {
    expect(cohortFilterSchema.safeParse({ clauses: [] }).success).toBe(false);
    const four = {
      clauses: [
        { type: "oauth-account", where: { provider: "github" } },
        { type: "oauth-account", where: { provider: "google" } },
        { type: "oauth-account", where: { provider: "discord" } },
        { type: "oauth-account", where: { provider: "reddit" } },
      ],
    };
    expect(cohortFilterSchema.safeParse(four).success).toBe(false);
  });

  it("validates the built-in seeded cohort defs", () => {
    for (const def of BUILTIN_COHORT_DEFS) {
      expect(() => parseCohortFilter(def.numeratorFilter)).not.toThrow();
      expect(() => parseCohortFilter(def.denominatorFilter)).not.toThrow();
    }
  });
});

describe("cohort-filter SQL is injection-safe", () => {
  it("binds every VALUE as a parameter and never interpolates it into SQL text", () => {
    // A malicious VALUE passes validation (the key `provider` is allowlisted) —
    // its safety rests entirely on parameterization.
    const evil = `github'; DROP TABLE "Badge"; --`;
    const filter = parseCohortFilter({
      clauses: [{ type: "oauth-account", where: { provider: evil } }],
    });
    const sql = buildCohortCountSql(filter, NATIVE, NOW);

    // The dangerous string is a bound value, not part of the query text.
    expect(sql.text).not.toContain("DROP TABLE");
    expect(sql.text).not.toContain(evil);
    expect(sql.values).toContain(evil);
    // The query text carries only numbered placeholders + fixed identifiers.
    expect(sql.text).toContain("$");
    expect(sql.text).toContain(`FROM "Badge" b1`);
  });

  it("binds KEYS as parameters too (jsonb ->> text), never as SQL text", () => {
    const filter = parseCohortFilter({
      clauses: [{ type: "oauth-account", where: { provider: "github" } }],
    });
    const sql = buildCohortCountSql(filter, NATIVE, NOW);
    // Both the key and the value are bound values; neither is literal SQL text.
    expect(sql.values).toContain("provider");
    expect(sql.values).toContain("github");
    expect(sql.values).toContain(NATIVE);
    expect(sql.text).not.toContain("'github'");
    expect(sql.text).not.toContain("'provider'");
  });

  it("composes multi-clause conjunctions as EXISTS subqueries", () => {
    const filter: CohortFilter = {
      clauses: [
        { type: "account-age", where: { provider: "github" }, whereGte: { olderThanMonths: 24 } },
        { type: "oauth-account", where: { provider: "github" } },
      ],
    };
    const sql = buildCohortCountSql(filter, NATIVE, NOW);
    expect(sql.text).toContain("EXISTS");
    expect(sql.text).toContain(`FROM "Badge" b2`);
    // whereGte value bound, and the tier cast present.
    expect(sql.values).toContain(24);
    expect(sql.text).toContain("::int >=");
  });
});
