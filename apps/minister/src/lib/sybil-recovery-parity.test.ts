import { knownBadgeTypes } from "@minister/shared";
import { describe, expect, it } from "vitest";

import { recoveryWeightFor } from "./assurance";
import { SYBIL_BADGE_WEIGHT_SEED, type BadgeWeightSeedRow } from "./sybil-config";

// The BadgeWeight seed migrates the recovery weights out of assurance.ts into
// the DB config. `recoveryWeightFor` stays the pure oracle; this test asserts
// the hand-transcribed seed reproduces it EXACTLY, so the migration is
// behavior-identical (design spec §5.4, impl brief §2.2, §5). Pure — no DB.

// Recovery resolution only distinguishes oauth-account by provenance; every
// other type ignores the provenance argument. Mirror recoveryWeightForLive's
// qualifier chain to pick the provenance the oracle is queried with for a row.
function provenanceForRow(row: BadgeWeightSeedRow): string | undefined {
  if (row.badgeType === "oauth-account") {
    return row.qualifier === "*" ? undefined : row.qualifier;
  }
  return undefined;
}

describe("sybil recovery-weight seed parity", () => {
  it("every seed row's recoveryWeight equals recoveryWeightFor(type, provenance)", () => {
    for (const row of SYBIL_BADGE_WEIGHT_SEED) {
      const provenance = provenanceForRow(row);
      expect(
        row.recoveryWeight,
        `type=${row.badgeType} qualifier=${row.qualifier} provenance=${provenance ?? "(none)"}`,
      ).toBe(recoveryWeightFor(row.badgeType, provenance));
    }
  });

  // --- Eligible set (the ONLY types the recovery engine reads) -----------------

  it("oauth-account provenance fallbacks: github/google/reddit/hackernews/undefined -> 20, discord/steam -> 10", () => {
    expect(recoveryWeightFor("oauth-account", "github")).toBe(20);
    expect(recoveryWeightFor("oauth-account", "google")).toBe(20);
    expect(recoveryWeightFor("oauth-account", "reddit")).toBe(20);
    expect(recoveryWeightFor("oauth-account", "hackernews")).toBe(20);
    expect(recoveryWeightFor("oauth-account", "discord")).toBe(10);
    expect(recoveryWeightFor("oauth-account", "steam")).toBe(10);
    expect(recoveryWeightFor("oauth-account", undefined)).toBe(20);
  });

  it("email-domain / email-exact -> 15, tlsn-attestation -> 100", () => {
    expect(recoveryWeightFor("email-domain")).toBe(15);
    expect(recoveryWeightFor("email-exact")).toBe(15);
    expect(recoveryWeightFor("tlsn-attestation")).toBe(100);
  });

  // --- Non-eligible fallbacks (seeded for table coherence, never read) ---------

  it("age-over-* and residency-* -> 60 (IAL2)", () => {
    for (const t of [
      "age-over-16",
      "age-over-18",
      "age-over-21",
      "age-over-25",
      "age-over-30",
      "age-over-35",
      "age-over-40",
      "age-over-45",
      "age-over-55",
      "age-over-65",
    ]) {
      expect(recoveryWeightFor(t), t).toBe(60);
    }
    expect(recoveryWeightFor("residency-country")).toBe(60);
    expect(recoveryWeightFor("residency-state")).toBe(60);
    expect(recoveryWeightFor("residency-city")).toBe(60);
  });

  it("account-age / social-following / wallet-* / onchain-event / public-key / domain-control -> 15 (IAL1)", () => {
    for (const t of [
      "account-age",
      "social-following",
      "wallet-control",
      "wallet-age",
      "onchain-event",
      "public-key",
      "domain-control",
    ]) {
      expect(recoveryWeightFor(t), t).toBe(15);
    }
  });

  it("invite-code -> 0 (IAL0)", () => {
    expect(recoveryWeightFor("invite-code")).toBe(0);
  });

  // --- Seed coherence invariants -----------------------------------------------

  it("allowSoloRecovery is true ONLY for tlsn-attestation, and every other row's recoveryWeight < 100", () => {
    for (const row of SYBIL_BADGE_WEIGHT_SEED) {
      if (row.badgeType === "tlsn-attestation") {
        expect(row.allowSoloRecovery, "tlsn-attestation must be solo").toBe(true);
        expect(row.recoveryWeight).toBe(100);
      } else {
        expect(row.allowSoloRecovery, `${row.badgeType} must not be solo`).toBe(false);
        expect(
          row.recoveryWeight,
          `${row.badgeType}:${row.qualifier} must be below the 100 threshold`,
        ).toBeLessThan(100);
      }
    }
  });

  it("every registry type has a '*' seed row (boot-check invariant, checked purely here)", () => {
    const starTypes = new Set(
      SYBIL_BADGE_WEIGHT_SEED.filter((r) => r.qualifier === "*").map((r) => r.badgeType),
    );
    for (const t of knownBadgeTypes()) {
      expect(starTypes.has(t), `missing '*' seed row for ${t}`).toBe(true);
    }
  });
});
