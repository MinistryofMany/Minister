import { describe, expect, it } from "vitest";

// HARD requirement (docs/groups-design.md): a `group-membership` badge must NEVER
// contribute anti-sybil score — otherwise founding a group and adding sock-puppet
// members would farm score for free, the exact attack the sybil system exists to
// stop. This pins that guarantee to the LIVE seed config, so a future edit that
// gives group membership a non-zero weight (or drops the zero-cap category) trips
// here.

import {
  SYBIL_BADGE_WEIGHT_SEED,
  SYBIL_BUCKET_CONFIG_SEED,
  SYBIL_CATEGORY_SEED,
  type ScorableBadge,
} from "./sybil-config";
import { buildSybilScoringConfig, sybilScore } from "./sybil-score";

const NATIVE = "did:web:ministry.id";
const NOW = Date.UTC(2026, 6, 12);

const config = buildSybilScoringConfig(
  SYBIL_BADGE_WEIGHT_SEED,
  SYBIL_CATEGORY_SEED,
  SYBIL_BUCKET_CONFIG_SEED,
);

function groupBadge(slug: string, role: string): ScorableBadge {
  return {
    type: "group-membership",
    attributes: { group: slug, role, groupId: `grp_${slug}` },
    expiresAt: null,
    issuer: NATIVE,
  };
}

describe("group-membership contributes zero anti-sybil score", () => {
  it("the seed carries a group-membership `*` row with sybilWeight 0", () => {
    const row = SYBIL_BADGE_WEIGHT_SEED.find(
      (r) => r.badgeType === "group-membership" && r.qualifier === "*",
    );
    expect(row, "group-membership must have a `*` BadgeWeight row").toBeDefined();
    expect(row!.sybilWeight).toBe(0);
  });

  it("a user loaded with many group badges stays raw 0 / bucket 0", () => {
    const badges = [
      groupBadge("acme", "owner"),
      groupBadge("beta", "admin"),
      groupBadge("gamma", "member"),
      groupBadge("delta", "member"),
      groupBadge("epsilon", "member"),
      groupBadge("zeta", "member"),
    ];
    const result = sybilScore(badges, config, { now: NOW, nativeIssuerDid: NATIVE });
    expect(result.raw).toBe(0);
    expect(result.bucket).toBe(0);
  });

  it("group badges add nothing on top of a real score", () => {
    const emailOnly: ScorableBadge[] = [
      {
        type: "email-domain",
        attributes: { domain: "example.com" },
        expiresAt: null,
        issuer: NATIVE,
      },
    ];
    const withGroups = [...emailOnly, groupBadge("acme", "owner"), groupBadge("beta", "member")];
    const base = sybilScore(emailOnly, config, { now: NOW, nativeIssuerDid: NATIVE });
    const boosted = sybilScore(withGroups, config, { now: NOW, nativeIssuerDid: NATIVE });
    expect(boosted.raw).toBe(base.raw);
    expect(boosted.bucket).toBe(base.bucket);
  });
});
