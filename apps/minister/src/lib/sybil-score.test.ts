import { describe, expect, it } from "vitest";

import {
  SYBIL_BADGE_WEIGHT_SEED,
  SYBIL_BUCKET_CONFIG_SEED,
  SYBIL_CATEGORY_SEED,
  type ScorableBadge,
  type SybilScoringConfig,
} from "./sybil-config";
import { sybilScore } from "./sybil-score";

// The scorer is tested against a config built from the REAL seed constants (the
// same shape `loadSybilScoringConfig` produces), so a seed edit that would move a
// worked example off its documented bucket fails here rather than in prod. Every
// worked example in design spec §3.7 / impl brief §3.7 is asserted on the exact
// bucket (and, where it distinguishes a rule, the exact raw score).

const NATIVE_DID = "did:web:ministry.id";
const NOW = 1_800_000_000_000; // fixed clock (unix ms); no Date.now() in the scorer

function buildSeedConfig(): SybilScoringConfig {
  const weights = new Map<string, Map<string, number>>();
  const categoryByType = new Map<string, string>();
  for (const row of SYBIL_BADGE_WEIGHT_SEED) {
    let byQualifier = weights.get(row.badgeType);
    if (!byQualifier) {
      byQualifier = new Map<string, number>();
      weights.set(row.badgeType, byQualifier);
    }
    byQualifier.set(row.qualifier, row.sybilWeight);
    categoryByType.set(row.badgeType, row.category);
  }
  const caps = new Map<string, number>();
  for (const cat of SYBIL_CATEGORY_SEED) caps.set(cat.name, cat.cap);
  return {
    weights,
    categoryByType,
    caps,
    cutoffs: {
      b1: SYBIL_BUCKET_CONFIG_SEED.bucket1Raw,
      b2: SYBIL_BUCKET_CONFIG_SEED.bucket2Raw,
      b3: SYBIL_BUCKET_CONFIG_SEED.bucket3Raw,
      b4: SYBIL_BUCKET_CONFIG_SEED.bucket4Raw,
      b3Cats: SYBIL_BUCKET_CONFIG_SEED.bucket3MinCats,
      b4Cats: SYBIL_BUCKET_CONFIG_SEED.bucket4MinCats,
    },
  };
}

const config = buildSeedConfig();
const ctx = { now: NOW, nativeIssuerDid: NATIVE_DID };

// Badge factory: native issuer + non-expiring by default, so tests opt IN to the
// hygiene edge cases (expiry / foreign issuer) explicitly.
function badge(
  type: string,
  attributes: Record<string, unknown> = {},
  overrides: Partial<Pick<ScorableBadge, "expiresAt" | "issuer">> = {},
): ScorableBadge {
  return {
    type,
    attributes,
    expiresAt: overrides.expiresAt ?? null,
    issuer: overrides.issuer ?? NATIVE_DID,
  };
}

const email = () => badge("email-domain", { domain: "example.com" });
const emailExact = () => badge("email-exact", { email: "a@example.com" });
const githubOauth = () => badge("oauth-account", { provider: "github" });
const githubAge24 = () => badge("account-age", { provider: "github", olderThanMonths: 24 });
const domainControl = () => badge("domain-control", { domain: "example.com" });
const walletAge24 = () => badge("wallet-age", { chain: "ethereum", olderThanMonths: 24 });
const invite = () => badge("invite-code", { label: "cohort-a" });

function score(badges: ScorableBadge[]) {
  return sybilScore(badges, config, ctx);
}

describe("sybilScore — worked examples (design spec §3.7)", () => {
  it("fresh account (no badges) -> raw 0, bucket 0", () => {
    expect(score([])).toEqual({ raw: 0, bucket: 0 });
  });

  it("one verified email -> raw 5, bucket 1", () => {
    // email category [5] -> floor(5/1)=5 (< cap 10, not qualifying); raw 5 >= b1(5).
    expect(score([email()])).toEqual({ raw: 5, bucket: 1 });
  });

  it("invited newcomer + email (invite 12 + email 5 = 17) -> bucket 2", () => {
    // invite [12] -> 12 (qualifies); email [5] -> 5; raw 17 >= b2(15).
    expect(score([invite(), email()])).toEqual({ raw: 17, bucket: 2 });
  });

  it("dev: github oauth (8) + account-age github:24 (15) + email (5) -> raw 24, bucket 2", () => {
    // social-oauth [15,8] -> 15 + floor(8/2)=4 = 19 (cap 30, qualifies); email 5.
    // raw 24: >= b2(15) but < b3(28) -> bucket 2.
    expect(score([githubOauth(), githubAge24(), email()])).toEqual({ raw: 24, bucket: 2 });
  });

  it("dev + second root via domain-control (10) -> raw 34, 2 qualifying cats, bucket 3", () => {
    // social 19 + email 5 + domain 10 = 34; qualifying: social(19) + domain(10) = 2.
    // raw 34 >= b3(28) && cats 2 >= b3Cats(2) -> bucket 3.
    expect(score([githubOauth(), githubAge24(), email(), domainControl()])).toEqual({
      raw: 34,
      bucket: 3,
    });
  });

  it("dev + second root via wallet-age 24mo (10) -> raw 34, 2 qualifying cats, bucket 3", () => {
    // Alternative second root: wallet category [10] -> 10 (qualifies). Same raw 34.
    expect(score([githubOauth(), githubAge24(), email(), walletAge24()])).toEqual({
      raw: 34,
      bucket: 3,
    });
  });

  it("free farmer (5 oauth, 2 email, 30 wallet-control, 20 public-key) -> raw 22, bucket 2 ceiling", () => {
    // social-oauth [8,5,4,4,4] -> 8 + floor(5/2)=2 + floor(4/4)=1 + 0 + 0 = 11 (qualifies);
    // email [5,5] -> 5 + floor(5/2)=2 = 7 (NOT qualifying); wallet [2]*30 -> 2 + 1 = 3;
    // attestation [1]*20 -> 1. raw = 11 + 7 + 3 + 1 = 22. Only 1 qualifying category,
    // so bucket 3 (needs 2) is unreachable — capped at bucket 2.
    const oauths = [
      badge("oauth-account", { provider: "github" }), // 8
      badge("oauth-account", { provider: "steam" }), // 5
      badge("oauth-account", { provider: "discord" }), // 4
      badge("oauth-account", { provider: "reddit" }), // 4
      badge("oauth-account", { provider: "hackernews" }), // 4
    ];
    const emails = [email(), emailExact()]; // both weight 5
    const wallets = Array.from({ length: 30 }, () =>
      badge("wallet-control", { chain: "ethereum" }),
    );
    const keys = Array.from({ length: 20 }, (_, i) =>
      badge("public-key", { kind: "pgp", fingerprint: `fp-${i}` }),
    );
    const result = score([...oauths, ...emails, ...wallets, ...keys]);
    expect(result.raw).toBe(22);
    expect(result.bucket).toBe(2);
  });

  it("spending farmer: free farmer + one domain-control (10) -> raw 32, 2 qualifying, bucket 3", () => {
    // Design spec §3.7: adding one cheap domain gives the second qualifying category.
    // 22 + domain 10 = 32; qualifying: social(11) + domain(10) = 2 -> bucket 3.
    const oauths = [
      badge("oauth-account", { provider: "github" }),
      badge("oauth-account", { provider: "steam" }),
      badge("oauth-account", { provider: "discord" }),
      badge("oauth-account", { provider: "reddit" }),
      badge("oauth-account", { provider: "hackernews" }),
    ];
    const emails = [email(), emailExact()];
    const wallets = Array.from({ length: 30 }, () =>
      badge("wallet-control", { chain: "ethereum" }),
    );
    const keys = Array.from({ length: 20 }, (_, i) =>
      badge("public-key", { kind: "pgp", fingerprint: `fp-${i}` }),
    );
    const result = score([...oauths, ...emails, ...wallets, ...keys, domainControl()]);
    expect(result).toEqual({ raw: 32, bucket: 3 });
  });

  it("spending farmer (impl brief §3.7): dev + one domain-control (10) -> bucket 3", () => {
    // Impl brief phrasing of the spending farmer: the dev stack plus a purchased
    // domain -> raw 34, 2 qualifying categories -> bucket 3.
    expect(score([githubOauth(), githubAge24(), email(), domainControl()])).toEqual({
      raw: 34,
      bucket: 3,
    });
  });
});

describe("sybilScore — input hygiene & rule edges (design spec §3.4-§3.5)", () => {
  it("an expired badge is excluded", () => {
    const expired = badge("invite-code", { label: "x" }, { expiresAt: new Date(NOW - 1) });
    // Only the (non-expiring) email counts -> raw 5, bucket 1. The expired invite
    // (weight 12) is dropped, so it does not push the raw up.
    expect(score([expired, email()])).toEqual({ raw: 5, bucket: 1 });
  });

  it("a badge expiring exactly at now is still counted (boundary: < now, not <= now)", () => {
    const atNow = badge("invite-code", { label: "x" }, { expiresAt: new Date(NOW) });
    // expiresAt.getTime() === now is NOT < now, so it is kept. invite [12] -> raw 12;
    // 12 >= b1(5) but < b2(15) -> bucket 1.
    expect(score([atNow])).toEqual({ raw: 12, bucket: 1 });
  });

  it("a non-native-issuer badge is excluded", () => {
    const foreign = badge("invite-code", { label: "x" }, { issuer: "did:web:evil.example" });
    // The imported invite (weight 12) never buys bucket; only the email counts.
    expect(score([foreign, email()])).toEqual({ raw: 5, bucket: 1 });
  });

  it("an unknown badge type contributes 0", () => {
    const unknown = badge("totally-made-up-type", { foo: "bar" });
    expect(score([unknown])).toEqual({ raw: 0, bucket: 0 });
    // ...and does not perturb a real badge alongside it.
    expect(score([unknown, email()])).toEqual({ raw: 5, bucket: 1 });
  });

  it("an oauth-account with no provider falls back to the '*' weight (4), never throws", () => {
    const noProvider = badge("oauth-account", {});
    // Chain degrades to ["*"] -> weight 4; single social category [4] -> 4; raw 4 < b1(5).
    expect(score([noProvider])).toEqual({ raw: 4, bucket: 0 });
  });

  it("the age-over ladder family-collapses to a single contribution (max member)", () => {
    // Holding age-over-16/18/21 (each weight 25) collapses to ONE member of 25, NOT
    // a decayed stack. raw is exactly 25 (25 + 12 + 6 = 43 would be the un-collapsed
    // sum, so asserting raw===25 proves the collapse).
    const ladder = [badge("age-over-16"), badge("age-over-18"), badge("age-over-21")];
    expect(score(ladder)).toEqual({ raw: 25, bucket: 2 });
  });

  it("the residency ladder (country<state<city) family-collapses to its max (city 16)", () => {
    const residency = [
      badge("residency-country", { country: "US" }),
      badge("residency-state", { country: "US", state: "CA" }),
      badge("residency-city", { country: "US", state: "CA", city: "SF" }),
    ];
    // Collapses to one member = max(10,14,16)=16. raw 16 (not 16+7+5). bucket 2.
    expect(score(residency)).toEqual({ raw: 16, bucket: 2 });
  });

  it("a second same-kind badge is decayed: two github oauth (8,8) -> 8 + floor(8/2)=12", () => {
    // Non-family types are each their own member, so a duplicate is halved:
    // [8,8] -> floor(8/1)=8 + floor(8/2)=4 = 12. Proves the floor(w/2) decay math.
    expect(score([githubOauth(), githubOauth()])).toEqual({ raw: 12, bucket: 1 });
  });

  it("geometric decay on three same-category members: [5,5,5] -> 5 + 2 + 1 = 8", () => {
    // Three emails (all category `email`, each its own member): 5 + floor(5/2)=2 +
    // floor(5/4)=1 = 8 (still under the cap of 10). Confirms the decay ladder.
    expect(score([email(), emailExact(), email()]).raw).toBe(8);
  });
});
