import { describe, expect, it } from "vitest";

import {
  AGE_THRESHOLDS,
  BADGE_TYPES,
  EmailDomainClaims,
  EmailExactClaims,
  OAuthAccountClaims,
  AccountAgeClaims,
  TwoFactorClaims,
  SocialFollowingClaims,
  ACCOUNT_AGE_MONTHS,
  FOLLOWERS_BUCKETS,
  ResidencyCityClaims,
  ResidencyCountryClaims,
  ResidencyStateClaims,
  TlsnAttestationClaims,
  getBadgeType,
  knownBadgeTypes,
} from "./badge-types";

describe("registry shape", () => {
  it("includes the core badge types from CLAUDE.md", () => {
    for (const slug of [
      "email-domain",
      "email-exact",
      "oauth-account",
      "account-age",
      "two-factor",
      "social-following",
      "residency-country",
      "residency-state",
      "residency-city",
      "tlsn-attestation",
    ]) {
      expect(getBadgeType(slug), `expected ${slug} in registry`).toBeDefined();
    }
  });

  it("includes one age-over-N entry per threshold", () => {
    for (const n of AGE_THRESHOLDS) {
      const meta = getBadgeType(`age-over-${n}`);
      expect(meta, `expected age-over-${n}`).toBeDefined();
      expect(meta?.label).toContain(String(n));
    }
  });

  it("knownBadgeTypes returns a stable sorted-ish list of all slugs", () => {
    const slugs = knownBadgeTypes();
    expect(slugs.length).toBe(Object.keys(BADGE_TYPES).length);
    for (const slug of slugs) {
      expect(BADGE_TYPES[slug]).toBeDefined();
    }
  });

  it("every registry entry's type matches its key", () => {
    for (const [slug, meta] of Object.entries(BADGE_TYPES)) {
      expect(meta.type).toBe(slug);
    }
  });
});

describe("EmailDomainClaims schema", () => {
  it("accepts a normal domain", () => {
    expect(EmailDomainClaims.parse({ domain: "example.com" })).toEqual({
      domain: "example.com",
    });
  });

  it("lowercases the domain", () => {
    expect(EmailDomainClaims.parse({ domain: "Example.COM" })).toEqual({
      domain: "example.com",
    });
  });

  it("rejects strings that look like email addresses", () => {
    expect(() => EmailDomainClaims.parse({ domain: "alice@example.com" })).toThrow();
  });

  it("rejects unqualified domains", () => {
    expect(() => EmailDomainClaims.parse({ domain: "localhost" })).toThrow();
  });
});

describe("EmailExactClaims schema", () => {
  it("accepts a valid email and lowercases it", () => {
    expect(EmailExactClaims.parse({ email: "Alice@Example.COM" })).toEqual({
      email: "alice@example.com",
    });
  });

  it("rejects malformed input", () => {
    expect(() => EmailExactClaims.parse({ email: "not-an-email" })).toThrow();
  });
});

describe("OAuthAccountClaims schema", () => {
  it("accepts a known provider with an accountId", () => {
    const parsed = OAuthAccountClaims.parse({
      provider: "github",
      accountId: "123",
    });
    expect(parsed.provider).toBe("github");
    expect(parsed.accountId).toBe("123");
    expect(parsed.handle).toBeUndefined();
  });

  it("accepts an optional handle", () => {
    expect(
      OAuthAccountClaims.parse({
        provider: "github",
        accountId: "1",
        handle: "octocat",
      }),
    ).toEqual({ provider: "github", accountId: "1", handle: "octocat" });
  });

  it("rejects unknown providers", () => {
    expect(() => OAuthAccountClaims.parse({ provider: "myspace", accountId: "x" })).toThrow();
  });
});

describe("AccountAgeClaims schema (github-derived)", () => {
  it("accepts each declared month threshold", () => {
    for (const m of ACCOUNT_AGE_MONTHS) {
      expect(AccountAgeClaims.parse({ provider: "github", olderThanMonths: m })).toEqual({
        provider: "github",
        olderThanMonths: m,
      });
    }
  });
  it("rejects an off-grid month value (raw age must never leak)", () => {
    expect(() => AccountAgeClaims.parse({ provider: "github", olderThanMonths: 30 })).toThrow();
  });
  it("rejects unknown keys (no raw created_at smuggled into a VC)", () => {
    expect(() =>
      AccountAgeClaims.parse({ provider: "github", olderThanMonths: 12, createdAt: "2020" }),
    ).toThrow();
  });
});

describe("TwoFactorClaims schema (github-derived)", () => {
  it("accepts a bare provider", () => {
    expect(TwoFactorClaims.parse({ provider: "github" })).toEqual({ provider: "github" });
  });
  it("rejects any extra field", () => {
    expect(() => TwoFactorClaims.parse({ provider: "github", enabled: true })).toThrow();
  });
});

describe("SocialFollowingClaims schema (github-derived)", () => {
  it("accepts each declared follower bucket", () => {
    for (const n of FOLLOWERS_BUCKETS) {
      expect(SocialFollowingClaims.parse({ provider: "github", followersAtLeast: n })).toEqual({
        provider: "github",
        followersAtLeast: n,
      });
    }
  });
  it("rejects an off-grid count (exact count must never leak)", () => {
    expect(() =>
      SocialFollowingClaims.parse({ provider: "github", followersAtLeast: 742 }),
    ).toThrow();
  });
});

describe("residency schemas", () => {
  it("country requires ISO 3166-1 alpha-2", () => {
    expect(ResidencyCountryClaims.parse({ country: "US" }).country).toBe("US");
    expect(() => ResidencyCountryClaims.parse({ country: "usa" })).toThrow();
    expect(() => ResidencyCountryClaims.parse({ country: "U" })).toThrow();
  });

  it("state requires country + state", () => {
    expect(ResidencyStateClaims.parse({ country: "US", state: "MD" })).toEqual({
      country: "US",
      state: "MD",
    });
    expect(() => ResidencyStateClaims.parse({ country: "US" })).toThrow();
  });

  it("city requires country + state + city", () => {
    expect(
      ResidencyCityClaims.parse({
        country: "US",
        state: "MD",
        city: "Baltimore",
      }),
    ).toEqual({ country: "US", state: "MD", city: "Baltimore" });
    expect(() => ResidencyCityClaims.parse({ country: "US", state: "MD" })).toThrow();
  });
});

describe("age-over schemas", () => {
  it("each entry accepts only its own threshold value", () => {
    const meta = getBadgeType("age-over-21");
    expect(meta).toBeDefined();
    expect(meta!.schema.parse({ threshold: 21 })).toEqual({ threshold: 21 });
    expect(() => meta!.schema.parse({ threshold: 18 })).toThrow();
  });
});

describe("TlsnAttestationClaims schema (strict)", () => {
  it("requires domain + claim", () => {
    const parsed = TlsnAttestationClaims.parse({
      domain: "id.me",
      claim: "age-over-18",
    });
    expect(parsed.domain).toBe("id.me");
    expect(parsed.claim).toBe("age-over-18");
  });

  it("rejects missing required fields", () => {
    expect(() => TlsnAttestationClaims.parse({ domain: "id.me" })).toThrow();
  });

  it("rejects unknown keys (no .passthrough() — unvalidated keys must never reach a signed VC)", () => {
    expect(() =>
      TlsnAttestationClaims.parse({
        domain: "id.me",
        claim: "age-over-18",
        extra: "custom field",
      }),
    ).toThrow();
  });
});
