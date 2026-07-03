import { z } from "zod";

// Badge type registry. Each entry pairs a stable slug with:
//   - display metadata (label, description, icon key)
//   - a Zod schema for the credentialSubject claims (excluding `id`,
//     which is always the user's did:web URL and is added at issuance)
//
// The schema is the source of truth for what a badge of this type
// "means" — plugins produce claims that pass `.parse()`, and the OIDC
// provider validates badges against this schema before disclosure.

// Icon keys actually referenced by the badge registry. Typing `iconKey`
// as this union (rather than `string`) lets the UI's icon map assert
// exhaustiveness: adding a badge type with an unmapped icon fails the
// typecheck instead of silently degrading to a fallback glyph.
export type BadgeIconKey =
  "at-sign" | "cake" | "globe" | "link" | "mail" | "map-pin" | "shield-check" | "ticket" | "users";

export interface BadgeTypeMeta<TClaims = unknown> {
  type: string;
  label: string;
  description: string;
  iconKey: BadgeIconKey;
  // Zod schema for the credentialSubject claims (without the `id`
  // field, which is always present and is added by issueVc).
  schema: z.ZodType<TClaims>;
}

// ---------------------------------------------------------------------------
// Individual badge types
// ---------------------------------------------------------------------------

export const EmailDomainClaims = z.object({
  domain: z
    .string()
    .min(1)
    .toLowerCase()
    .regex(/^[a-z0-9.-]+\.[a-z]{2,}$/u, "Not a valid domain"),
});
export type EmailDomainClaims = z.infer<typeof EmailDomainClaims>;

export const EmailExactClaims = z.object({
  email: z.string().email().toLowerCase(),
});
export type EmailExactClaims = z.infer<typeof EmailExactClaims>;

export const OAUTH_PROVIDERS = ["github", "google", "discord"] as const;
export const OAuthAccountClaims = z.object({
  provider: z.enum(OAUTH_PROVIDERS),
  accountId: z.string().min(1),
  handle: z.string().min(1).optional(),
});
export type OAuthAccountClaims = z.infer<typeof OAuthAccountClaims>;

// ---------------------------------------------------------------------------
// GitHub-derived (provider-generic) badge types
//
// These attest facts about a connected OAuth account without leaking the
// underlying PII. The provider is one of OAUTH_PROVIDERS; today only the
// github plugin issues them, but the claim shapes stay provider-generic so
// a future Google/Discord plugin can reuse them.
// ---------------------------------------------------------------------------

// Account age — a COARSE "older than N months" threshold, never the exact
// creation date. The plugin picks the highest bucket the account satisfies,
// so disclosing this reveals only a lower bound. Anti-sybil: a fresh account
// can't fake a multi-year lower bound.
export const ACCOUNT_AGE_MONTHS = [12, 24, 36, 60] as const;
export type AccountAgeMonths = (typeof ACCOUNT_AGE_MONTHS)[number];
export const AccountAgeClaims = z
  .object({
    provider: z.enum(OAUTH_PROVIDERS),
    olderThanMonths: z.union([z.literal(12), z.literal(24), z.literal(36), z.literal(60)]),
  })
  .strict();
export type AccountAgeClaims = z.infer<typeof AccountAgeClaims>;

// Social following — a COARSE "at least N followers" bucket, never the exact
// count. Followers are a stronger anti-sybil / reputation signal than repo
// count (they need social proof, not just `git init`). Highest bucket wins.
export const FOLLOWERS_BUCKETS = [10, 50, 100, 500, 1000] as const;
export type FollowersBucket = (typeof FOLLOWERS_BUCKETS)[number];
export const SocialFollowingClaims = z
  .object({
    provider: z.enum(OAUTH_PROVIDERS),
    followersAtLeast: z.union([
      z.literal(10),
      z.literal(50),
      z.literal(100),
      z.literal(500),
      z.literal(1000),
    ]),
  })
  .strict();
export type SocialFollowingClaims = z.infer<typeof SocialFollowingClaims>;

export const AGE_THRESHOLDS = [16, 18, 21, 25, 30, 35, 40, 45, 55, 65] as const;
export type AgeThreshold = (typeof AGE_THRESHOLDS)[number];

const AgeOverClaimsFor = (threshold: AgeThreshold) =>
  z.object({
    threshold: z.literal(threshold),
  });

const COUNTRY_RE = /^[A-Z]{2}$/u; // ISO 3166-1 alpha-2
export const ResidencyCountryClaims = z.object({
  country: z.string().regex(COUNTRY_RE),
});
export const ResidencyStateClaims = z.object({
  country: z.string().regex(COUNTRY_RE),
  state: z.string().min(1),
});
export const ResidencyCityClaims = z.object({
  country: z.string().regex(COUNTRY_RE),
  state: z.string().min(1),
  city: z.string().min(1),
});
export type ResidencyCountryClaims = z.infer<typeof ResidencyCountryClaims>;
export type ResidencyStateClaims = z.infer<typeof ResidencyStateClaims>;
export type ResidencyCityClaims = z.infer<typeof ResidencyCityClaims>;

// The label identifies the invite campaign/cohort, not the code — the
// code string itself must never appear in claims, since multi-use codes
// remain redeemable after a holder discloses the VC.
export const InviteCodeClaims = z.object({
  label: z.string().min(1),
});
export type InviteCodeClaims = z.infer<typeof InviteCodeClaims>;

// Generic TLSNotary attestation — domain + a single structured claim.
// Strict (no `.passthrough()`): the issuance path signs whatever this
// schema returns into the credentialSubject, so unknown keys must be
// rejected rather than smuggled into a signed VC. Specific plugins
// (id.me, github, etc.) refine this with their own VC types in Stage 8+.
export const TlsnAttestationClaims = z
  .object({
    domain: z.string().min(1),
    claim: z.string().min(1),
  })
  .strict();
export type TlsnAttestationClaims = z.infer<typeof TlsnAttestationClaims>;

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

function ageOverEntry(threshold: AgeThreshold): BadgeTypeMeta {
  return {
    type: `age-over-${threshold}`,
    label: `Age over ${threshold}`,
    description: `Holder has proven they are over ${threshold} years old.`,
    iconKey: "cake",
    schema: AgeOverClaimsFor(threshold),
  };
}

export const BADGE_TYPES: Record<string, BadgeTypeMeta> = {
  "email-domain": {
    type: "email-domain",
    label: "Email domain",
    description: "Holder controls an email address at the named domain.",
    iconKey: "at-sign",
    schema: EmailDomainClaims,
  },
  "email-exact": {
    type: "email-exact",
    label: "Email address",
    description:
      "Holder controls the exact email address. Less private than email-domain — opt-in.",
    iconKey: "mail",
    schema: EmailExactClaims,
  },
  "oauth-account": {
    type: "oauth-account",
    label: "Connected account",
    description: "Holder controls a third-party account (GitHub, Google, etc).",
    iconKey: "link",
    schema: OAuthAccountClaims,
  },
  "account-age": {
    type: "account-age",
    label: "Account age",
    description: "Holder's connected account is at least the stated number of months old.",
    iconKey: "cake",
    schema: AccountAgeClaims,
  },
  "social-following": {
    type: "social-following",
    label: "Following",
    description: "Holder's connected account has at least the stated number of followers.",
    iconKey: "users",
    schema: SocialFollowingClaims,
  },
  "residency-country": {
    type: "residency-country",
    label: "Country of residence",
    description: "Holder is a resident of the named country.",
    iconKey: "globe",
    schema: ResidencyCountryClaims,
  },
  "residency-state": {
    type: "residency-state",
    label: "State/region of residence",
    description: "Holder is a resident of the named state or region.",
    iconKey: "map-pin",
    schema: ResidencyStateClaims,
  },
  "residency-city": {
    type: "residency-city",
    label: "City of residence",
    description: "Holder is a resident of the named city.",
    iconKey: "map-pin",
    schema: ResidencyCityClaims,
  },
  "invite-code": {
    type: "invite-code",
    label: "Invited",
    description:
      "Holder redeemed an invite code issued by a Minister admin for the named campaign.",
    iconKey: "ticket",
    schema: InviteCodeClaims,
  },
  "tlsn-attestation": {
    type: "tlsn-attestation",
    label: "TLSNotary attestation",
    description:
      "Generic TLSNotary attestation. Specific plugins refine this with their own claim shapes.",
    iconKey: "shield-check",
    schema: TlsnAttestationClaims,
  },
  ...Object.fromEntries(AGE_THRESHOLDS.map((t) => [`age-over-${t}`, ageOverEntry(t)] as const)),
};

export function getBadgeType(slug: string): BadgeTypeMeta | undefined {
  return BADGE_TYPES[slug];
}

export function knownBadgeTypes(): string[] {
  return Object.keys(BADGE_TYPES);
}
