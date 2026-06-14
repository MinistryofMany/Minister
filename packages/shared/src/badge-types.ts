import { z } from "zod";

// Badge type registry. Each entry pairs a stable slug with:
//   - display metadata (label, description, icon key)
//   - a Zod schema for the credentialSubject claims (excluding `id`,
//     which is always the user's did:web URL and is added at issuance)
//
// The schema is the source of truth for what a badge of this type
// "means" — plugins produce claims that pass `.parse()`, and the OIDC
// provider validates badges against this schema before disclosure.

export interface BadgeTypeMeta<TClaims = unknown> {
  type: string;
  label: string;
  description: string;
  iconKey: string;
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

// Generic TLSNotary attestation — domain + arbitrary structured claim.
// Tightened by specific plugins (id.me, github, etc.) in their own VC
// types; this catch-all lets us issue ad-hoc proofs in Stage 8+.
export const TlsnAttestationClaims = z
  .object({
    domain: z.string().min(1),
    claim: z.string().min(1),
  })
  .passthrough();
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
  ...Object.fromEntries(
    AGE_THRESHOLDS.map((t) => [`age-over-${t}`, ageOverEntry(t)] as const),
  ),
};

export function getBadgeType(slug: string): BadgeTypeMeta | undefined {
  return BADGE_TYPES[slug];
}

export function knownBadgeTypes(): string[] {
  return Object.keys(BADGE_TYPES);
}
