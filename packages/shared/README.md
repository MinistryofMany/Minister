# @minister/shared

Badge-type registry and Zod claim schemas for the Minister identity platform. Defines every recognized badge type (slug, label, description, icon key, and a Zod schema for its `credentialSubject` claims), along with lookup helpers. Used by both the Minister server and badge plugins to validate claims before VC issuance and OIDC disclosure.

Part of the **Ministry of Many** project.

## Install

```
pnpm add @minister/shared
```

## Usage

```ts
import { BADGE_TYPES, getBadgeType, knownBadgeTypes, EmailDomainClaims } from "@minister/shared";

// List all registered badge type slugs.
console.log(knownBadgeTypes());
// → ["email-domain", "email-exact", "oauth-account", "residency-country", ...]

// Look up a badge type by slug.
const emailDomain = getBadgeType("email-domain");
if (!emailDomain) throw new Error("unknown badge type");

console.log(emailDomain.label); // "Email domain"
console.log(emailDomain.description); // "Holder controls an email address at the named domain."
console.log(emailDomain.iconKey); // "at-sign"

// Validate plugin-produced claims with the badge type's Zod schema.
const result = emailDomain.schema.safeParse({ domain: "acme.org" });
if (!result.success) {
  console.error(result.error.issues);
}

// You can also import claim schemas directly for typed access.
const parsed = EmailDomainClaims.parse({ domain: "ACME.ORG" });
// → { domain: "acme.org" }  (schema lowercases the domain)

// Access the full registry map directly.
for (const [slug, meta] of Object.entries(BADGE_TYPES)) {
  console.log(slug, meta.label);
}
```

## API

### Registry

| Export               | Purpose                                                          |
| -------------------- | ---------------------------------------------------------------- |
| `BADGE_TYPES`        | `Record<string, BadgeTypeMeta>` - the full slug-to-metadata map. |
| `getBadgeType(slug)` | Returns `BadgeTypeMeta \| undefined` for the given slug.         |
| `knownBadgeTypes()`  | Returns `string[]` of all registered slugs.                      |

### Claim schemas (Zod)

Each schema validates the `credentialSubject` claims for that badge type (the `id` field is excluded - it is added at issuance).

| Export                   | Badge type          | Key fields                                                            |
| ------------------------ | ------------------- | --------------------------------------------------------------------- |
| `EmailDomainClaims`      | `email-domain`      | `domain: string` (lowercase, valid domain)                            |
| `EmailExactClaims`       | `email-exact`       | `email: string` (lowercase email)                                     |
| `OAuthAccountClaims`     | `oauth-account`     | `provider: "github" \| "google" \| "discord"`, `accountId`, `handle?` |
| `ResidencyCountryClaims` | `residency-country` | `country: string` (ISO 3166-1 alpha-2)                                |
| `ResidencyStateClaims`   | `residency-state`   | `country`, `state`                                                    |
| `ResidencyCityClaims`    | `residency-city`    | `country`, `state`, `city`                                            |
| `InviteCodeClaims`       | `invite-code`       | `label: string` (campaign name, not the code itself)                  |
| `TlsnAttestationClaims`  | `tlsn-attestation`  | `domain`, `claim` (passthrough for additional fields)                 |

Age-over badge types (`age-over-16` through `age-over-65`) are registered for each value in `AGE_THRESHOLDS` with schema `{ threshold: <literal> }`.

### Constants

| Export            | Purpose                                             |
| ----------------- | --------------------------------------------------- |
| `OAUTH_PROVIDERS` | `readonly ["github", "google", "discord"]`          |
| `AGE_THRESHOLDS`  | `readonly [16, 18, 21, 25, 30, 35, 40, 45, 55, 65]` |

### Types

`BadgeTypeMeta<TClaims>`, `EmailDomainClaims`, `EmailExactClaims`, `OAuthAccountClaims`, `ResidencyCountryClaims`, `ResidencyStateClaims`, `ResidencyCityClaims`, `InviteCodeClaims`, `TlsnAttestationClaims`, `AgeThreshold`

## License

Copyright (c) 2026 AtHeartEngineering LLC, authored by AtHeartEngineer.

Licensed under either of **MIT** ([LICENSE-MIT](./LICENSE-MIT)) or **Apache License 2.0** ([LICENSE-APACHE](./LICENSE-APACHE)) at your option.
