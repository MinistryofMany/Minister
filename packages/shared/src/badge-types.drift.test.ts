import { describe, expect, it } from "vitest";

import { BADGE_TYPES, knownBadgeTypes } from "./badge-types";

// ===========================================================================
// Cross-package drift gate — PROVIDER SIDE (mirror of the SDK's
// minister-client/src/badges/drift.test.ts).
//
// The SDK's badge registry is a hand-transcribed MIRROR of this provider-side
// registry, pinned there against a frozen EXPECTED table. That gate is
// one-sided: it only trips when someone edits the SDK. A change made HERE (a new
// slug, a flipped `sybilResistance`, a loosened/tightened schema, a changed
// `credentialType`) failed NO test in either repo until this file existed.
//
// This is the SAME frozen contract, committed on BOTH sides (the `prf-vectors`
// pattern): each repo now trips its own suite on any registry change, so drift
// is caught on whichever side moves first — silent RP badge rejection (strict
// drift fails closed) or silent claim stripping (lax drift) can no longer ship
// unnoticed. Update BOTH tables in the same change when the registry changes.
// ===========================================================================

type Sybil = "none" | "weak" | "moderate";

interface Expected {
  credentialType: string;
  sybilResistance: Sybil;
  // A claims object that MUST parse for this type.
  sample: Record<string, unknown>;
  // z.object(...).strict() rejects unknown keys; plain z.object strips them.
  strict: boolean;
}

const AGE_THRESHOLDS = [16, 18, 21, 25, 30, 35, 40, 45, 55, 65] as const;

// Byte-for-byte identical to the SDK's EXPECTED (drift.test.ts). The
// `credentialType` here is NOT stored on BadgeTypeMeta (the provider derives the
// VC `type[]` entry elsewhere), so it is pinned only as documentation of the
// shared contract; the load-bearing assertions are the slug set, strictness,
// sybilResistance, and sample validity.
const EXPECTED: Record<string, Expected> = {
  "email-domain": {
    credentialType: "MinisterEmailDomainCredential",
    sybilResistance: "weak",
    sample: { domain: "example.com" },
    strict: false,
  },
  "email-exact": {
    credentialType: "MinisterEmailExactCredential",
    sybilResistance: "weak",
    sample: { email: "user@example.com" },
    strict: false,
  },
  "domain-control": {
    credentialType: "MinisterDomainControlCredential",
    sybilResistance: "moderate",
    sample: { domain: "example.com" },
    strict: false,
  },
  "oauth-account": {
    credentialType: "MinisterOauthAccountCredential",
    sybilResistance: "weak",
    sample: { provider: "github", handle: "octocat" },
    strict: false,
  },
  "account-age": {
    credentialType: "MinisterAccountAgeCredential",
    sybilResistance: "moderate",
    sample: { provider: "github", olderThanMonths: 24 },
    strict: true,
  },
  "social-following": {
    credentialType: "MinisterSocialFollowingCredential",
    sybilResistance: "moderate",
    sample: { provider: "github", followersAtLeast: 100 },
    strict: true,
  },
  "residency-country": {
    credentialType: "MinisterResidencyCountryCredential",
    sybilResistance: "none",
    sample: { country: "US" },
    strict: false,
  },
  "residency-state": {
    credentialType: "MinisterResidencyStateCredential",
    sybilResistance: "none",
    sample: { country: "US", state: "California" },
    strict: false,
  },
  "residency-city": {
    credentialType: "MinisterResidencyCityCredential",
    sybilResistance: "none",
    sample: { country: "US", state: "California", city: "San Francisco" },
    strict: false,
  },
  "invite-code": {
    credentialType: "MinisterInviteCodeCredential",
    sybilResistance: "none",
    sample: { label: "spring-2026" },
    strict: false,
  },
  "tlsn-attestation": {
    credentialType: "MinisterTlsnAttestationCredential",
    sybilResistance: "none",
    sample: { domain: "id.me", claim: "verified" },
    strict: true,
  },
  "wallet-control": {
    credentialType: "MinisterWalletControlCredential",
    sybilResistance: "weak",
    sample: { chain: "ethereum" },
    strict: true,
  },
  "wallet-age": {
    credentialType: "MinisterWalletAgeCredential",
    sybilResistance: "moderate",
    sample: { chain: "ethereum", olderThanMonths: 24 },
    strict: true,
  },
  "onchain-event": {
    credentialType: "MinisterOnchainEventCredential",
    sybilResistance: "moderate",
    sample: { event: "eth2-genesis-depositor" },
    strict: true,
  },
  "public-key": {
    credentialType: "MinisterPublicKeyCredential",
    sybilResistance: "weak",
    sample: { kind: "pgp", fingerprint: "AABBCCDD", algorithm: "ed25519" },
    strict: true,
  },
  ...Object.fromEntries(
    AGE_THRESHOLDS.map((t) => [
      `age-over-${t}`,
      {
        credentialType: `MinisterAgeOver${t}Credential`,
        sybilResistance: "none" as Sybil,
        sample: { threshold: t },
        strict: false,
      },
    ]),
  ),
};

// Reserved cross-cutting VC-metadata keys the disclosure path stamps under the
// signature (issue.ts) and the SDK strips before schema.parse (verify-badge.ts).
// No per-type claim schema may DECLARE one of these as a field: a schema-declared
// `nullifier` would be silently eaten SDK-side (and rejected by a strict schema
// requiring it), and a schema-declared `id` would override the pairwise subject
// and fail every RP holder-binding check. Fail-closed, but a confusing outage
// from an innocent-looking registry addition — forbid it structurally here.
const RESERVED_KEYS = ["id", "issuanceMonth", "nullifier"] as const;

describe("badge registry drift (frozen contract, provider side)", () => {
  it("has the exact same slug set as the canonical contract", () => {
    expect(new Set(knownBadgeTypes())).toEqual(new Set(Object.keys(EXPECTED)));
  });

  for (const [slug, exp] of Object.entries(EXPECTED)) {
    describe(slug, () => {
      it("matches sybilResistance", () => {
        const def = BADGE_TYPES[slug];
        expect(def, `registry is missing badge type ${slug}`).toBeDefined();
        expect(def!.sybilResistance).toBe(exp.sybilResistance);
      });

      it("accepts the canonical sample claims", () => {
        expect(() => BADGE_TYPES[slug]!.schema.parse(exp.sample)).not.toThrow();
      });

      it(`is ${exp.strict ? "STRICT (rejects)" : "lax (strips)"} on an unknown key`, () => {
        const schema = BADGE_TYPES[slug]!.schema;
        const withExtra = { ...exp.sample, __driftProbe: 1 };
        if (exp.strict) {
          expect(() => schema.parse(withExtra)).toThrow();
        } else {
          const parsed = schema.parse(withExtra) as Record<string, unknown>;
          expect(parsed).not.toHaveProperty("__driftProbe");
        }
      });

      // Reserved-key guard: no schema may declare/echo a reserved metadata key.
      it("never echoes a reserved metadata key back through its schema", () => {
        const schema = BADGE_TYPES[slug]!.schema;
        const withReserved = {
          ...exp.sample,
          id: "did:web:evil:u:attacker",
          issuanceMonth: "1999-01",
          nullifier: "mnv1:SMUGGLED",
        };
        if (exp.strict) {
          // A strict schema rejects the unknown reserved keys outright.
          expect(() => schema.parse(withReserved)).toThrow();
        } else {
          // A lax schema strips them — none may survive the parse.
          const parsed = schema.parse(withReserved) as Record<string, unknown>;
          for (const key of RESERVED_KEYS) {
            expect(parsed, `${slug} echoed reserved key ${key}`).not.toHaveProperty(key);
          }
        }
      });
    });
  }
});
