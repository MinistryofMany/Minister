import { BADGE_TYPES } from "@minister/shared";
import { ministerCredentialType } from "@minister/vc";

// Disclosure-time claims sanitizer for reMintVc.
//
// A stored badge VC is re-minted at every disclosure (OIDC id_token, share
// link). reMintVc preserves claim values verbatim by default — so a VC issued
// under an OLDER schema keeps disclosing whatever it was signed with, even after
// the schema drops a field. The concrete hazard: pre-Phase-1 oauth-account VCs
// carried the raw github `accountId` (the Sybil anchor); without this hook they
// would re-disclose it to every relying party after deploy, and the SDK strip is
// cosmetic (the RP receives the raw vcJwt regardless).
//
// This re-parses the preserved claims through the CURRENT badge-type schema
// before re-signing. For oauth-account the schema is non-strict, so a stray
// `accountId` is dropped and the re-minted VC carries only the current shape —
// making anchor retroactivity CODE-enforced, not a remembered runbook step.
//
// credentialType -> current Zod claim schema, built once from the shared registry.
const SCHEMA_BY_CREDENTIAL_TYPE = new Map(
  Object.values(BADGE_TYPES).map(
    (meta) => [ministerCredentialType(meta.type), meta.schema] as const,
  ),
);

// Re-parse `claims` (already stripped of `id`/`issuanceMonth` by reMintVc)
// through the current schema for the VC's type. An unknown type passes through
// unchanged (a foreign/future type this deploy cannot parse is never silently
// mangled). A parse failure propagates: the disclosure call sites treat a
// reMint throw as "do not disclose this badge", which is the fail-closed posture
// we want for a claim set the current schema rejects.
export function sanitizeDisclosedClaims(
  claims: Record<string, unknown>,
  vcType: string[],
): Record<string, unknown> {
  for (const t of vcType) {
    const schema = SCHEMA_BY_CREDENTIAL_TYPE.get(t);
    if (schema) {
      return schema.parse(claims) as Record<string, unknown>;
    }
  }
  return claims;
}
