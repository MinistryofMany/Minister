// Attribute-value allowlist for badge statistics (design spec §6, phase-2 impl
// brief §2). A privacy control, not a convenience: the public transparency page
// must never leak a rare attribute value. k-suppression alone is insufficient —
// the mere EXISTENCE of a row like `email-domain=corp.example.com` reveals that
// someone at that org uses Minister, which no count-suppression can fix.
//
// So the recompute materializes/publishes attribute distributions ONLY for keys
// whose value space is a closed enum, listed here. This same allowlist gates
// cohort-def validation (cohort-filter.ts) — a def naming a non-allowlisted key
// is rejected, which ALSO closes a JSON-key injection hole: keys are only ever
// these code-owned literals, never free-form input interpolated into SQL.
//
// The map lives in code, keyed by the registry, and every listed key is
// re-checked at module load against the closed publishable set (and against the
// forbidden set) so a typo or a forbidden key cannot slip in.

import { AGE_THRESHOLDS, knownBadgeTypes } from "@minister/shared";

// The closed-enum keys whose value space is small and non-identifying. Only
// these may ever be published (design spec §6). Anything not here is dropped.
export const PUBLISHABLE_KEYS = [
  "provider",
  "olderThanMonths",
  "followersAtLeast",
  "chain",
  "event",
  "threshold",
  "kind",
  "country",
] as const;
export type PublishableKey = (typeof PUBLISHABLE_KEYS)[number];

// Keys that MUST NEVER be materialized/published — the existence of a row keyed
// on one of these leaks an individual or an org (design spec §6). Held as an
// explicit denylist so the module-load self-check can assert the per-type map
// never references one (defense in depth beyond "not in PUBLISHABLE_KEYS").
export const FORBIDDEN_KEYS = [
  "email",
  "domain",
  "fingerprint",
  "state",
  "city",
  "handle",
] as const;

const PUBLISHABLE_SET: ReadonlySet<string> = new Set(PUBLISHABLE_KEYS);
const FORBIDDEN_SET: ReadonlySet<string> = new Set(FORBIDDEN_KEYS);

// The per-type allowlist: which allowlisted keys are valid for which badge type,
// derived from each type's claim schema (packages/shared/src/badge-types.ts)
// intersected with PUBLISHABLE_KEYS.
//
// Deliberate omissions (type-level total only, no attribute rows):
//   * email-domain / email-exact / domain-control — only `domain`/`email` keys
//     (both forbidden).
//   * residency-state / residency-city — even though their schema carries
//     `country` (which is publishable for residency-COUNTRY), publishing a
//     state/city cohort's attribute rows is disallowed by the brief: their
//     EXISTENCE at finer granularity is identifying, so only the type-level
//     total may show. They get NO attribute keys here.
//   * invite-code (`label`), tlsn-attestation (`domain`/`claim`),
//     public-key (`fingerprint`/`algorithm` forbidden; only `kind` survives).
const ALLOWLISTED_KEYS_BY_TYPE: Record<string, readonly PublishableKey[]> = {
  "oauth-account": ["provider"],
  "account-age": ["provider", "olderThanMonths"],
  "social-following": ["provider", "followersAtLeast"],
  "residency-country": ["country"],
  "wallet-control": ["chain"],
  "wallet-age": ["chain", "olderThanMonths"],
  "onchain-event": ["event"],
  "public-key": ["kind"],
  // Every age-over-N type publishes its single `threshold` enum.
  ...Object.fromEntries(AGE_THRESHOLDS.map((t) => [`age-over-${t}`, ["threshold"] as const])),
};

// Module-load self-check (fail-loud on a bad edit): every type is in the
// registry, every listed key is publishable, and no forbidden key is ever
// referenced. A drift here is a code bug, not a runtime condition.
(function assertAllowlistIntegrity(): void {
  const known = new Set(knownBadgeTypes());
  for (const [type, keys] of Object.entries(ALLOWLISTED_KEYS_BY_TYPE)) {
    if (!known.has(type)) {
      throw new Error(`stats-allowlist: unknown badge type "${type}" (not in the registry)`);
    }
    for (const key of keys) {
      if (FORBIDDEN_SET.has(key)) {
        throw new Error(`stats-allowlist: forbidden key "${key}" listed for type "${type}"`);
      }
      if (!PUBLISHABLE_SET.has(key)) {
        throw new Error(`stats-allowlist: non-publishable key "${key}" listed for type "${type}"`);
      }
    }
  }
})();

/**
 * Is `key` an allowlisted (publishable) attribute key for `type`? Fail-closed:
 * an unknown type, or a key not explicitly listed for that type, is rejected.
 * Used by BOTH the recompute (which keys to materialize) and cohort-def
 * validation (reject a def referencing a non-allowlisted key). The result is
 * always one of the code-owned literal keys, never free-form input.
 */
export function isAllowlistedKey(type: string, key: string): boolean {
  return ALLOWLISTED_KEYS_BY_TYPE[type]?.includes(key as PublishableKey) ?? false;
}

/** The allowlisted keys for a type (empty for a type-level-total-only type). */
export function allowlistedKeysFor(type: string): readonly PublishableKey[] {
  return ALLOWLISTED_KEYS_BY_TYPE[type] ?? [];
}

/** Every (type, key) pair the recompute should materialize attribute rows for. */
export function allowlistedTypeKeyPairs(): Array<{ type: string; key: PublishableKey }> {
  const pairs: Array<{ type: string; key: PublishableKey }> = [];
  for (const [type, keys] of Object.entries(ALLOWLISTED_KEYS_BY_TYPE)) {
    for (const key of keys) pairs.push({ type, key });
  }
  return pairs;
}
