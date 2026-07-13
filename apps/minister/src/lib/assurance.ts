// Assurance knobs — the single, tunable source of truth for both
// authentication assurance (AAL, on sessions/credentials) and identity
// assurance (IAL, on badges, used as recovery weight). Pure and
// side-effect-free so it imports cleanly from edge config, server
// actions, and tests alike. The numbers here are the levers you turn
// (see DESIGNDECISIONS #3, #5, #6, #7); nothing else encodes them.

// ---------------------------------------------------------------------------
// Authentication assurance level (NIST 800-63B, numeric for clean `>= floor`)
// ---------------------------------------------------------------------------
// 0 = none / public, 1 = single-factor (magic link, recovery code),
// 2 = phishing-resistant (passkey, paired TOTP).
export type Aal = 0 | 1 | 2;

// AAL a freshly-authenticated credential of each kind confers. Passkey is
// phishing-resistant (AAL2); a magic link is inbox-bound single-factor
// (AAL1); a recovery code is a single-use single factor (AAL1, and the
// caller additionally flags the session `recovered`); TOTP is AAL2 once
// paired (the table lists it so the seam exists — see DESIGNDECISIONS #14).
export function aalForCredential(kind: "passkey" | "email" | "recovery-code" | "totp"): Aal {
  switch (kind) {
    case "passkey":
      return 2;
    case "totp":
      return 2;
    case "email":
      return 1;
    case "recovery-code":
      return 1;
  }
}

// ---------------------------------------------------------------------------
// Lifecycle / recovery constants
// ---------------------------------------------------------------------------

// A newly added email/passkey can sign in but cannot mutate other
// credentials or start recovery/merge until this window passes — long
// enough that the "a credential was added" notification reaches a human
// who is traveling/asleep before the new credential gains power.
// (DESIGNDECISIONS #5.)
export const CREDENTIAL_QUARANTINE_MS = 72 * 60 * 60 * 1000;

// Donor account is tombstoned on merge and hard-deleted after this window;
// the merge is reversible until then. (DESIGNDECISIONS #13.)
export const MERGE_REVERSAL_DAYS = 7;

// Recovery codes generated per batch. Regenerating deletes unused rows.
// (DESIGNDECISIONS #6.)
export const RECOVERY_CODE_COUNT = 10;

// Weighted-badge recovery succeeds once accumulated weight reaches this.
// Calibrated so recovery is at least as hard as the front door: one
// gov-doc proof (IAL3) clears it alone; low-IAL factors are near-worthless
// in aggregate (it takes 5+ OAuth links). (DESIGNDECISIONS #7.)
export const RECOVERY_THRESHOLD = 100;

// ---------------------------------------------------------------------------
// Identity assurance level (IAL) -> weight
// ---------------------------------------------------------------------------
// Per-IAL recovery weight. A badge's IAL maps here for the *baseline*
// weight; specific (type, provenance) pairs can override below
// (e.g. github/google OAuth outweighs the bare IAL1 baseline). Keyed by
// the IAL string stored on Badge.assuranceLevel. (DESIGNDECISIONS #7.)
export const BADGE_ASSURANCE_WEIGHT: Record<string, number> = {
  IAL0: 0,
  IAL1: 15,
  IAL2: 60,
  IAL3: 100,
};

// Badge type -> IAL. tlsn-attestation is gov-doc grade (IAL3); age/residency
// proofs are gov-doc-backed (IAL2); OAuth and email proofs are single
// real-world-account checks (IAL1); invite-code proves nothing about a
// person (IAL0). Unknown types default to IAL1 (a conservative middle —
// non-zero so a new type still helps, but never gov-doc strength).
export function assuranceLevelFor(badgeType: string, _provenance?: string): string {
  if (badgeType === "tlsn-attestation") return "IAL3";
  if (badgeType.startsWith("age-over") || badgeType.startsWith("residency")) return "IAL2";
  if (badgeType === "oauth-account") return "IAL1";
  if (badgeType === "email-domain" || badgeType === "email-exact") return "IAL1";
  if (badgeType === "invite-code") return "IAL0";
  return "IAL1";
}

// Per-type recovery weight overrides. These deviate from the bare IAL
// baseline so the scoring reflects how hard a credential is to forge or for
// an attacker to *also* hold: github/google OAuth (20) outweighs the IAL1
// baseline, while discord/steam-class OAuth (10) sits below it. Email proofs
// land at 15 (the IAL1 baseline). Keys with a function pick by provenance.
// (DESIGNDECISIONS #7.)
const OAUTH_DEFAULT_WEIGHT = 20;
const OAUTH_LOW_PROVENANCE = new Set(["discord", "steam"]);
const OAUTH_LOW_WEIGHT = 10;

const RECOVERY_WEIGHT_BY_TYPE: Record<string, number> = {
  "tlsn-attestation": 100,
  "email-domain": 15,
  "email-exact": 15,
  "invite-code": 0,
  // Self-asserted group membership proves nothing about a person and is not
  // recovery-eligible; weight 0 keeps it out of the recovery math entirely.
  "group-membership": 0,
};

// Recovery weight a live re-proof of this badge contributes toward the
// threshold. oauth-account is provenance-sensitive (discord/steam = 10,
// otherwise 20); everything else reads the per-type table, falling back to
// the IAL baseline for types without an explicit override (e.g. age/
// residency at IAL2 = 60). (DESIGNDECISIONS #7.)
export function recoveryWeightFor(badgeType: string, provenance?: string): number {
  if (badgeType === "oauth-account") {
    return provenance && OAUTH_LOW_PROVENANCE.has(provenance)
      ? OAUTH_LOW_WEIGHT
      : OAUTH_DEFAULT_WEIGHT;
  }
  const override = RECOVERY_WEIGHT_BY_TYPE[badgeType];
  if (override !== undefined) return override;
  return BADGE_ASSURANCE_WEIGHT[assuranceLevelFor(badgeType, provenance)] ?? 0;
}

// Badge types a plugin can RE-PROVE live, bound to a recovery attempt's
// nonce (so a stored/leaked VC can't be replayed). Only these count toward
// threshold recovery. One-shot types (invite-code) can't be re-proven and
// are excluded. (DESIGNDECISIONS #8.)
export const RECOVERY_ELIGIBLE_TYPES: ReadonlySet<string> = new Set([
  "oauth-account",
  "email-domain",
  "email-exact",
  "tlsn-attestation",
]);
