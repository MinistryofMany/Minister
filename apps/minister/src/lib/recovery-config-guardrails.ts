// Pure guardrails for the recovery-config editor (design spec §5.4, impl brief
// §5/§6). This module is deliberately plain (no prisma, no "use server", no
// side effects) so:
//   * the security-critical decision logic is unit-tested offline, and
//   * the "use server" action file (recovery-config-actions.ts) can import these
//     consts + helpers (a "use server" module may itself export ONLY async fns).
//
// The recovery config is the account-takeover control surface. Two directions
// matter and are treated asymmetrically:
//   * DEFENSIVE  (weight DECREASE / threshold INCREASE) — makes recovery HARDER —
//     applies IMMEDIATELY and clears any pending weakening on that field.
//   * WEAKENING  (weight INCREASE / threshold DECREASE) — makes recovery EASIER —
//     is SCHEDULED 72h out, so a human sees the change before it gains power.

import { CREDENTIAL_QUARANTINE_MS } from "@/lib/assurance";

// The delay a WEAKENING recovery-config change waits before taking effect. The
// design brief calls to reuse the 72h credential-quarantine window (a weakening
// must be visible to a human — via the admin broadcast — before it gains power),
// so this is that constant re-exported under a role-specific name.
export const RECOVERY_WEAKEN_DELAY_MS = CREDENTIAL_QUARANTINE_MS;

// Bounds (design spec §5.4). threshold never drops below today's 100 ("recovery
// at least as hard as the front door").
export const RECOVERY_WEIGHT_MIN = 0;
export const RECOVERY_WEIGHT_MAX = 100;
export const RECOVERY_THRESHOLD_MIN = 100;
export const RECOVERY_THRESHOLD_MAX = 1000;

// -----------------------------------------------------------------------------
// Bounds validation. Returns an error string, or null when valid.
// -----------------------------------------------------------------------------

export function validateRecoveryWeightBounds(weight: number): string | null {
  if (!Number.isInteger(weight)) {
    return "Recovery weight must be a whole number.";
  }
  if (weight < RECOVERY_WEIGHT_MIN || weight > RECOVERY_WEIGHT_MAX) {
    return `Recovery weight must be between ${RECOVERY_WEIGHT_MIN} and ${RECOVERY_WEIGHT_MAX}.`;
  }
  return null;
}

export function validateThresholdBounds(threshold: number): string | null {
  if (!Number.isInteger(threshold)) {
    return "Threshold must be a whole number.";
  }
  if (threshold < RECOVERY_THRESHOLD_MIN || threshold > RECOVERY_THRESHOLD_MAX) {
    return `Threshold must be between ${RECOVERY_THRESHOLD_MIN} and ${RECOVERY_THRESHOLD_MAX}.`;
  }
  return null;
}

// -----------------------------------------------------------------------------
// Solo-block invariant (design spec §5.4): no single non-solo badge type may
// reach the threshold on its own. Stated as a global state predicate, so it is
// enforced from BOTH sides — a weight edit AND a threshold/solo edit are each
// checked against it. `allowSoloRecovery` is the deliberate escape hatch (seeded
// only for tlsn-attestation, whose weight 100 == threshold 100).
//
// Returns an error string when the (weight, threshold, allowSolo) combination
// would let one badge solo-recover an account, or null when safe.
// -----------------------------------------------------------------------------

export function soloBlockError(
  effectiveWeight: number,
  effectiveThreshold: number,
  allowSolo: boolean,
): string | null {
  if (effectiveWeight >= effectiveThreshold && !allowSolo) {
    return (
      `A single badge at recovery weight ${effectiveWeight} would meet the recovery ` +
      `threshold ${effectiveThreshold} on its own. Enable solo recovery for this row ` +
      `first, or keep its weight below the threshold.`
    );
  }
  return null;
}

// -----------------------------------------------------------------------------
// Asymmetric apply timing. The direction is decided against the current LIVE
// column value (NOT the effective-with-pending value): what the operator sees in
// the "live" column is the baseline they are moving from.
// -----------------------------------------------------------------------------

// Prisma-ready field set for a recoveryWeight write. `kind` is advisory (drives
// the audit/email copy); the field members are spread straight into the update.
export type RecoveryWeightWrite =
  | {
      kind: "immediate";
      recoveryWeight: number;
      pendingRecoveryWeight: null;
      recoveryEffectiveAt: null;
    }
  | {
      kind: "scheduled";
      pendingRecoveryWeight: number;
      recoveryEffectiveAt: Date;
    };

/**
 * Plan a recoveryWeight write given the current live column value and the
 * requested value.
 *   * requested <= live  → DEFENSIVE (or a no-op): apply immediately AND clear
 *     any pending weakening previously scheduled on this row.
 *   * requested >  live  → WEAKENING: leave the live weight untouched and
 *     schedule the new value to take effect in 72h.
 */
export function planRecoveryWeightWrite(
  currentLive: number,
  requested: number,
  now: number,
): RecoveryWeightWrite {
  if (requested <= currentLive) {
    return {
      kind: "immediate",
      recoveryWeight: requested,
      pendingRecoveryWeight: null,
      recoveryEffectiveAt: null,
    };
  }
  return {
    kind: "scheduled",
    pendingRecoveryWeight: requested,
    recoveryEffectiveAt: new Date(now + RECOVERY_WEAKEN_DELAY_MS),
  };
}

export type ThresholdWrite =
  | {
      kind: "immediate";
      threshold: number;
      pendingThreshold: null;
      thresholdEffectiveAt: null;
    }
  | {
      kind: "scheduled";
      pendingThreshold: number;
      thresholdEffectiveAt: Date;
    };

/**
 * Plan a threshold write given the current live threshold and the requested one.
 *   * requested >= live → DEFENSIVE (or a no-op): apply immediately AND clear any
 *     pending weakening (a scheduled threshold decrease).
 *   * requested <  live → WEAKENING: leave the live threshold and schedule the
 *     new (lower) value 72h out.
 */
export function planThresholdWrite(
  currentLive: number,
  requested: number,
  now: number,
): ThresholdWrite {
  if (requested >= currentLive) {
    return {
      kind: "immediate",
      threshold: requested,
      pendingThreshold: null,
      thresholdEffectiveAt: null,
    };
  }
  return {
    kind: "scheduled",
    pendingThreshold: requested,
    thresholdEffectiveAt: new Date(now + RECOVERY_WEAKEN_DELAY_MS),
  };
}

// -----------------------------------------------------------------------------
// Effective-value resolution. Phase 1 has NO promotion job: once a scheduled
// weakening's effectiveAt passes, the recovery ENGINE reads the pending value
// (see sybil-config.ts effectiveRecoveryWeight / loadEffectiveThreshold) but the
// live column is never promoted. Both admin review surfaces — /admin/recovery-
// config (the editor) and /admin/sybil-score (a read-only mirror of the same
// column) — must resolve "what does the engine actually use right now" through
// this SAME helper, so they can never show contradictory recovery weights for
// the same row.
// -----------------------------------------------------------------------------

export function effectiveRecoveryWeight(
  row: {
    recoveryWeight: number;
    pendingRecoveryWeight: number | null;
    recoveryEffectiveAt: Date | null;
  },
  now: number,
): number {
  return row.pendingRecoveryWeight != null &&
    row.recoveryEffectiveAt != null &&
    row.recoveryEffectiveAt.getTime() <= now
    ? row.pendingRecoveryWeight
    : row.recoveryWeight;
}

export function effectiveRecoveryThreshold(
  cfg: {
    threshold: number;
    pendingThreshold: number | null;
    thresholdEffectiveAt: Date | null;
  },
  now: number,
): number {
  return cfg.pendingThreshold != null &&
    cfg.thresholdEffectiveAt != null &&
    cfg.thresholdEffectiveAt.getTime() <= now
    ? cfg.pendingThreshold
    : cfg.threshold;
}
