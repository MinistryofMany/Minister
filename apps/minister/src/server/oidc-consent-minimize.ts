import { issuanceMonthStartSeconds } from "@minister/vc";

import {
  selectMinimalAnonymitySet,
  type PolicyAttrValue,
  type PolicyNode,
  type UserBadge,
} from "@/lib/oidc-policy";

// Pure (non-"use server") helpers for the consent over-disclosure guard.
// Kept out of oidc-actions.ts because a "use server" module may only
// export async functions; these are synchronous and unit-testable on
// their own. oidc-actions.ts imports them on the consent-submit path.

// Narrow denormalized Json badge attributes to the scalar subset the
// policy engine compares against (string | number | boolean). A non-scalar
// value can never equal a policy `where` scalar, so dropping it is safe
// and fail-closed.
export function coerceAttrs(attributes: unknown): Record<string, PolicyAttrValue> {
  const out: Record<string, PolicyAttrValue> = {};
  if (attributes && typeof attributes === "object") {
    for (const [k, v] of Object.entries(attributes as Record<string, unknown>)) {
      if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
        out[k] = v;
      }
    }
  }
  return out;
}

/** The Badge-row fields the policy engine's feed needs. */
export interface PolicyBadgeRow {
  id: string;
  type: string;
  attributes: unknown;
  issuedAt: Date;
}

/**
 * The single Badge-row → policy-badge seam for BOTH consent feed points
 * (approveConsent's loadBadgesForUser and the authorize page's picker view).
 *
 * `issuedAt` is deliberately COARSENED to the badge's UTC issuance-month
 * start. The disclosed VC carries only the coarse `issuanceMonth` claim
 * (every fine-grained issuance timestamp is a cross-RP correlator — MIN-1),
 * and relying parties evaluate `maxAgeDays` against that bucket's start.
 * Feeding the exact Badge.issuedAt here would let selection/minimization
 * pass a gray-zone badge (true age within the window, coarse age outside)
 * that the RP's gate then rejects — after minimization already trimmed away
 * an alternative that would have passed both. Same clock ⇒ same decision.
 */
export function toPolicyUserBadge(row: PolicyBadgeRow): UserBadge {
  return {
    id: row.id,
    type: row.type,
    attributes: coerceAttrs(row.attributes),
    issuedAt: issuanceMonthStartSeconds(row.issuedAt),
  };
}

/**
 * Server-side minimization. With no policy this is the identity (today's
 * flat per-scope flow is unchanged). With a policy it trims the submitted,
 * owned ∩ requested badges down to ONE minimal satisfying set (the
 * most-anonymous), so the disclosed set is never more than one satisfying
 * combination. The result is always a subset of `submitted` — minimization
 * never fabricates or over-discloses. This is the authoritative
 * over-disclosure guard (Phase-2 design F-5 / §8.3).
 */
export function minimizeToPolicy(
  policy: PolicyNode | null,
  submitted: UserBadge[],
  holderCounts: Map<string, number>,
  now: number = Math.floor(Date.now() / 1000),
): UserBadge[] {
  if (!policy) return submitted;
  const result = selectMinimalAnonymitySet(policy, submitted, holderCounts, now);
  const keep = new Set(result.selectedBadgeIds);
  return submitted.filter((b) => keep.has(b.id));
}
