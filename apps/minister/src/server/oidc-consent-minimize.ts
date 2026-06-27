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
