// Data-shaping for the PUBLIC transparency page (phase-2 impl brief §6). This
// module is where the three privacy layers compose at render, in order, over the
// already-materialized (and already-allowlist-filtered) BadgeStat/CohortStat
// rows. It is PURE (no I/O) so it is unit-testable in isolation and so the
// privacy composition is auditable in one place:
//
//   1. Allowlist re-check (defense in depth): an attribute row whose key is not
//      `isAllowlistedKey(type, key)` is DROPPED even if it somehow reached the
//      table. Type-level totals (attributeKey === "") are not attribute rows and
//      pass through.
//   2. k-suppression: every published count goes through `suppress(count, k)`, so
//      a count in 1..k-1 renders as "<k" (a 0 renders as 0 — an absence is not
//      identifying). k comes from `DEFAULT_SUPPRESSION_K` (never hardcoded).
//   3. count rounding: a count that SURVIVES suppression (>= k) is coarsened with
//      `roundPublic` before it is shown.
//
// The cohort percentage is derived ONLY from values that already passed layers 2
// and 3 — never from a raw numerator/denominator — so it can never leak an exact
// small count. See `buildPublicCohortRow`.

import { isAllowlistedKey } from "@/lib/stats-allowlist";
import { DEFAULT_SUPPRESSION_K, roundPublic, suppress } from "@/lib/stats-public";

// A raw materialized BadgeStat row as this module consumes it (the display fields
// only — id/computedAt are irrelevant to shaping).
export interface BadgeStatInput {
  badgeType: string;
  attributeKey: string;
  attributeValue: string;
  count: number;
}

/**
 * Render one count for the public surface: k-suppression THEN rounding (layers 2
 * and 3, in that order). A suppressed small count (1..k-1) returns the "<k"
 * sentinel; a 0 returns "0"; a surviving count (>= k) is rounded and formatted.
 * This is the ONLY function that turns a raw count into published text — every
 * public count flows through it.
 */
export function publicCountDisplay(count: number): string {
  const suppressed = suppress(count, DEFAULT_SUPPRESSION_K);
  // A suppressed cell is the "<k" sentinel string — publish it verbatim.
  if (typeof suppressed === "string") return suppressed;
  // suppress() returns 0 only for count <= 0; nothing to round or hide.
  if (suppressed <= 0) return "0";
  // Survived suppression (>= k): coarsen before publishing.
  return roundPublic(suppressed).toLocaleString();
}

export interface PublicAttrValue {
  value: string;
  display: string; // suppressed + rounded
}

export interface PublicAttrGroup {
  key: string;
  values: PublicAttrValue[];
}

export interface PublicTypeRow {
  type: string;
  totalDisplay: string; // suppressed + rounded type-level total
  rawTotal: number; // ORDERING ONLY — never rendered; used to sort types by size
  attributes: PublicAttrGroup[];
}

/**
 * Group flat BadgeStat rows into per-type public rows, applying all three privacy
 * layers. Layer 1 (allowlist re-check) drops any attribute row whose key is not
 * allowlisted for its type — a non-allowlisted key can therefore NEVER reach the
 * returned structure, even if one slipped into the table. Layers 2 and 3 are
 * applied to every count via `publicCountDisplay`.
 *
 * `rawTotal` is retained on each row for size-descending ordering only; it is the
 * caller's contract not to render it (the page renders `totalDisplay`).
 */
export function buildPublicTypeRows(stats: readonly BadgeStatInput[]): PublicTypeRow[] {
  const byType = new Map<string, PublicTypeRow>();
  // Attribute values are accumulated per (type,key) before display-shaping so we
  // can sort within a key by true count (ordering is coarse, non-leaking info).
  const attrAccum = new Map<string, Map<string, { value: string; count: number }[]>>();

  function typeRow(type: string): PublicTypeRow {
    let row = byType.get(type);
    if (!row) {
      row = { type, totalDisplay: publicCountDisplay(0), rawTotal: 0, attributes: [] };
      byType.set(type, row);
    }
    return row;
  }

  for (const stat of stats) {
    const isTotal = stat.attributeKey === "" && stat.attributeValue === "";
    if (isTotal) {
      const row = typeRow(stat.badgeType);
      row.rawTotal = stat.count;
      row.totalDisplay = publicCountDisplay(stat.count);
      continue;
    }
    // LAYER 1 (defense in depth): a non-allowlisted attribute key never renders,
    // even if it reached the table. Fail closed.
    if (!isAllowlistedKey(stat.badgeType, stat.attributeKey)) continue;

    // Ensure the type row exists even if its total row is absent/out of order.
    typeRow(stat.badgeType);
    let byKey = attrAccum.get(stat.badgeType);
    if (!byKey) {
      byKey = new Map();
      attrAccum.set(stat.badgeType, byKey);
    }
    const values = byKey.get(stat.attributeKey) ?? [];
    values.push({ value: stat.attributeValue, count: stat.count });
    byKey.set(stat.attributeKey, values);
  }

  // Attach shaped (suppressed + rounded) attribute groups to each type row.
  for (const [type, byKey] of attrAccum) {
    const row = byType.get(type);
    if (!row) continue;
    const groups: PublicAttrGroup[] = [];
    for (const [key, values] of byKey) {
      values.sort((a, b) => b.count - a.count);
      groups.push({
        key,
        values: values.map((v) => ({ value: v.value, display: publicCountDisplay(v.count) })),
      });
    }
    groups.sort((a, b) => a.key.localeCompare(b.key));
    row.attributes = groups;
  }

  return Array.from(byType.values()).sort((a, b) => b.rawTotal - a.rawTotal);
}

export interface PublicCohortRow {
  label: string;
  numeratorDisplay: string;
  denominatorDisplay: string;
  // A percentage string ("42%") ONLY when both sides survive k-suppression and it
  // is safe to derive from rounded values; otherwise null (the cohort is too
  // small to report a ratio without leaking an exact small count).
  percentDisplay: string | null;
}

/**
 * Shape one cohort (numerator/denominator distinct-user counts) for public
 * display. Counts go through `publicCountDisplay` (suppression + rounding). The
 * percentage is the privacy-critical part:
 *
 *   - It is computed ONLY when BOTH sides survive k-suppression (>= k). If either
 *     side is a small count (1..k-1) the ratio is withheld (null) — a percentage
 *     over a raw small numerator or denominator would reconstruct that exact
 *     count.
 *   - When shown, it is derived from the ROUNDED values (`roundPublic`), i.e. a
 *     pure function of the counts already published on the page. It therefore
 *     leaks nothing beyond what the rounded counts already show.
 */
export function buildPublicCohortRow(
  label: string,
  numerator: number,
  denominator: number,
): PublicCohortRow {
  const bothSurvive = numerator >= DEFAULT_SUPPRESSION_K && denominator >= DEFAULT_SUPPRESSION_K;

  let percentDisplay: string | null = null;
  if (bothSurvive) {
    const roundedNum = roundPublic(numerator);
    const roundedDen = roundPublic(denominator);
    if (roundedDen > 0) {
      // roundPublic is monotonic and numerator <= denominator, so 0..100.
      percentDisplay = `${Math.round((roundedNum / roundedDen) * 100)}%`;
    }
  }

  return {
    label,
    numeratorDisplay: publicCountDisplay(numerator),
    denominatorDisplay: publicCountDisplay(denominator),
    percentDisplay,
  };
}
