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
//   2. range bucketing: every published count is shown as an honest RANGE via
//      `publicCountBucket` (change C) — a count in 1..4 renders as "<5", a 0 as
//      "0", and larger counts as a widening range ("5–9", "10–24", …, "N,000+").
//      The range subsumes the old k-suppression + single-number rounding: no
//      exact count is ever printed, and the sub-5 range is exactly the "<5"
//      suppression sentinel.
//
// The cohort percentage is derived ONLY from rounded values (`roundPublic`),
// never from a raw numerator/denominator, and is then coarsened to the nearest
// 5% — so it can never leak an exact small count. See `buildPublicCohortRow`.

import { isAllowlistedKey, isAllowlistedValue } from "@/lib/stats-allowlist";
import {
  DEFAULT_SUPPRESSION_K,
  publicCountBucket,
  publicCountLowerBound,
  roundPublic,
} from "@/lib/stats-public";

// A raw materialized BadgeStat row as this module consumes it (the display fields
// only — id/computedAt are irrelevant to shaping).
export interface BadgeStatInput {
  badgeType: string;
  attributeKey: string;
  attributeValue: string;
  count: number;
}

/**
 * Render one count for the public surface as an honest RANGE (change C) via
 * `publicCountBucket`: 1..4 -> "<5", 0 -> "0", larger counts -> a widening range
 * up to "N,000+". No exact count is ever printed. This is the ONLY function that
 * turns a raw count into published text — every public count flows through it.
 */
export function publicCountDisplay(count: number): string {
  return publicCountBucket(count);
}

/**
 * The numeric key a row is ORDERED by on the public surface — the LOWER BOUND of
 * the range that is printed, never the raw count, so DOM order can leak nothing
 * finer than the bucket shown. Two cells in the SAME printed range therefore sort
 * identically; callers sort DESC by this key and tie-break lexicographically,
 * making order a pure function of the rendered text.
 */
export function publicSortKey(count: number): number {
  return publicCountLowerBound(count);
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
  rawTotal: number; // ORDERING ONLY — never rendered; fed through publicSortKey to sort types
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
  // Attribute values are accumulated per (type,key) before display-shaping. The
  // raw count is retained ONLY to derive the published sort key (`publicSortKey`)
  // and the display text; rows are ordered by that published key, not the raw
  // count, so DOM order never leaks finer than what is printed.
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
    // even if it reached the table. Fail closed. The value is ALSO re-checked
    // against its closed-enum domain — `Badge.attributes` is stored verbatim, so
    // an out-of-domain (e.g. free-text) value must never surface even under an
    // allowlisted key.
    if (!isAllowlistedKey(stat.badgeType, stat.attributeKey)) continue;
    if (!isAllowlistedValue(stat.badgeType, stat.attributeKey, stat.attributeValue)) continue;

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
      // Order by the PUBLISHED value (DESC), tie-broken by attribute value name.
      // Two values that display the same (both suppressed, or both rounded to the
      // same number) therefore sort by name, never by their distinct raw counts.
      values.sort((a, b) => {
        const delta = publicSortKey(b.count) - publicSortKey(a.count);
        return delta !== 0 ? delta : a.value.localeCompare(b.value);
      });
      groups.push({
        key,
        values: values.map((v) => ({ value: v.value, display: publicCountDisplay(v.count) })),
      });
    }
    groups.sort((a, b) => a.key.localeCompare(b.key));
    row.attributes = groups;
  }

  // Order types by their PUBLISHED total (DESC), tie-broken by type name, so two
  // types whose totals display the same are ordered by name, not by raw count.
  return Array.from(byType.values()).sort((a, b) => {
    const delta = publicSortKey(b.rawTotal) - publicSortKey(a.rawTotal);
    return delta !== 0 ? delta : a.type.localeCompare(b.type);
  });
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
 *   - When shown, it is derived from the ROUNDED values (`roundPublic`) — a pure
 *     function of already-coarsened counts — and then coarsened to the NEAREST 5%
 *     (change C). It therefore leaks nothing beyond what the published ranges
 *     already show, and two raw pairs that round to the same values yield the same
 *     percentage.
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
      // roundPublic is monotonic and numerator <= denominator, so 0..100. Coarsen
      // to the nearest 5% so the ratio stays as coarse as the published ranges.
      const pct = (roundedNum / roundedDen) * 100;
      percentDisplay = `${Math.round(pct / 5) * 5}%`;
    }
  }

  return {
    label,
    numeratorDisplay: publicCountDisplay(numerator),
    denominatorDisplay: publicCountDisplay(denominator),
    percentDisplay,
  };
}
