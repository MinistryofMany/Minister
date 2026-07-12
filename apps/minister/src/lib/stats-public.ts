// Public-surface privacy helpers for badge statistics (design spec §6, phase-2
// impl brief §6). Pure, no I/O — the public transparency page (P2-U2) composes
// them over materialized counts. Two of the three privacy layers (the third is
// the attribute allowlist, applied at materialization):
//
//   * k-suppression: a cell with a small non-zero count shows "<k" rather than a
//     precise small number (a count of 1-4 is close to naming a person).
//   * count rounding: published counts are coarsened so hourly diffing can't
//     watch single +1 transitions (a differencing deanonymization vector).
//
// Admin views show exact counts and MUST NOT call these.

// Default k for suppression (design spec §6). A cell of 1..k-1 is suppressed.
export const DEFAULT_SUPPRESSION_K = 5;

// Below this, round to the nearest 10; at or above, round to ~5% granularity
// (two significant figures) so large counts still coarsen but stay legible.
const LARGE_COUNT_THRESHOLD = 1000;

/**
 * k-anonymity suppression. Returns the sentinel string `"<k"` when the count is
 * a small positive number (`0 < count < k`); a true `0` stays `0` (there is
 * nothing to hide — the absence of holders is not identifying); a count `>= k`
 * passes through unchanged (round it separately for publication).
 *
 * @returns a number for pass-through/zero, or a `"<k"` string when suppressed.
 */
export function suppress(count: number, k: number = DEFAULT_SUPPRESSION_K): number | string {
  if (count <= 0) return 0;
  if (count < k) return `<${k}`;
  return count;
}

/**
 * Coarsen a count for public display: nearest 10 for small counts, ~5%
 * granularity (two significant figures) for large ones, so an observer diffing
 * the page hourly cannot watch a single holder join or leave. Never negative;
 * `<= 0` returns `0`.
 *
 * Intended to run AFTER `suppress` on the public page (suppressed small cells
 * never reach here); on its own a value below 5 would round toward 0, which is
 * exactly why the public composition suppresses first.
 */
export function roundPublic(count: number): number {
  if (count <= 0) return 0;
  if (count < LARGE_COUNT_THRESHOLD) return Math.round(count / 10) * 10;
  // Two significant figures: step = 10^(floor(log10(count)) - 1).
  const magnitude = Math.floor(Math.log10(count));
  const step = 10 ** (magnitude - 1);
  return Math.round(count / step) * step;
}

// ---------------------------------------------------------------------------
// Range bucketing for the PUBLIC transparency page (change C). Instead of a
// rounded single number, a count is published as an honest RANGE so the printed
// value never implies more precision than the bucket it falls in. Buckets widen
// with magnitude; from 1000 up we floor to the nearest 1000 as an open "N,000+".
// ---------------------------------------------------------------------------

// The fixed sub-1000 ranges. `lower` is the inclusive lower bound (used to order
// rows so DOM position can never leak finer than the printed bucket).
const COUNT_BUCKETS: ReadonlyArray<{ lower: number; upper: number; label: string }> = [
  { lower: 1, upper: 4, label: "<5" },
  { lower: 5, upper: 9, label: "5–9" },
  { lower: 10, upper: 24, label: "10–24" },
  { lower: 25, upper: 49, label: "25–49" },
  { lower: 50, upper: 99, label: "50–99" },
  { lower: 100, upper: 249, label: "100–249" },
  { lower: 250, upper: 499, label: "250–499" },
  { lower: 500, upper: 999, label: "500–999" },
];

/**
 * Map a raw count to an honest public range label (change C):
 *   0 -> "0"; 1-4 -> "<5"; 5-9 -> "5–9"; 10-24 -> "10–24"; 25-49 -> "25–49";
 *   50-99 -> "50–99"; 100-249 -> "100–249"; 250-499 -> "250–499";
 *   500-999 -> "500–999"; >=1000 -> nearest-1000 floor as "N,000+"
 *   (1000-1999 -> "1,000+", 2750 -> "2,000+", 10500 -> "10,000+").
 * Ranges use an en-dash; thousands use locale separators. `<= 0` is "0".
 */
export function publicCountBucket(count: number): string {
  if (count <= 0) return "0";
  if (count >= LARGE_COUNT_THRESHOLD) {
    const floored = Math.floor(count / 1000) * 1000;
    return `${floored.toLocaleString()}+`;
  }
  for (const b of COUNT_BUCKETS) {
    if (count >= b.lower && count <= b.upper) return b.label;
  }
  // Unreachable: the ranges above cover 1..999 exhaustively.
  return "0";
}

/**
 * The inclusive LOWER BOUND of the range `publicCountBucket(count)` prints. Rows
 * are ordered by this so two counts in the SAME printed bucket sort identically —
 * DOM order can never leak a finer distinction than the range shown. For a
 * "N,000+" bucket the lower bound is that floored thousand, so distinct printed
 * buckets still order correctly.
 */
export function publicCountLowerBound(count: number): number {
  if (count <= 0) return 0;
  if (count >= LARGE_COUNT_THRESHOLD) return Math.floor(count / 1000) * 1000;
  for (const b of COUNT_BUCKETS) {
    if (count >= b.lower && count <= b.upper) return b.lower;
  }
  return 0;
}
