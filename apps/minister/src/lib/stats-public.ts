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
