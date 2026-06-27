// Coarse, relative anonymity hint shown to the USER at consent (Phase-2
// design F-3 / §3.3). The user sees a bucket label so they can make an
// INFORMED override between satisfying choices; the relying party never
// sees the integer (that would be a needless per-type side-channel). Raw
// counts are used server-side only, for ranking.
//
// Buckets are coarse on purpose: a type held by very few users could be
// identifying if a live integer leaked over time, so the smallest bucket
// collapses everything under 10 into one label.

export type AnonymityBucket = "very-small" | "small" | "medium" | "large";

export interface AnonymityHint {
  bucket: AnonymityBucket;
  /** Short user-facing label for the bucket. */
  label: string;
}

const HINTS: Record<AnonymityBucket, string> = {
  "very-small": "Few people hold this — least private",
  small: "Some people hold this",
  medium: "Many people hold this",
  large: "Very many people hold this — most private",
};

/**
 * Map a raw distinct-holder count to a coarse bucket. Buckets:
 *   <10   → very-small
 *   10–99 → small
 *   100–999 → medium
 *   1000+ → large
 */
export function anonymityHint(holderCount: number): AnonymityHint {
  const bucket: AnonymityBucket =
    holderCount < 10
      ? "very-small"
      : holderCount < 100
        ? "small"
        : holderCount < 1000
          ? "medium"
          : "large";
  return { bucket, label: HINTS[bucket] };
}
