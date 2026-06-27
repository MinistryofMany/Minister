import { anonymityHint, type AnonymityBucket } from "@/lib/anonymity-hint";
import { summarizeAttributes, type DisplayBadge } from "@/lib/badges";
import {
  evaluate,
  isAllOf,
  isAnyOf,
  isAtLeast,
  isBadgeLeaf,
  selectMinimalAnonymitySet,
  type PolicyNode,
  type UserBadge,
} from "@/lib/oidc-policy";

import { getBadgeType } from "@minister/shared";

// Builds the plain-object view the consent screen renders when the RP
// sends a structured minister_policy. Crosses the RSC server→client
// boundary, so every field is a plain JSON value (no Zod schemas / class
// instances). The structure tells the client how to render the choice
// (radio for "satisfy one of", pick-n for "satisfy n of", checkboxes for
// "all required"), which badges to pre-select (the minimal, most-anonymous
// satisfying set), and a coarse per-branch anonymity hint for informed
// override. The UI is convenience; oidc-actions minimizes authoritatively.

export interface PolicyBadgeOption {
  id: string;
  label: string;
  summary: string;
}

// A leaf requirement (one badge type) within the policy, with the user's
// holdings of that type and its coarse anonymity bucket.
export interface PolicyLeafView {
  type: string;
  typeLabel: string;
  description: string;
  anonymityBucket: AnonymityBucket;
  anonymityLabel: string;
  // The user's badges that satisfy this leaf (type + where/maxAgeDays).
  options: PolicyBadgeOption[];
  /** True when the user holds nothing that satisfies this leaf. */
  unmet: boolean;
}

export type PolicyGroupKind = "one-of" | "n-of" | "all-of" | "single";

// One renderable group derived from the top-level policy node.
export interface PolicyGroupView {
  kind: PolicyGroupKind;
  // For n-of: how many leaves must be selected. For one-of: 1.
  required: number;
  leaves: PolicyLeafView[];
}

export interface PolicyConsentView {
  group: PolicyGroupView;
  /** Pre-selected minimal, most-anonymous satisfying badge ids. */
  preselectedBadgeIds: string[];
  /** True iff the user can satisfy the policy at all. */
  satisfiable: boolean;
  /** Required badge types the user cannot satisfy (for the gap hint). */
  gaps: string[];
}

function leafOptions(leaf: { type: string }, badges: DisplayBadge[]): PolicyBadgeOption[] {
  return badges
    .filter((b) => b.type === leaf.type)
    .map((b) => ({
      id: b.id,
      label: b.meta.label,
      summary: summarizeAttributes(b.type, b.attributes),
    }));
}

function buildLeafView(
  node: PolicyNode,
  badges: DisplayBadge[],
  userBadges: UserBadge[],
  holderCounts: Map<string, number>,
  now: number,
): PolicyLeafView {
  // Only top-level/near-leaf badge nodes are surfaced as leaves. A nested
  // composite under a one-of/n-of branch is summarized by its first badge
  // type for display; the authoritative evaluation always uses the full
  // policy server-side.
  //
  // AUDIT L-1 (documented, deferred): for a composite OR-branch this shows
  // only the branch's FIRST leaf type (`firstBadgeType`), so the consent UI
  // under-describes a multi-leaf composite branch. This is a DISPLAY
  // limitation only — server-side minimization (minimizeToPolicy /
  // selectMinimalAnonymitySet) evaluates the full subtree and is
  // authoritative for what is actually disclosed. A future improvement
  // could render the full composite branch label; not implemented now.
  const type = firstBadgeType(node);
  const meta = type ? getBadgeType(type) : undefined;
  const count = type ? (holderCounts.get(type) ?? 0) : 0;
  const hint = anonymityHint(count);
  return {
    type: type ?? "",
    typeLabel: meta?.label ?? type ?? "Requirement",
    description: meta?.description ?? (type ? `Badge of type ${type}.` : "A combined requirement."),
    anonymityBucket: hint.bucket,
    anonymityLabel: hint.label,
    options: type ? leafOptions({ type }, badges) : [],
    unmet: !evaluate(node, userBadges, now),
  };
}

function firstBadgeType(node: PolicyNode): string | null {
  if (isBadgeLeaf(node)) return node.badge.type;
  const children = isAllOf(node)
    ? node.allOf
    : isAnyOf(node)
      ? node.anyOf
      : isAtLeast(node)
        ? node.atLeast.of
        : [];
  for (const child of children) {
    const t = firstBadgeType(child);
    if (t) return t;
  }
  return null;
}

/**
 * Build the consent view for a structured policy. The top-level node kind
 * decides the group rendering:
 *   anyOf       → one-of (radio: exactly one branch)
 *   atLeast{n}  → n-of  (pick exactly n branches)
 *   allOf/leaf  → all-of/single (each branch required)
 */
export function buildPolicyConsentView(
  policy: PolicyNode,
  badges: DisplayBadge[],
  userBadges: UserBadge[],
  holderCounts: Map<string, number>,
  now: number,
): PolicyConsentView {
  const selection = selectMinimalAnonymitySet(policy, userBadges, holderCounts, now);

  let kind: PolicyGroupKind;
  let required: number;
  let branches: PolicyNode[];
  if (isAnyOf(policy)) {
    kind = "one-of";
    required = 1;
    branches = policy.anyOf;
  } else if (isAtLeast(policy)) {
    kind = "n-of";
    required = policy.atLeast.n;
    branches = policy.atLeast.of;
  } else if (isAllOf(policy)) {
    kind = "all-of";
    branches = policy.allOf;
    required = branches.length;
  } else {
    kind = "single";
    required = 1;
    branches = [policy];
  }

  const leaves = branches.map((b) => buildLeafView(b, badges, userBadges, holderCounts, now));

  return {
    group: { kind, required, leaves },
    preselectedBadgeIds: selection.selectedBadgeIds,
    satisfiable: selection.satisfiable,
    gaps: selection.gaps,
  };
}
