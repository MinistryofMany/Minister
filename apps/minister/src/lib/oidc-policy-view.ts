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
  // True when disclosing this badge also discloses a per-RP Sybil nullifier
  // (crypto-core M5) — drives the consent screen's persistent-tag notice.
  carriesNullifier: boolean;
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

// One row of the locked "you've already proven these to this platform"
// transparency section: a badge TYPE the user has already disclosed to this
// client AND that this room requests, with the user's holdings of that type.
// Rendered auto-checked and disabled. Plain object across the RSC boundary.
export interface AlreadyGrantedType {
  type: string;
  typeLabel: string;
  description: string;
  badges: PolicyBadgeOption[];
}

// Build the locked "already proven" section from the SPECIFIC badge instance
// ids the user previously disclosed to this client AND that this room
// requests (audit W1). It shows exactly those instances — never every held
// instance of a granted TYPE — grouped by type for display, skipping any id
// the user no longer holds (nothing to lock). The caller passes the
// already-granted ∩ requested instance ids (grantedRelevantBadgeIds), scoped
// to the room's requested types (F-2(a): a previously-granted instance the
// room does not request is not shown and not disclosed for this room).
//
// NOTE: this section is a TRANSPARENCY display. What is actually disclosed
// is decided server-side by minimizeToPolicy over (submitted ∪ granted-
// relevant), which may trim a shown instance away if this room's minimal
// satisfying set does not need it.
export function buildAlreadyGrantedView(
  grantedBadgeIds: readonly string[],
  badges: DisplayBadge[],
): AlreadyGrantedType[] {
  const grantedSet = new Set(grantedBadgeIds);
  // Preserve the input badge order within each type; group by type.
  const byType = new Map<string, PolicyBadgeOption[]>();
  for (const badge of badges) {
    if (!grantedSet.has(badge.id)) continue;
    const option: PolicyBadgeOption = {
      id: badge.id,
      label: badge.meta.label,
      summary: summarizeAttributes(badge.type, badge.attributes),
      carriesNullifier: badge.nullifierRef !== null,
    };
    const bucket = byType.get(badge.type);
    if (bucket) bucket.push(option);
    else byType.set(badge.type, [option]);
  }
  const out: AlreadyGrantedType[] = [];
  for (const [type, held] of byType) {
    const meta = getBadgeType(type);
    out.push({
      type,
      typeLabel: meta?.label ?? type,
      description: meta?.description ?? `Badge of type ${type}.`,
      badges: held,
    });
  }
  return out;
}

function leafOptions(leaf: { type: string }, badges: DisplayBadge[]): PolicyBadgeOption[] {
  return badges
    .filter((b) => b.type === leaf.type)
    .map((b) => ({
      id: b.id,
      label: b.meta.label,
      summary: summarizeAttributes(b.type, b.attributes),
      carriesNullifier: b.nullifierRef !== null,
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
  // Phase-3: types already shown in the locked "already proven" section
  // (group 2). Their leaves are excluded from this pickable group so each
  // type appears in exactly one group. The server still folds the granted
  // set into minimizeToPolicy authoritatively (oidc-actions), so excluding
  // a granted leaf from the picker never under-discloses — it only avoids
  // showing the same type twice.
  excludeTypes: ReadonlySet<string> = new Set(),
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

  const visibleBranches =
    excludeTypes.size === 0
      ? branches
      : branches.filter((b) => {
          const t = firstBadgeType(b);
          return !(t !== null && excludeTypes.has(t));
        });

  const leaves = visibleBranches.map((b) =>
    buildLeafView(b, badges, userBadges, holderCounts, now),
  );

  // Preselection covers the pickable (non-locked) leaves only — the locked
  // section seeds its own ids in the consent screen. Drop any preselected id
  // whose badge type is excluded (now shown locked instead).
  const excludedBadgeIds = new Set(badges.filter((b) => excludeTypes.has(b.type)).map((b) => b.id));
  const preselectedBadgeIds = selection.selectedBadgeIds.filter((id) => !excludedBadgeIds.has(id));

  return {
    group: { kind, required, leaves },
    preselectedBadgeIds,
    satisfiable: selection.satisfiable,
    gaps: selection.gaps,
  };
}
