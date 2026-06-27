import { z } from "zod";

// Minister-side mirror of Discreetly's policy model
// (Discreetly/packages/policy/src/{types,schema,evaluate}.ts). This is a
// DELIBERATE copy — Minister has exactly one consumer (the OIDC consent
// flow) and pulling in a shared package would couple the two repos' build
// graphs (see Phase-2 design F-2/F-7). The copy is kept honest by
// oidc-policy.drift.test.ts, which fails CI if the two schemas diverge,
// matching the minister-client badge-registry "copy + drift-check"
// pattern.
//
// Beyond the mirror, this module adds `selectMinimalAnonymitySet`: given a
// requirement subtree, the user's held badges, and per-type anonymity-set
// sizes, it computes the MINIMAL satisfying selection that maximizes
// anonymity, plus the alternative satisfying selections for the consent
// override UI. Selection is advisory (it drives the pre-selected consent
// toggles); the authoritative over-disclosure guard is the server-side
// minimization in oidc-actions.

// ---------------------------------------------------------------------------
// Types (mirror of Discreetly policy types)
// ---------------------------------------------------------------------------

export type PolicyAttrValue = string | number | boolean;

export interface BadgeLeaf {
  badge: {
    type: string;
    where?: Record<string, PolicyAttrValue>;
    /** Badge must have been issued within this many days of `now`. */
    maxAgeDays?: number;
  };
}

export interface AllOfNode {
  allOf: PolicyNode[];
}

export interface AnyOfNode {
  anyOf: PolicyNode[];
}

export interface AtLeastNode {
  atLeast: { n: number; of: PolicyNode[] };
}

export type PolicyNode = BadgeLeaf | AllOfNode | AnyOfNode | AtLeastNode;

/** A badge the user holds, as seen by selection/evaluation. */
export interface UserBadge {
  id: string;
  type: string;
  attributes: Record<string, PolicyAttrValue>;
  /** VC `iat`, unix seconds. */
  issuedAt: number;
}

export function isBadgeLeaf(node: PolicyNode): node is BadgeLeaf {
  return "badge" in node;
}

export function isAllOf(node: PolicyNode): node is AllOfNode {
  return "allOf" in node;
}

export function isAnyOf(node: PolicyNode): node is AnyOfNode {
  return "anyOf" in node;
}

export function isAtLeast(node: PolicyNode): node is AtLeastNode {
  return "atLeast" in node;
}

// ---------------------------------------------------------------------------
// Strict zod schema (mirror of Discreetly schema.ts)
// ---------------------------------------------------------------------------

const attrValue = z.union([z.string(), z.number(), z.boolean()]);

const badgeLeaf = z
  .object({
    badge: z
      .object({
        type: z.string().min(1),
        where: z.record(attrValue).optional(),
        maxAgeDays: z.number().positive().optional(),
      })
      .strict(),
  })
  .strict();

/**
 * Recursive zod schema mirroring `PolicyNode`. Each object is `.strict()`
 * so unknown keys are rejected. Empty `allOf`/`anyOf`/`atLeast.of` arrays
 * are valid and meaningful (`{ allOf: [] }` is admit-all, `{ anyOf: [] }`
 * is admit-none).
 */
export const policyNodeSchema: z.ZodType<PolicyNode> = z.lazy(() =>
  z.union([
    badgeLeaf,
    z.object({ allOf: z.array(policyNodeSchema) }).strict(),
    z.object({ anyOf: z.array(policyNodeSchema) }).strict(),
    z
      .object({
        atLeast: z
          .object({ n: z.number().int().nonnegative(), of: z.array(policyNodeSchema) })
          .strict(),
      })
      .strict(),
  ]),
);

/** Parse + validate untrusted JSON into a PolicyNode; throws on invalid input. */
export function parsePolicy(input: unknown): PolicyNode {
  return policyNodeSchema.parse(input);
}

/** Max recursion depth accepted by `policyDepth`-gated callers. */
export const MAX_POLICY_DEPTH = 8;

// Breadth bounds (audit C-1). Depth + byte caps alone do NOT bound a
// policy: a single flat `atLeast{ n, of: [...] }` with a large `n` and
// hundreds of duplicate-type leaves stays shallow, small, and passes a
// type-set width check, yet drives O(n^k) combination enumeration in
// selection and freezes the event loop. These caps make breadth explicit.
// Real room policies have a tiny `n` and a handful of branches, so the
// limits are generous headroom while still hard.

/** Max `atLeast.n` threshold accepted. */
export const MAX_ATLEAST_N = 16;
/** Max children on any single `anyOf` / `allOf` / `atLeast.of` node. */
export const MAX_NODE_CHILDREN = 16;
/** Max total nodes (leaves + composites) across the whole policy tree. */
export const MAX_POLICY_NODES = 64;

/**
 * Enforce the breadth bounds above on a parsed policy tree. Returns the
 * first violation as a short reason string, or `null` if the tree is
 * within all bounds. Counts every node (leaf and composite) toward the
 * total-node cap; this is the breadth defense depth alone cannot provide.
 * Fail-closed: callers reject (redirect-error) on any non-null reason.
 */
export function policyBoundsViolation(node: PolicyNode): string | null {
  let total = 0;
  const overflow = { hit: false as boolean, reason: "" as string };

  const walk = (n: PolicyNode): void => {
    if (overflow.hit) return;
    total += 1;
    if (total > MAX_POLICY_NODES) {
      overflow.hit = true;
      overflow.reason = "policy has too many nodes";
      return;
    }
    if (isBadgeLeaf(n)) return;
    let children: PolicyNode[];
    if (isAllOf(n)) {
      children = n.allOf;
    } else if (isAnyOf(n)) {
      children = n.anyOf;
    } else if (isAtLeast(n)) {
      if (n.atLeast.n > MAX_ATLEAST_N) {
        overflow.hit = true;
        overflow.reason = "atLeast.n exceeds the maximum";
        return;
      }
      children = n.atLeast.of;
    } else {
      const _exhaustive: never = n;
      throw new Error(`unknown policy node shape: ${JSON.stringify(_exhaustive)}`);
    }
    if (children.length > MAX_NODE_CHILDREN) {
      overflow.hit = true;
      overflow.reason = "policy node has too many children";
      return;
    }
    for (const child of children) {
      walk(child);
      if (overflow.hit) return;
    }
  };

  walk(node);
  return overflow.hit ? overflow.reason : null;
}

/**
 * Structural depth of a policy tree (a single leaf has depth 1). Used by
 * the authorize validator to reject pathologically nested payloads before
 * they reach selection.
 */
export function policyDepth(node: PolicyNode): number {
  if (isBadgeLeaf(node)) return 1;
  if (isAllOf(node)) return 1 + maxChildDepth(node.allOf);
  if (isAnyOf(node)) return 1 + maxChildDepth(node.anyOf);
  if (isAtLeast(node)) return 1 + maxChildDepth(node.atLeast.of);
  const _exhaustive: never = node;
  throw new Error(`unknown policy node shape: ${JSON.stringify(_exhaustive)}`);
}

function maxChildDepth(children: PolicyNode[]): number {
  let max = 0;
  for (const child of children) {
    const d = policyDepth(child);
    if (d > max) max = d;
  }
  return max;
}

/** Every distinct badge `type` mentioned anywhere in the policy tree. */
export function policyBadgeTypes(node: PolicyNode): Set<string> {
  const out = new Set<string>();
  collectTypes(node, out);
  return out;
}

function collectTypes(node: PolicyNode, out: Set<string>): void {
  if (isBadgeLeaf(node)) {
    out.add(node.badge.type);
    return;
  }
  if (isAllOf(node)) {
    for (const child of node.allOf) collectTypes(child, out);
    return;
  }
  if (isAnyOf(node)) {
    for (const child of node.anyOf) collectTypes(child, out);
    return;
  }
  if (isAtLeast(node)) {
    for (const child of node.atLeast.of) collectTypes(child, out);
    return;
  }
  const _exhaustive: never = node;
  throw new Error(`unknown policy node shape: ${JSON.stringify(_exhaustive)}`);
}

// ---------------------------------------------------------------------------
// Evaluation (mirror of Discreetly evaluate.ts)
// ---------------------------------------------------------------------------

const SECONDS_PER_DAY = 86_400;

function leafSatisfied(leaf: BadgeLeaf, badges: UserBadge[], now: number): boolean {
  return badges.some((candidate) => badgeSatisfiesLeaf(leaf, candidate, now));
}

function badgeSatisfiesLeaf(leaf: BadgeLeaf, candidate: UserBadge, now: number): boolean {
  const { type, where, maxAgeDays } = leaf.badge;
  if (candidate.type !== type) return false;
  if (maxAgeDays !== undefined && now - candidate.issuedAt > maxAgeDays * SECONDS_PER_DAY) {
    return false;
  }
  if (where) {
    for (const [key, value] of Object.entries(where)) {
      if (candidate.attributes[key] !== value) return false;
    }
  }
  return true;
}

/**
 * Evaluate a policy against the set of held/disclosed badges. `now` is
 * unix seconds. Mirrors Discreetly's `evaluate` exactly, including
 * fail-closed throwing on an unrecognized runtime shape.
 */
export function evaluate(policy: PolicyNode, badges: UserBadge[], now: number): boolean {
  if (isBadgeLeaf(policy)) return leafSatisfied(policy, badges, now);
  if (isAllOf(policy)) return policy.allOf.every((node) => evaluate(node, badges, now));
  if (isAnyOf(policy)) return policy.anyOf.some((node) => evaluate(node, badges, now));
  if (isAtLeast(policy)) {
    const satisfied = policy.atLeast.of.filter((node) => evaluate(node, badges, now)).length;
    return satisfied >= policy.atLeast.n;
  }
  const _exhaustive: never = policy;
  throw new Error(`unknown policy node shape: ${JSON.stringify(_exhaustive)}`);
}

// ---------------------------------------------------------------------------
// Minimal-anonymity selection
// ---------------------------------------------------------------------------

/**
 * A satisfying selection of the user's badges for some subtree: the badge
 * ids to disclose, and the set of types they cover (for anonymity
 * ranking). A selection is always derived from badges the user actually
 * holds — selection never fabricates.
 */
export interface Selection {
  badgeIds: string[];
  /** Distinct badge types disclosed by this selection. */
  types: Set<string>;
}

export interface SelectionResult {
  /** True iff the user holds a set of badges that satisfies the policy. */
  satisfiable: boolean;
  /** The minimal, largest-anonymity satisfying selection (empty if unsatisfiable). */
  selectedBadgeIds: string[];
  /**
   * Other satisfying selections the user could disclose instead, for the
   * consent override UI. Each is a distinct minimal satisfying set. Does
   * not include the chosen `selectedBadgeIds`.
   */
  alternatives: string[][];
  /**
   * Badge types the policy requires that the user cannot satisfy. Empty
   * when satisfiable; drives the "you don't hold a badge for this"
   * consent hint when not.
   */
  gaps: string[];
}

// Cap on how many alternative satisfying selections we enumerate per
// anyOf/atLeast node, to bound consent-render cost on a crafted policy.
const MAX_ALTERNATIVES = 16;

// Cap on C(prefix.length, n) before we enumerate atLeast alternatives.
// Above this we skip enumeration and return only the chosen minimal set
// (audit C-1 — bounds the quartic+ combinatorial path regardless of the
// upstream breadth caps). A few hundred is ample for real n+4 prefixes.
const MAX_ATLEAST_COMBINATIONS = 500;

/**
 * Anonymity of a selection, as the multiset of its per-type holder counts
 * sorted ASCENDING. Comparison is lexicographic on this vector: the
 * weakest link (smallest anonymity set in the combination) dominates how
 * identifying the disclosure is, so it is compared first. A missing type
 * count is treated as 0 (maximally identifying), which is conservative.
 */
function anonymityVector(types: Set<string>, holderCounts: Map<string, number>): number[] {
  return [...types].map((t) => holderCounts.get(t) ?? 0).sort((a, b) => a - b);
}

/**
 * Rank two selections: higher anonymity is better. Returns < 0 if `a` is
 * better (more private), > 0 if `b` is better, 0 if indistinguishable.
 *
 * 1. Larger weakest-link-first anonymity vector wins (lexicographic; the
 *    first position where the ascending-sorted counts differ decides).
 * 2. Tie-break: fewer disclosed badges wins (less to reveal).
 * 3. Tie-break: stable type ordering (sorted joined types) for
 *    determinism.
 */
function compareSelections(a: Selection, b: Selection, holderCounts: Map<string, number>): number {
  const va = anonymityVector(a.types, holderCounts);
  const vb = anonymityVector(b.types, holderCounts);
  const len = Math.max(va.length, vb.length);
  for (let i = 0; i < len; i++) {
    // A shorter vector means an absent weakest link at this position;
    // treat as +Infinity so the present, finite weakest link is the one
    // that decides (a longer combination is only worse if it adds a
    // smaller anonymity set, which lands earlier in the ascending order).
    const ai = i < va.length ? va[i]! : Number.POSITIVE_INFINITY;
    const bi = i < vb.length ? vb[i]! : Number.POSITIVE_INFINITY;
    if (ai !== bi) return bi - ai; // larger count is better → earlier
  }
  if (a.badgeIds.length !== b.badgeIds.length) {
    return a.badgeIds.length - b.badgeIds.length; // fewer badges better
  }
  const ka = [...a.types].sort().join(" ");
  const kb = [...b.types].sort().join(" ");
  return ka < kb ? -1 : ka > kb ? 1 : 0;
}

function bestOf(selections: Selection[], holderCounts: Map<string, number>): Selection | null {
  if (selections.length === 0) return null;
  let best = selections[0]!;
  for (let i = 1; i < selections.length; i++) {
    if (compareSelections(selections[i]!, best, holderCounts) < 0) best = selections[i]!;
  }
  return best;
}

function mergeSelections(parts: Selection[]): Selection {
  const ids = new Set<string>();
  const types = new Set<string>();
  for (const part of parts) {
    for (const id of part.badgeIds) ids.add(id);
    for (const t of part.types) types.add(t);
  }
  return { badgeIds: [...ids], types };
}

/**
 * All minimal satisfying selections for a node, ranked best-first. Empty
 * array ⇒ the user cannot satisfy this node. Capped at MAX_ALTERNATIVES
 * to bound work on adversarial policies.
 */
function selectionsFor(
  node: PolicyNode,
  badges: UserBadge[],
  holderCounts: Map<string, number>,
  now: number,
): Selection[] {
  if (isBadgeLeaf(node)) {
    // Each held badge that satisfies the leaf is a candidate selection.
    // A leaf's anonymity is its TYPE count regardless of which instance
    // satisfies where/maxAgeDays, so all instances share an anonymity
    // vector and the tie-break (fewest badges, then stable ordering)
    // picks a deterministic one. Distinct ids stay as distinct
    // alternatives so the override UI can show the user's other holdings.
    const out: Selection[] = [];
    for (const b of badges) {
      if (badgeSatisfiesLeaf(node, b, now)) {
        out.push({ badgeIds: [b.id], types: new Set([b.type]) });
      }
    }
    return rankAndCap(out, holderCounts);
  }

  if (isAllOf(node)) {
    // Must satisfy every child. The best satisfying selection is the
    // union of each child's best selection; if any child is
    // unsatisfiable, the whole node is.
    const childBests: Selection[] = [];
    for (const child of node.allOf) {
      const childSelections = selectionsFor(child, badges, holderCounts, now);
      const best = bestOf(childSelections, holderCounts);
      if (best === null) return []; // a required child cannot be met
      childBests.push(best);
    }
    // allOf has a single combined selection (the union of child bests);
    // there is no "alternative branch" at this node — alternatives surface
    // inside any anyOf/atLeast children, but those are resolved to their
    // best here. Returning one selection is correct for the minimal set.
    return [mergeSelections(childBests)];
  }

  if (isAnyOf(node)) {
    // Satisfy ANY one child. Each satisfiable child contributes its best
    // selection as a candidate; the override UI offers the non-chosen ones.
    const candidates: Selection[] = [];
    for (const child of node.anyOf) {
      const best = bestOf(selectionsFor(child, badges, holderCounts, now), holderCounts);
      if (best !== null) candidates.push(best);
    }
    return rankAndCap(candidates, holderCounts);
  }

  if (isAtLeast(node)) {
    const { n, of } = node.atLeast;
    // n satisfied children required. Collect each child's best selection,
    // rank them, and combine the n most-anonymous. Degenerate n<=0 ⇒ the
    // empty selection satisfies.
    const childBests: Selection[] = [];
    for (const child of of) {
      const best = bestOf(selectionsFor(child, badges, holderCounts, now), holderCounts);
      if (best !== null) childBests.push(best);
    }
    if (n <= 0) return [{ badgeIds: [], types: new Set() }];
    if (childBests.length < n) return []; // cannot reach the threshold
    // Sort children best-first. The CHOSEN minimal set is just the top-n
    // (O(k log k) sort, already done) — combination enumeration only exists
    // to OFFER alternatives ("swap the n-th for the (n+1)-th"). Enumeration
    // is C(prefix.length, n), which is attacker-amplifiable, so it is
    // guarded (audit C-1): when the count would exceed a small constant we
    // drop alternative enumeration and return only the chosen top-n set.
    // This never changes which minimal set is chosen.
    childBests.sort((a, b) => compareSelections(a, b, holderCounts));
    const prefix = childBests.slice(0, Math.min(childBests.length, n + 4));
    const topN = mergeSelections(childBests.slice(0, n));
    if (chooseCount(prefix.length, n) > MAX_ATLEAST_COMBINATIONS) {
      // Too many alternatives to enumerate safely — return just the chosen
      // minimal set (the override UI loses swap suggestions for this node,
      // but the disclosed set is identical and selection stays bounded).
      return [topN];
    }
    const combos = nCombinations(prefix, n).map((parts) => mergeSelections(parts));
    return rankAndCap(combos, holderCounts);
  }

  const _exhaustive: never = node;
  throw new Error(`unknown policy node shape: ${JSON.stringify(_exhaustive)}`);
}

function rankAndCap(selections: Selection[], holderCounts: Map<string, number>): Selection[] {
  const ranked = [...selections].sort((a, b) => compareSelections(a, b, holderCounts));
  return dedupeSelections(ranked).slice(0, MAX_ALTERNATIVES);
}

function dedupeSelections(selections: Selection[]): Selection[] {
  const seen = new Set<string>();
  const out: Selection[] = [];
  for (const sel of selections) {
    const key = [...sel.badgeIds].sort().join(" ");
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(sel);
  }
  return out;
}

/**
 * C(k, n) = number of n-combinations from k items, computed iteratively
 * and SATURATED at MAX_ATLEAST_COMBINATIONS + 1 so a large input can never
 * overflow or do unbounded work just to size the enumeration (audit C-1).
 */
function chooseCount(k: number, n: number): number {
  if (n < 0 || n > k) return 0;
  if (n === 0 || n === k) return 1;
  const r = Math.min(n, k - n);
  let result = 1;
  for (let i = 0; i < r; i++) {
    result = (result * (k - i)) / (i + 1);
    if (result > MAX_ATLEAST_COMBINATIONS) return MAX_ATLEAST_COMBINATIONS + 1;
  }
  return result;
}

function nCombinations<T>(items: T[], n: number): T[][] {
  if (n <= 0) return [[]];
  if (n > items.length) return [];
  const out: T[][] = [];
  const pick = (start: number, chosen: T[]): void => {
    if (chosen.length === n) {
      out.push([...chosen]);
      return;
    }
    for (let i = start; i < items.length; i++) {
      chosen.push(items[i]!);
      pick(i + 1, chosen);
      chosen.pop();
    }
  };
  pick(0, []);
  return out;
}

/** Collect the badge types the policy requires that the user cannot satisfy. */
function findGaps(node: PolicyNode, badges: UserBadge[], now: number, gaps: Set<string>): void {
  if (isBadgeLeaf(node)) {
    if (!leafSatisfied(node, badges, now)) gaps.add(node.badge.type);
    return;
  }
  if (isAllOf(node)) {
    for (const child of node.allOf) {
      if (!evaluate(child, badges, now)) findGaps(child, badges, now, gaps);
    }
    return;
  }
  if (isAnyOf(node)) {
    // anyOf is a gap only if NO child is satisfiable; report each branch's
    // missing leaf so the user sees what would satisfy it.
    for (const child of node.anyOf) findGaps(child, badges, now, gaps);
    return;
  }
  if (isAtLeast(node)) {
    for (const child of node.atLeast.of) {
      if (!evaluate(child, badges, now)) findGaps(child, badges, now, gaps);
    }
    return;
  }
  const _exhaustive: never = node;
  throw new Error(`unknown policy node shape: ${JSON.stringify(_exhaustive)}`);
}

/**
 * Compute the minimal, largest-anonymity satisfying selection for a
 * policy over the user's held badges, plus override alternatives and the
 * unsatisfiable gaps.
 *
 * - Satisfiable ⇒ `selectedBadgeIds` is the most-private minimal set,
 *   `alternatives` are other minimal satisfying sets, `gaps` is empty.
 * - Unsatisfiable ⇒ `selectedBadgeIds` and `alternatives` are empty (the
 *   flow never pre-selects or fabricates a non-satisfying disclosure),
 *   and `gaps` lists the required types the user can't meet.
 *
 * @param holderCounts per-type distinct-holder counts (anonymity ranking).
 * @param now unix seconds (deterministic for tests / maxAgeDays).
 */
export function selectMinimalAnonymitySet(
  policy: PolicyNode,
  badges: UserBadge[],
  holderCounts: Map<string, number>,
  now: number,
): SelectionResult {
  const ranked = selectionsFor(policy, badges, holderCounts, now);
  if (ranked.length === 0) {
    const gaps = new Set<string>();
    findGaps(policy, badges, now, gaps);
    return { satisfiable: false, selectedBadgeIds: [], alternatives: [], gaps: [...gaps] };
  }
  const [best, ...rest] = ranked;
  return {
    satisfiable: true,
    selectedBadgeIds: best!.badgeIds,
    alternatives: rest.map((s) => s.badgeIds),
    gaps: [],
  };
}
