# Phase 2 Security Audit — OIDC anonymity-aware OR/threshold selection

Scope: the Minister consent path that maps a relying-party `minister_policy`
(OR / `atLeast` requirement tree) to a minimal, most-anonymous badge
disclosure, and the server-side over-disclosure guard that enforces it.

## Verdict

The over-disclosure invariant is **SOUND**. A consent submission can never
disclose more than one minimal satisfying set of the policy:
`minimizeToPolicy` (server-side, authoritative) trims the submitted,
owned ∩ requested badges to a single minimal satisfying selection, and is the
enforcement point regardless of what the UI pre-selects or a tampered POST
ticks. Verified end-to-end, including the absent-policy (flat per-scope) and
malformed-policy paths, by unit tests and the Playwright e2e suite
(`oidc-token-security.spec.ts`, `oidc-policy-selection.spec.ts`).

## Findings

### C-1 — CRITICAL: whole-instance DoS via unbounded `atLeast` combinatorics — FIXED

A crafted `atLeast{ n, of: [...] }` with a large `n` and many duplicate-type
leaves (proven: `n=156` over `160` leaves) stayed shallow, fit under the 4 KB
byte cap, and passed the type-set scope check (one distinct type), yet drove
quartic+ combination enumeration in `selectMinimalAnonymitySet`, freezing the
Node event loop at both authorize-page render and consent-submit. Depth and
byte caps alone do not bound a policy — this is a breadth attack.

Fixed with two layers:

1. **Breadth bounds at parse time** (`lib/oidc-policy.ts`
   `policyBoundsViolation`, wired into `parseMinisterPolicy` in
   `lib/oidc-authorize.ts` right after `parsePolicy`, before any depth /
   selection work): caps `atLeast.n` (`MAX_ATLEAST_N = 16`), per-node child
   count (`MAX_NODE_CHILDREN = 16`), and **total node count across the whole
   tree** (`MAX_POLICY_NODES = 64`). Fail-closed: any violation rejects via the
   existing `redirect-error` path (`invalid_request`).
2. **Bounded alternative enumeration** (`lib/oidc-policy.ts`, `atLeast` branch
   of `selectionsFor`): the chosen minimal set is the top-`n` children by
   anonymity (O(k log k) sort, unchanged). Combination enumeration only exists
   to offer swap alternatives, so it is short-circuited when
   `C(prefix.length, n)` would exceed `MAX_ATLEAST_COMBINATIONS = 500`
   (computed by a saturating `chooseCount`). Which minimal set is chosen is
   unchanged.

Bounds are generous for real room policies (tiny `n`, few branches) but hard.

### W-1 — `holderCountsByType` returned the cached Map by reference — FIXED

`lib/anonymity-sets.ts`: a caller mutating the returned map could corrupt the
60s-cached anonymity ranking. Now returns a fresh defensive copy
(`new Map(value)`) on every call. Cache still serves without re-querying within
the TTL; covered by a new "caller mutation cannot poison the cache" test.

### W-2 — recursive zod parse ran before the breadth check — FIXED

Subsumed by C-1: the total-node-count / breadth bound is applied during/right
after `JSON.parse` + `parsePolicy`, and `MAX_POLICY_BYTES` (4 KB) is kept
tight, so an over-broad tree is rejected as early as possible.

### L-1 — composite OR-branch consent view shows only the first leaf — DOCUMENTED, DEFERRED

`lib/oidc-policy-view.ts` (`buildLeafView` / `firstBadgeType`): a multi-leaf
composite OR-branch is summarized in the consent UI by its first leaf type
only. This is a **display** limitation; server-side minimization evaluates the
full subtree and is authoritative for what is actually disclosed. Documented in
code; not fixed now.

### L-2 — stripped-policy flat consent — DOCUMENTED, DEFERRED

`server/oidc-actions.ts`: when no policy is present (param absent or stripped on
the front channel), `minimizeToPolicy` is the identity and consent falls back
to the flat per-scope flow, which is itself bounded (owned ∩ requested only)
and default-off. A stripped policy cannot widen disclosure beyond the flat
menu. Optional future hardening: bind a signed "policy expected" signal so a
stripped policy is detectable rather than silently downgraded. Documented in
code; not implemented now.

## Gates

typecheck, lint, build, unit (233 passed, incl. new C-1 / W-1 tests), and e2e
(36 passed, incl. over-disclosure and policy-selection specs) all green.
