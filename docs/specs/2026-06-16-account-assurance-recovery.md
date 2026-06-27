# Account assurance, recovery, and merge

Status: all 5 slices implemented + unit-tested + green on branch
`feat/account-assurance-recovery` (not yet run against a live DB/browser — see
DESIGNDECISIONS.md #19). Design approved 2026-06-15; implementation 2026-06-16.

## Problem

Minister's identity model has three structural gaps:

1. **Email is load-bearing as identity.** `User.email` was `@unique`, so a second
   email meant a second person. No way to add a work + school email, change an
   email, or sign in with an alternate address.
2. **All credentials are equally trusted, and any live session can rewrite the
   credential set silently.** A leaked magic link was full, permanent, unnotified
   takeover: it could enroll an attacker passkey with no step-up and no alert.
3. **No recovery.** Lose your factors and the account is gone. No recovery codes,
   no backup path, no way to swap a dead email.

## Organizing abstraction: assurance levels (AAL/IAL)

One concept pays for step-up, recovery, the magic-link-vs-passkey distinction, and
weighted recovery: an **authentication assurance level** on every credential,
session, and operation (NIST 800-63 AAL), plus an **identity assurance level** on
every badge (IAL), used as recovery weight.

- Credential -> AAL: passkey = AAL2 (phishing-resistant), magic link = AAL1,
  recovery code = AAL1 (lands quarantined), TOTP (future) = AAL2-when-paired.
- Session carries the AAL it was obtained at (a JWT claim, like the existing `gen`).
- Sensitive operations declare a required AAL floor; a server guard enforces it and
  triggers step-up when the session is below the floor.
- Badge -> IAL -> recovery weight (a code-level map, tunable without migration).

## The five slices

### Slice 1 — Multi-credential identity

- `UserEmail` (many per user, one `isPrimary`, each `verifiedAt`, global-unique
  `email`). `User.email` is now a denormalized cache of the primary.
- Custom Auth.js adapter: `getUserByEmail` and the email sign-in path resolve
  email -> `UserEmail` -> user. `createUser` writes both `User.email` (primary
  cache) and a `UserEmail` row. `linkAccount`/`createAuthenticator` stamp lifecycle
  fields.
- Credential-management UI: list emails + passkeys + linked accounts; add/remove
  email; set primary; add/remove passkey; everything gated by the AAL2 guard.

### Slice 2 — Assurance + step-up + quarantine + notify

- `aal` claim on the session JWT, set from the authenticating credential.
- `requireAal(session, floor)` server guard. Floor for any credential mutation,
  primary-email promotion, recovery start, or merge start = AAL2.
- New credentials land `status = "quarantined"`, `quarantinedUntil = now + COOLDOWN`.
  A quarantined credential can sign in but cannot mutate other credentials or start
  recovery/merge.
- Every credential mutation writes an `AuditLog` row and emails all verified
  addresses with a one-click "wasn't me -> revoke + lock" link.

### Slice 3 — Recovery codes

- `RecoveryCode` (Argon2id hashes, single-use). Generate 10, show once, hash at
  rest. Regenerate deletes unused rows.
- Redeeming one lands a **quarantined, reduced-assurance** session: can enroll a
  fresh passkey, rate-limited, notifies all emails, cannot evict other credentials.
- Cold-start backstop for the user with one passkey and no badges.

### Slice 4 — Weighted badge-threshold recovery

- Per-badge `assuranceLevel` (set at issuance from a registry of (type, provenance)
  -> IAL). Code-level weight map IAL -> points.
- `RecoveryAttempt` (nonce, requiredScore, accumulatedScore) + `RecoveryProof`
  (one per badge type, weight). Recovery **re-runs live verification** bound to the
  attempt nonce — a stored `Badge.vcJwt` is NOT accepted (no replay). Public badges
  do not count. `(attemptId, badgeType)` unique so a type can't double-count.
- Satisfying the threshold lands the same quarantined, reduced-assurance session as
  recovery codes. Threshold calibrated >= front-door auth strength.

### Slice 5 — Account merge

- Dual-control: prove control of both accounts at AAL2 in one ceremony before
  anything moves.
- Survivor keeps its `userId`; donor is reconciled in and tombstoned
  (`mergedIntoUserId`/`mergedAt`), hard-deleted after the reversal window.
- Data reconciliation with explicit collision rules:
  - `Eligibility @@unique([userId, badgeType])`: keep earlier `eligibleAt`.
  - `InviteRedemption @@unique([inviteCodeId, userId])`: keep one (already spent).
  - `Badge`: union (optionally dedupe identical `(type, attributes)`).
  - Donor emails -> survivor `UserEmail` rows.
  - `isBanned`: sticky-OR (survivor banned if either was). `isAdmin`: survivor's
    value, never escalate from donor. Bump `sessionGeneration`.
- **Subject-override seam (lossless-for-RPs):** for each client the donor had token
  history with (`OidcAccessToken[userId, clientId]`), write a `SubjectOverride` row
  on the survivor carrying the donor's old pairwise sub. The survivor then presents
  the donor's historical identity to RPs the donor used. Irreducible limit: if both
  accounts used the same RP, one login presents one sub — the user picks; the other
  is stranded (documented).
- `MergeRecord.snapshot` holds enough to reverse within `reversibleUntil`.

## Key interface contracts (so slices compose)

- `src/lib/assurance.ts`:
  - `type Aal = 0 | 1 | 2`
  - `aalForCredential(kind: "passkey" | "email" | "recovery-code" | "totp"): Aal`
  - `BADGE_ASSURANCE_WEIGHT: Record<string /* IAL */, number>` and
    `assuranceLevelFor(badgeType: string, provenance?: string): string`
  - `RECOVERY_THRESHOLD: number`, `CREDENTIAL_QUARANTINE_MS: number`
- Session: extend the JWT/session with `aal: Aal`. `getCurrentSession()` returns it.
  `requireAal(floor: Aal)` throws a typed `StepUpRequiredError` the UI catches to
  route into step-up.
- `pairwiseSub(userId, clientId)` stays a PURE sync HMAC (keep its tests). Add
  `async resolveSub(userId, clientId)` = check `SubjectOverride`, else `pairwiseSub`.
  Update `/oidc/token` and `/oidc/userinfo` call sites to `await resolveSub(...)`.

## Constraints

- ZK / crypto unchanged. No secrets in code. Commits authored as AtHeartEngineer.
- Built on a worktree against a scratch DB (`minister_spike`); the live dev DB and
  `main` are untouched. No migration is applied to the live DB — see
  DESIGNDECISIONS.md (migrations vs db push).
