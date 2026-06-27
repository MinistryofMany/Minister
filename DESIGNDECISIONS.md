# Design decisions — account assurance, recovery, merge

Every judgment call made while building slices 1–5 on branch
`feat/account-assurance-recovery`, with context and how to change it. Built on a
worktree against the scratch DB `minister_spike`; nothing here touched `main` or the
live dev DB. Review and veto anything; we can adjust before this merges.

Legend: **Chose** = what's implemented. **Alt** = the alternative. **Change** = the
one place to flip it.

---

## 1. Primary key stays `cuid()`, not UUID

- **Chose:** leave `User.id` as `@default(cuid())`. The architectural ask ("don't
  key identity on email") is satisfied by demoting `User.email`, not by changing the
  PK — the id was already opaque.
- **Alt:** switch the generator to `uuid(7)` (time-sortable). Pure churn: migrates
  every PK + FK for no security gain.
- **Change:** the `@id` line on each model + a data migration. Recommend not doing it
  unless you need UUID specifically for external interop.

## 2. Schema is synced with `db push`, no migration files

- **Context:** Minister has no `prisma/migrations/` dir — dev uses `db push`. This
  change (drop a unique, add 6 tables) is big enough that a reviewable migration is
  arguably worth it.
- **Chose:** push to the scratch DB for testing; do NOT introduce a migrations dir or
  touch the live DB. The SQL diff is reviewable via
  `prisma migrate diff --from-... --to-schema-datamodel`.
- **Alt:** adopt `prisma migrate` now (baseline migration + this change).
- **Change:** run `prisma migrate dev --name account_assurance_recovery` once you
  decide; it will create the baseline + this delta. Open question for you.

### Revised 2026-06-17 (design review with Tyler)

**Decided: adopt `prisma migrate` - but baseline AFTER this wave of schema changes
settles, not now.** Keep `db push` through the in-flight rework (the OIDC profile-grant
fields just added; then the session acting-credential columns, the `RecoveryProof`
unique-key change, and the account-assurance tables). Once the schema has stabilized in
its post-rework shape, create the baseline migration (capturing current state, marked
applied via `migrate resolve --applied`) and route all subsequent changes through
`prisma migrate`. Rationale: baselining now would immediately churn against the queued
changes; baselining as the capstone gives one clean starting point. Migrations are
wanted for reviewable diffs + cross-machine reproducibility (Tyler works across
computers).

## 3. AAL is numeric `0|1|2`; magic link = AAL1, passkey = AAL2

- **Chose:** `type Aal = 0 | 1 | 2`. Email magic link authenticates at AAL1
  (single factor, inbox-bound). Passkey authenticates at AAL2 (phishing-resistant).
  Recovery code / threshold recovery land at AAL1 **and** quarantined.
- **Why:** matches NIST 800-63B intent (passkey is AAL2-grade; email link is not).
- **Alt:** strings (`"aal1"`); or treat magic link as AAL0. Numeric compares cleanly
  for `>= floor`.
- **Change:** `aalForCredential` in `src/lib/assurance.ts`.

## 4. Credential mutations require AAL2; first-passkey bootstrap is the exception

- **Chose:** adding/removing an email or passkey, promoting a primary email, starting
  recovery, and starting merge all require AAL2. **Exception:** a brand-new
  magic-link-only user (no passkey yet) may enroll their FIRST passkey from an AAL1
  session — otherwise they could never reach AAL2. Adding a _second login email_ or a
  _second/replacement passkey_ requires AAL2.
- **Why:** kills the takeover scenario (a leaked magic link is AAL1 and cannot graft
  an attacker credential) without bricking new accounts.
- **Risk to weigh:** the bootstrap exception means a leaked magic link on a
  passkey-less account CAN enroll the first passkey. Mitigation: that enrollment is
  quarantined + notified, and any _second_ mutation needs AAL2. Acceptable? Your call.
- **Change:** `requireAal` call sites + the bootstrap check in the add-passkey action.

### Revised 2026-06-17 (design review with Tyler)

- **Hardening = option C (account-level), but step-up, not a time-block.** A destructive
  credential action (remove email, set primary, remove passkey, start merge/recovery)
  from a session riding a fresh / quarantined credential is NOT blocked for 72h. Instead
  it requires a fresh **email confirmation** (risk-adaptive step-up): more risk -> a
  higher bar, never a hard wall. Confirmation links go to all verified emails, so a
  second verified email alerts the real owner. Honest limit: if the attacker controls
  your only inbox, a confirmation to it doesn't stop them - same as today.
- **The bootstrap passkey is currently active + notified but NOT quarantined**, despite
  the original #4 text claiming "quarantined + notified". So today a leaked magic link on
  a passkey-less account can enroll a first passkey, sign in with it to reach AAL2, and
  evict the owner. Fix owed (above + below).
- **Sessions must record how they logged in** (auth method + acting credential id + aal +
  recovered). This is the real fix for #15 and what lets the step-up say "this action is
  coming from the freshly-bootstrapped credential."
- **Open, app-wide decision:** doing this well points at dropping JWT-strategy sessions
  for Auth.js DB-backed sessions (opaque id + a `Session` row, which already exists in
  the schema, unused). JWT here pays staleness + no per-session revocation while
  `getCurrentSession()` already does a per-request DB read - costs without the benefit
  (see samsch gist: https://gist.github.com/samsch/0d1f3d3b4745d778f78b230cf6061452).
  Options: (1) switch to DB sessions [recommended ★★★★★], (2) JWT + per-session
  revocation table [worst of both ★★], (3) keep as-is [★★]. **DECIDED 2026-06-17: option 1.** Sequence: implement the session switch as its own
  self-contained unit first, then stack the reworked account-assurance work on top of
  it - the old feat branch (112f890) is built on the now-replaced JWT model, so we lift
  logic from it rather than rebase. Keeps the app-wide session change reviewable on its
  own and avoids rewriting auth.config / session.ts twice.

## 5. New-credential quarantine window = 72h

- **Chose:** `CREDENTIAL_QUARANTINE_MS = 72h`. A newly added email/passkey can sign in
  but can't mutate other credentials or start recovery/merge for 72h.
- **Why:** long enough that the notification email ("a credential was added") reaches a
  human who's traveling/asleep before the new credential gains power.
- **Alt:** 24h (faster legit use) or 7d (safer). Tunable.
- **Change:** `CREDENTIAL_QUARANTINE_MS` in `src/lib/assurance.ts`.

### Revised 2026-06-17 (design review with Tyler)

Reframed from a hard block to **risk-adaptive step-up** (see #4): a freshly-added
credential is not blocked for 72h - for 72h it is treated as elevated risk and its
sensitive actions require email-confirmation step-up instead. 72h kept (covers a long
weekend); must stay an easily-tunable single constant (`CREDENTIAL_QUARANTINE_MS`).

## 6. Recovery codes: 10 codes, single-use, Argon2id, regenerate invalidates

- **Chose:** generate 10 codes (`base32`, grouped), show once, store only Argon2id
  hashes (same hasher as `OidcClient.clientSecretHash`). Regenerating deletes all
  unused codes. Redeeming one consumes it and lands a quarantined AAL1 session.
- **Alt:** 8 or 16 codes; bcrypt. 10 is the common default (GitHub/Google).
- **Change:** `RECOVERY_CODE_COUNT` in the recovery-codes lib.

## 7. Badge IAL mapping + recovery weights (THE scoring — most worth your review)

- **Context:** your idea — recovery weight should reflect how hard a credential is to
  forge or for an attacker to also hold. Passport >> Steam.
- **Chose (proposed, tunable):**

  | Badge type                                         | IAL  | Weight                    |
  | -------------------------------------------------- | ---- | ------------------------- |
  | `tlsn-attestation` (passport / gov-doc provenance) | IAL3 | 100                       |
  | `age-over-N`, `residency-*` backed by tlsn/gov doc | IAL2 | 60                        |
  | `oauth-account` (github/google)                    | IAL1 | 20                        |
  | `oauth-account` (discord/steam-class)              | IAL1 | 10                        |
  | `email-domain` / `email-exact`                     | IAL1 | 15                        |
  | `invite-code`                                      | IAL0 | 0 (not recovery-eligible) |

- **`RECOVERY_THRESHOLD = 100`** — satisfiable by one gov-doc proof, OR a couple of
  IAL2 proofs, OR many low-value ones (deliberately hard: 5+ OAuth links). A single
  low-IAL factor can never recover an account.
- **Why these numbers:** recovery must be **at least as hard as the front door**, and
  low-IAL factors must be near-worthless in aggregate or "I re-linked 5 throwaways"
  becomes a takeover path. Gov-doc dominates because it's the hardest to steal.
- **Change:** `BADGE_ASSURANCE_WEIGHT` + `RECOVERY_THRESHOLD` in `src/lib/assurance.ts`.
  This is the knob you'll most likely want to turn — it's isolated on purpose.

### Revised 2026-06-17 (design review with Tyler) — supersedes the table above; NOT yet implemented

The fixed-threshold model above is replaced by a **value-scaled, two-weight**
model. Recorded here so it survives across machines; the code still reflects the
original until the implementation pass.

**1. Per-(type, domain) identity + falloff, not per-type dedup.** A proven factor
is keyed by `(badgeType, domain, account)`, where `domain` is the OAuth provider
(github/google/discord) or the email domain. The same exact account can't be
re-proven twice (replay guard), but different accounts at the same provider now
stack with **diminishing returns**: each additional factor sharing the same
`(type, domain)` is worth half the previous (20 -> 10 -> 5 -> 0), applied to BOTH
weights below. The domain is an identity key only, not a quality score - we do not
rank gmail below a custom domain, because the system can't see that a given gmail
runs a company Workspace.

**2. Two weights per badge - `protect` and `proof`.**
- `protect` raises the account's value (how much losing it costs).
- `proof` is how much re-proving it counts toward recovery (how hard for an
  attacker to also re-prove it live).
- Equal for most badges. **Email is the deliberate exception**: high `protect`
  (losing an inbox is dangerous - resets bank logins, etc.) but low `proof` (it's
  phishable, and re-proving an email is ~equivalent to just logging in by magic
  link). So a phishable email can never be its own cheap way back in.

| Badge | protect | proof |
| --- | --- | --- |
| passport / "US Citizen" (TLSNotary or OpenPassport) | 100 | 100 |
| age-over-* / residency-* (gov-doc backed) | 60 | 60 |
| oauth github / google | 20 | 20 |
| oauth discord / steam / social | 10 | 10 |
| email (any domain) | 20 | 5 |
| invite-code | 0 | 0 |

**3. Value-scaled bar with a cap.** Account value `V` = sum of `protect` over the
account's **re-provable** badges (with falloff). Recovery bar
`T = min(0.50 * V, 100)`. Recovery succeeds once the accumulated `proof` of
live-re-proven badges (with falloff) reaches `T`.
- The 0.50 ratio means any single badge worth more than half the account's value
  becomes effectively mandatory to re-prove (e.g. a passport in a rich account).
- The cap of 100 = a passport's proof weight, so holding one gov-doc-grade badge
  always lets you recover no matter how rich the account; the bar never exceeds
  re-proving that one strong credential.
- Only re-provable badges count toward `V`, so un-re-provable junk can't raise the
  bar with no way to clear it (today only invite-code is un-re-provable, weight 0).

Worked examples:
- Thin (google 20 + gmail 8): V=28, T=14; re-prove google (proof 20) clears it.
- Rich (passport 100 + github 20 + google 20 + email 20): V=160, T=80; everything
  except the passport = proof 45 < 80, so the **passport is mandatory**.
- Valuable-email, no strong badge (email 20 + google 20 + github 20): V=60, T=30;
  two logins = proof 40 >= 30 clears it, but the email alone (proof 5) never can.
- A thin email-only account can't threshold-recover (proof 5 < its bar), which is
  fine: if you can re-prove the email you can just log in by magic link. Threshold
  recovery is for when login factors are lost but other re-provable badges remain.

**4. Engineering requirements for the implementation pass.**
- All tunables (the two-weight table, the 0.50 ratio, the 100 cap, the 0.5 falloff
  factor, the recovery-eligible type set) live in ONE well-decomposed config block
  at the top of the scoring module or a dedicated config file, so the numbers are
  easy to play with.
- Add a typed `RecoveryPolicy` seam so a user can later pick their own recovery
  threshold/mechanisms within bounds; default it to the global config, leave a
  `TODO` for the per-user override, build no UI/logic now (stub).
- Leave a `TODO` near this code: build a simulator / toy demo page to experiment
  with these values and see what feels right (deferred).

**5. Schema impact.** `RecoveryProof`'s unique key moves from `(attemptId,
badgeType)` to `(attemptId, badgeType, domain, account)`; weight is computed at
record-time from how many same-`(type, domain)` proofs already landed in the
attempt.

**Doc fix owed:** the original #7 line "satisfiable by ... many low-value ones
(deliberately hard: 5+ OAuth links)" describes behavior the schema forbade
(per-type dedup capped OAuth at one row). The new model makes stacking real (with
falloff), so reword that when the as-built doc is updated.

## 8. Only LIVE re-proof counts for recovery; stored VCs and public badges don't

- **Chose:** threshold recovery re-runs the actual plugin verification (re-do the
  OAuth dance / TLSNotary proof) bound to `RecoveryAttempt.nonce`. A stored
  `Badge.vcJwt` is never accepted (replay defense). `Badge.isPublic` badges do not
  count (an attacker can enumerate them and target exactly those).
- **Recovery-eligible badge types:** only those a plugin can re-prove live
  (`oauth-account`, `email-domain`/`email-exact`, `tlsn-attestation`). One-shot types
  (`invite-code`) can't be re-proven and are weight 0.
- **Change:** the recovery-eligibility set in the recovery lib; per-plugin re-proof
  hooks.

## 9. Recovered / quarantined session capabilities

- **Chose:** a session obtained via recovery code OR threshold recovery is AAL1 +
  flagged `recovered`. It can: enroll a fresh passkey (to climb to AAL2), view the
  account. It cannot: remove other credentials, change primary email, start a merge,
  or disclose badges to RPs until the user re-establishes an AAL2 factor. All recovery
  events notify every verified email.
- **Why:** recovery is the floor of account security; a recovered session must not be
  able to instantly evict the legitimate owner.
- **Change:** the capability checks keyed on the `recovered` session flag.

## 10. Single-primary-email enforced in app logic, not a DB constraint

- **Context:** Postgres can't portably express "exactly one `isPrimary=true` per
  user" via Prisma.
- **Chose:** enforce inside the transaction that flips primary (clear others, set one).
- **Alt:** a partial unique index via raw SQL (`WHERE isPrimary`). Stronger, but
  outside Prisma's schema and easy to forget on restore.
- **Change:** the set-primary server action (and add a raw partial index later if you
  want belt-and-suspenders).

## 11. `SubjectOverride` has no `@@unique([clientId, sub])`

- **Context:** during the merge reversal window the donor still exists (tombstoned).
  A unique on `(clientId, sub)` could collide with the donor's still-derivable sub.
- **Chose:** no such constraint; the invariant ("a client never sees one sub for two
  live users") is upheld by app logic + the donor being tombstoned (can't log in).
- **Change:** add the constraint only if reversal is dropped.

## 12. Merge survivor = the account you're signed into; donor proven second

- **Chose:** you start merge from the account you want to KEEP (already AAL2), then
  prove control of the donor (passkey or magic-link round-trip). Survivor keeps its
  RP identities for free; the override seam carries the donor's over.
- **Alt:** let the user pick survivor after proving both. More flexible, more UI.
- **Change:** the merge ceremony entry point.

## 13. Merge reversal window = 7 days; ban sticky-OR; admin never escalates

- **Chose:** donor tombstoned, hard-deleted after 7 days. `isBanned` survivor = donor
  OR survivor. `isAdmin` = survivor's existing value (merge never grants admin).
- **Change:** `MERGE_REVERSAL_DAYS`; the flag-merge rules in the merge transaction.

## 14. TOTP not built tonight

- **Context:** you asked about TOTP. It fits the AAL model as an AAL2-when-paired
  factor, but it's weaker than the passkey already supported and isn't one of the five
  slices.
- **Chose:** leave a clean seam (the `aalForCredential` map already lists `"totp"`)
  but don't implement. Recovery codes + a second passkey cover the same need better.
- **Change:** add a TOTP credential table + enroll/verify flow later; the AAL plumbing
  already accepts it.

## 15. Acting-credential quarantine can't be fully enforced yet

- **Context:** the design says a _quarantined_ credential can sign in but can't mutate
  other credentials. The session JWT carries the AAL but NOT which credential row
  authenticated it, so the server can't say "the credential this session was obtained
  with is itself quarantined."
- **Chose:** enforce what the JWT proves — the AAL2 floor — and additionally fail
  closed on `session.recovered`. This already blocks the main attack (a quarantined
  magic-link credential is AAL1 and can't pass the AAL2 floor).
- **Gap:** a quarantined _passkey_ (AAL2) could pass the floor. To close this fully,
  thread the authenticating credential id onto the JWT and reject if it's quarantined.
- **Change:** add a `cred` claim in `auth.config.ts` jwt callback + check it in the
  credential actions. Small follow-on.

## 16. reverseMerge restores ownership, not content

- **Chose:** `reverseMerge` (within the 7-day window) un-tombstones the donor, moves
  every snapshotted row back by primary key, recreates deleted collision losers,
  restores flags + demoted primary emails, and removes created subject-overrides.
- **Does NOT restore:** if the survivor _edited the content_ of a moved row during the
  window, reversal moves the row back to the donor with the edited content (it restores
  ownership, not the pre-merge field values). Documented in the `reverseMerge` doc
  comment. Acceptable for a 7-day undo window; full content-versioning is out of scope.

### Revised 2026-06-17 (design review with Tyler)

**Direction reversed: we DO want full content versioning - but as an admin-only account
history with point-in-time rollback, NOT user-facing undo.** Users' changes are
forward-only (no undo): a user-facing undo is an attacker tool (reverse a credential
removal, undo sign-out-everywhere, undo recovery hardening). Rollback lives only behind
`requireAdmin`, audited.

- `reverseMerge` is currently **unwired** (library function + tests, no server action),
  so honoring "no user undo" is free; wire reversal behind admin when the general system
  lands. The merge email over-promises ("a merge can be reversed for a limited time")
  with no endpoint behind it - wire admin reversal or soften the copy.
- **Treat full versioning as its own initiative** (design -> spec -> build), decoupled
  from the account-assurance rework; merge-undo becomes one case it subsumes.
- **Mechanism (lean: option 1)** built on the append-only `AuditLog`: (1) reversible
  change-journal with redacted before/after diffs, admin applies inverses [★★★★]; (2)
  row-level history / temporal tables, restore "as of" a timestamp [★★★]; (3)
  snapshot-on-change [★★].
- **Settle at spec time:** PII/secret redaction (no raw VC JWTs, magic-link tokens, PKCE
  verifiers, plugin step data - secrets versioned by reference, never by value); whether
  credentials are revertible at all (re-granting a removed credential is double-edged
  even for an admin); retention (full vs windowed).

## 17. Live re-proof wired for email-domain only; oauth + tlsn are typed stubs

- **Chose:** slice 4's threshold _accounting_ is complete and exhaustively tested, and
  `email-domain` re-proof is wired end-to-end (nonce-bound single-use link).
  `oauth-account` and `tlsn-attestation` re-proof are typed integration points that
  **throw "not yet wired"** — they are not faked. `email-exact` is eligible/weighted
  but has no plugin in the repo, so no live path exists.
- **Impact:** today, threshold recovery is only reachable by someone with an
  `email-domain` badge. Wiring the OAuth dance (state === attempt nonce) and the
  TLSNotary re-presentation is the remaining work to make slice 4 fully useful.
- **Change:** implement the two `complete*ReProof` functions in
  `recovery-threshold-actions.ts`.

## 18. Donor-proof hand-off is copy-paste (v1)

- **Chose:** the merge donor authenticates via a magic link to a verified donor email;
  the donor confirm page shows a single-use code the human pastes into the survivor's
  session to finish the merge. Keeps `confirmMerge` inside the survivor's AAL2 session.
- **Alt:** a fully redirected ceremony (no paste). More polish, more flow state.
- **Change:** `merge-actions.ts` + the `/settings/merge/confirm-donor` page.

## 19. Not applied to the live DB; no end-to-end run yet

- All work is on the `feat/account-assurance-recovery` worktree against the scratch DB
  `minister_spike`. The live dev DB and `main` are untouched. The schema change has NOT
  been applied to the live DB (see #2).
- **Tested:** typecheck clean; 323 unit tests green (pure logic + crypto, Prisma mocked
  following the house pattern). **Not yet run:** the DB-backed server actions, the
  WebAuthn ceremonies, the email round-trips, and the OIDC flows against a live server —
  these need an integration/e2e pass (and the e2e helpers may need to resolve users via
  `UserEmail`). Nothing DB-backed has executed against Postgres yet.

---

## Build status by slice

| Slice                        | Logic + tests             | UI    | Notes                                          |
| ---------------------------- | ------------------------- | ----- | ---------------------------------------------- |
| Spine (AAL/adapter/sub-seam) | done, 38 tests            | n/a   | verified by orchestrator                       |
| 1+2 Credentials + step-up    | done, 28 tests            | built | acting-cred quarantine gap (#15)               |
| 3 Recovery codes             | done, 17 tests            | built | actions not live-DB-tested                     |
| 4 Weighted badge recovery    | accounting done, 30 tests | built | only email-domain re-proof wired (#17)         |
| 5 Account merge              | done, 25 tests            | built | reverseMerge content caveat (#16); paste (#18) |

323 unit tests total, typecheck + lint clean. Nothing here has been run against a live
database or browser — see #19.
