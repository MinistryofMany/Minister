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
  session — otherwise they could never reach AAL2. Adding a *second login email* or a
  *second/replacement passkey* requires AAL2.
- **Why:** kills the takeover scenario (a leaked magic link is AAL1 and cannot graft
  an attacker credential) without bricking new accounts.
- **Risk to weigh:** the bootstrap exception means a leaked magic link on a
  passkey-less account CAN enroll the first passkey. Mitigation: that enrollment is
  quarantined + notified, and any *second* mutation needs AAL2. Acceptable? Your call.
- **Change:** `requireAal` call sites + the bootstrap check in the add-passkey action.

## 5. New-credential quarantine window = 72h
- **Chose:** `CREDENTIAL_QUARANTINE_MS = 72h`. A newly added email/passkey can sign in
  but can't mutate other credentials or start recovery/merge for 72h.
- **Why:** long enough that the notification email ("a credential was added") reaches a
  human who's traveling/asleep before the new credential gains power.
- **Alt:** 24h (faster legit use) or 7d (safer). Tunable.
- **Change:** `CREDENTIAL_QUARANTINE_MS` in `src/lib/assurance.ts`.

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

  | Badge type | IAL | Weight |
  |---|---|---|
  | `tlsn-attestation` (passport / gov-doc provenance) | IAL3 | 100 |
  | `age-over-N`, `residency-*` backed by tlsn/gov doc | IAL2 | 60 |
  | `oauth-account` (github/google) | IAL1 | 20 |
  | `oauth-account` (discord/steam-class) | IAL1 | 10 |
  | `email-domain` / `email-exact` | IAL1 | 15 |
  | `invite-code` | IAL0 | 0 (not recovery-eligible) |

- **`RECOVERY_THRESHOLD = 100`** — satisfiable by one gov-doc proof, OR a couple of
  IAL2 proofs, OR many low-value ones (deliberately hard: 5+ OAuth links). A single
  low-IAL factor can never recover an account.
- **Why these numbers:** recovery must be **at least as hard as the front door**, and
  low-IAL factors must be near-worthless in aggregate or "I re-linked 5 throwaways"
  becomes a takeover path. Gov-doc dominates because it's the hardest to steal.
- **Change:** `BADGE_ASSURANCE_WEIGHT` + `RECOVERY_THRESHOLD` in `src/lib/assurance.ts`.
  This is the knob you'll most likely want to turn — it's isolated on purpose.

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

---

## Status of each slice (updated as built)

See the final session report / commit log on this branch for what is fully
implemented + tested vs. scaffolded. Anything not green is called out explicitly —
nothing is labeled done that hasn't run.
</content>
