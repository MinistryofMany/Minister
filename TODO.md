# Minister — TODO

Things we've explicitly mocked, stubbed, or skipped — paired with what
needs doing later. Anything tagged here is a known gap, not a bug.

## TLSNotary (Stage 6 — partial)

The Minister-side scaffolding is real and tested. The cryptographic
proof path is not. Three concrete pieces remain:

### 1. Browser-extension TLSNotary prover

**Where:** `apps/extension/src/background.ts`

**What's there:** MV3 manifest, background service worker, popup, and
the message-routing surface (popup → background → submit-presentation).
The background's `submitPresentation` helper already POSTs to
`/api/tlsn/submit` and handles the response.

**What's missing:** `performProof()` currently throws `"TLSNotary
prover not yet wired"`. Need to:

- Add `tlsn-js` as a dep and load its WASM in an offscreen document
  (MV3 service workers can't host heavy WASM in the worker context).
- Open a session against the target URL via the `ws-proxy` (see below).
- Exchange handshakes with the notary server.
- Return the finalized presentation as base64.
- Cross-check the crate / image versions match: notary is pinned to
  `ghcr.io/tlsnotary/notary-server:v0.1.0-alpha.11`; `tlsn-js` must be
  compatible.

### 2. `ws-proxy` service

**Where:** `services/ws-proxy/`

**What's there:** alpine Dockerfile stub, commented out in
`docker-compose.yml`.

**What's missing:** A real WebSocket → TCP relay. The browser extension
can't open raw TCP sockets, so it tunnels through this proxy to reach
the target HTTPS host. Implementation should:

- Be in Rust or Go (TCP socket lifecycle is the bulk of the work).
- Take WS connections from the extension carrying `{ host, port }`.
- Open a TCP socket to the target, bidirectionally relay bytes.
- Rate-limit + allow-list target hosts (id.me, github.com, etc.). We
  must not become an open proxy.
- Uncomment the compose service entry and wire the URL into the
  extension's config.

### 3. `tlsn-verifier` crate integration

**Where:** `services/tlsn-verifier/src/main.rs`, `verify_real()`

**What's there:** Real Rust Axum HTTP server. `passthrough` mode
(default) base64-decodes a JSON "presentation" of shape
`{ sent, received, serverName }`, enforces server-name match, returns
it. Unit tests cover passthrough.

**What's missing:** `verify_real()` currently throws to make sure no
one accidentally ships prod with the rubber-stamp path enabled. Need
to:

- Pin the `tlsn-verifier` crate in `Cargo.toml` (commented entry is
  there). Match the notary image version.
- Implement `verify_real()` against the crate API — call its
  `Verifier::verify(&presentation, ...)`, extract the verified TLS
  transcript, return it in the same `Transcript { sent, received,
serverName }` shape.
- Switch `VERIFIER_MODE=real` in compose / prod env.
- Add tests with a real captured presentation as a test fixture.

### Why the Minister side still works

`tlsn-attestation` plugin + `/api/tlsn/submit` endpoint round-trip
through the verifier sidecar, which can be exercised end-to-end in
passthrough mode. So Stage 7+ work can build on top of TLSNotary
plumbing without blocking on the prover.

---

## Stage 9 hardening (deferred by design)

These are intentional Stage 9 items, listed here so they don't get
lost:

- ~~Rate limiting on `/oidc/token`, `/oidc/authorize`,
  `/api/auth/signin/*`, share-link views.~~ Done — in-memory
  sliding-window limiter (`src/lib/rate-limit.ts`) on all of those plus
  `/oidc/userinfo` and `/api/tlsn/submit`. Process-local by design;
  swap the limiter internals for Redis (Upstash) if Minister ever runs
  more than one instance.
- KMS-backed signing key (currently dev: ephemeral persisted JWK at
  `apps/minister/dev-keys/issuer.jwk`).
- ~~Real email transport (Resend / SES).~~ Done — `src/lib/mailer.ts`
  sends via Resend's HTTP API when `RESEND_API_KEY` + `MAIL_FROM` are
  set; otherwise dev console-logs and prod throws. Sign-in magic links,
  plugin emails, and share-link emails all route through it. **Not yet
  done:** a live send hasn't been verified against a Resend account —
  needs a verified sender domain and a confirmed test recipient (see
  `docs/email-setup.md`).
- ~~Audit-log review UI at `/admin/audit`.~~ Done (consolidation work) —
  basic paginated viewer; filters/search still Stage 9 material.
- OIDC security-review pass: refresh tokens, scope-creep prevention,
  error-response side channels.
- Production deploy guide.

---

## Consolidation — dropped / not ported

The prior Express/tRPC Minister iteration (originally at
ahes:/tank/Minister) had its invite-code gateway and admin panel ported
here, then was deleted — both the server copy and the local archive.
What wasn't ported is listed below; re-building any of it means
re-implementing against this codebase, not restoring old code.

- **Q&A gateway** — not ported. Would need a `QnaChallenge` model +
  admin CRUD; the old `requireReview` flow also implies a pending-review
  badge state Minister's `Badge` model doesn't have.
- **Review-queue / badge approval workflow** — not ported (same reason:
  no pending state on `Badge`).
- **Aadhaar / anon-aadhaar zk gateway** — not ported (explicitly out for
  now). If revived: `@anon-aadhaar/core` Groth16 verification, UIDAI
  trust-list pinning + rotation, nullifier dedup, age/gender disclosure.
- **Mobile app / passport NFC (openpassport-style)** — not ported. The
  old spike proved Expo + NFCPassportReader (iOS) / JMRTD (Android)
  linking via EAS; Mopro was deferred as its own task.

---

## Account assurance / recovery - security follow-ups

From the 2026-06-27 security audit of the account-assurance + recovery + merge
work (landed together with OIDC Phase 3 grant disclosure). None are blocking for
the alpha; all are accepted, known gaps.

### H-1 (High) - credential quarantine cooldown is not enforced — RESOLVED 2026-07-12

**Was:** quarantine fields were written at credential-add and displayed, but no
production code read them to gate an operation, so a session that had just
reached AAL2 via a freshly-grafted (still-quarantined) passkey could
immediately start a merge, generate recovery codes, or change the primary
email.

**Shipped:** a two-layer gate (`src/lib/credential-lifecycle.ts` pure policy +
`src/lib/credential-gate.ts` DB wrappers) enforced by `startMerge`,
`confirmMerge` (before the donor proof is consumed), `generateMyRecoveryCodes`,
and `setPrimaryEmail`:

1. the user must hold >=1 non-quarantined passkey (lazy window expiry via
   `effectiveCredentialStatus`), and
2. when the session's `cred` JWT claim (new; stamped in `auth.config.ts` on
   every passkey auth event) names the acting passkey, that passkey must be
   non-quarantined and still on the account — cleared instantly by re-authing
   with an established passkey (the UIs run the ceremony and retry once).

Passkey quarantine + the "a passkey was added" notification also moved to
WRITE time (`createAuthenticator` override in `src/auth.ts`), closing the
bypass where a raw WebAuthn ceremony skipped the client-side
`markPasskeyEnrolled` finalize (now a read-only reporter). Refusals are typed
results with finished user copy + `retryAt`, audited as
`credential.quarantine_refused`.

**Residual (known, accepted):**

- A pre-deploy JWT without the `cred` claim passes layer 2 while it lives
  (layer 1 still applies); a daily-active session can slide indefinitely.
- The bootstrap first passkey is active immediately (DESIGNDECISIONS #4), so
  the leaked-magic-link -> bootstrap-passkey -> pivot path on a PASSKEY-LESS
  account remains (#4-revised "fix owed": email-confirmation step-up).
- A user whose only passkey is in-window (e.g. enrolled a new key then removed
  the old) waits out the <=72h hold for these four actions; copy says exactly
  when it clears. The #4-revised email-confirmation step-up would soften this.

### OidcGrant rows are not migrated on account merge

**Where:** `apps/minister/src/lib/merge.ts` / `src/server/merge-actions.ts` vs
the Phase 3 `OidcGrant` model.

**What:** `merge.ts` re-points 15 donor->survivor models but does not know about
`OidcGrant` (new in Phase 3; the merge code predates it). After a merge, a
donor's `OidcGrant` rows (the durable "already proven these badge types to this
RP" record) stay on the tombstoned donor and cascade-delete when the donor is
hard-deleted. The survivor does not inherit the donor's already-proven history
for RPs only the donor used.

**Why it matters:** Minor - only the consent screen's "you've already proven
these to this platform" transparency display is affected; no data leak, no auth
break. After a merge the survivor may be re-shown a donor-only RP's badges as
not-yet-proven.

**Fix:** Add `tx.oidcGrant` handling to the merge transaction - union-OR the
donor's `badgeTypes` / `profileName` / `profileAvatar` into the survivor's
`(userId, clientId)` row, with collision handling on the
`@@unique([userId, clientId])`, mirroring how `subjectOverride` is merged.

### Donor auth codes survive a merge and /token ignores the tombstone

**Where:** `apps/minister/src/app/oidc/token/route.ts` and
`apps/minister/src/lib/merge.ts` (pre-existing; NOT a regression of the Phase 7
pairwise seam - the same held when donor subs were derived in-txn).

**What:** `mergeAccounts` neither consumes nor re-points `OidcAuthorizationCode`
rows, and the `/token` user lookup selects only `id/displayName/avatarUrl` with
no `mergedIntoUserId` check (userinfo likewise). A donor auth code minted just
before a merge (60s TTL, PKCE held by the donor's own browser) can redeem AFTER
the merge commits: `resolveSub(donorUserId, clientId)` finds no override (the
donor's own overrides were re-pointed to the survivor) and derives the donor's
sub, minting a fresh `OidcAccessToken` on the tombstoned donor - a live token
for a merged-away account, outside the reversal snapshot, with the survivor
holding no override for that client. Bounded by the 60s auth-code TTL but
unhandled. The Phase 7 RepeatableRead merge txn closes the _in-txn_ drift window
(a token committed mid-merge now stays on the donor); this is the _post-commit_
class the drift check always documented as out of scope.

**Why it matters:** The same un-preserved-sub state the in-txn drift check aborts
on, reachable for ~60s post-commit. Fail direction is a stale token on a
tombstoned donor whose badges have all moved, not a cross-account leak.

**Fix (two cheap closures, orthogonal to the pairwise seam):** (1) delete the
donor's `OidcAuthorizationCode` rows inside the merge transaction (consider
WizardSession-adjacent pending flows too); (2) select `mergedIntoUserId` in the
`/token` (and `/userinfo`) user lookup and refuse with `invalid_grant` /
unauthorized when non-null. Deferred here because the `/token` guard is a
behavioral change to the OIDC endpoints, separate from the merge/seam surface
this PR touches - filed per the auditor's own recommendation.

---

## crypto-core Phase 5 (email dedup) — accepted follow-ups

These are deliberate deferrals from the Phase 5 finalization review, not stubs.
Each is safe for the interim window (near-zero users) and recorded so the
gate-claim/code gap is never silent.

- **Provider table is deliberately minimal (under-normalization accepted).**
  `PLUS_TAG_IGNORING_PROVIDERS` covers only outlook/hotmail/live (+ gmail's
  dot/tag rules). iCloud/Proton/Fastmail and Microsoft regional consumer
  domains (hotmail.co.uk, outlook.fr, msn.com, …) also subaddress with `+tag`
  but are intentionally omitted — ADR §2.3 fails toward NOT over-matching, and
  `email-domain`/`email-exact` are `sybilResistance: "weak"`. Adding any of them
  is an append-only change that MUST bump `ANCHOR_NORMALIZATION_VERSION` and be
  treated as a re-verification event (`normalize.ts` versioning contract).
- **`ANCHOR_NORMALIZATION_VERSION` is not persisted per anchor.** The re-key
  procedure is documented but has no executable "affected anchors" query. Fold a
  version column into Signet's `dedup_entries` schema (or `Badge.nullifierRef`
  metadata) at the Phase 3 backend split so a future table change can be
  enumerated precisely.
- **Auto-issue email-domain shares the mint-window discipline only partially.**
  `autoIssueEmailDomainBadge` now registers the Sybil anchor and persists the
  nullifierRef (closing the old nullifier-less 2x-Sybil), and releases a fresh
  registration on mint failure, but it does NOT wrap the mint in
  `serializeMintWindow` + a mint-side re-validation probe as the wizard runtime
  does. The residual pre-INSERT delete-vs-reissue window is strictly smaller than
  the one the wizard closes (release is sibling-guarded once the badge commits).
  Unify both issuance paths on the shared register→mint→compensate→self-heal core
  at the Phase 3 backend split.

## Misc small things

- `services/ws-proxy/`: alpine stub; see Stage 6 item above.
- `next.config.ts`: `typedRoutes` is OFF because it rejected `redirect()`
  to external RP `redirect_uri`s. If a typedRoutes-compatible escape
  hatch lands upstream, re-enable.

---

## Post-launch UI/UX findings (2026-07-02, live ministry-prod)

Found by Tyler on the first real sign-up against the live deploy. These are
bugs/UX gaps, not deliberate stubs. Tracked as session tasks #26-#30.

1. **Magic-link copy says "check the server logs" even though email sent
   (#26).** The verify-request page shows the dev/no-transport message despite
   SES/SMTP being configured and the email being delivered. The send path is
   correct (uses `SMTP_URL`); only the UI copy is keyed off the wrong signal.
   Find where the signin/verify-request page picks "check your inbox" vs "check
   the server logs" and make it honor `mailTransportConfigured()` (which already
   returns true for `SMTP_URL`).

2. **"Add a passkey" is in the badges box (#27).** Move it to a warning/CTA
   banner at the top of the page and hide it once the user has ≥1 passkey
   (Authenticator count > 0).

3. **Auto-issue `email-domain` badge at signup (#28).** On magic-link
   verification, auto-issue the `email-domain` badge for the user's domain
   unless it's a public/freemail host (gmail, icloud, outlook, yahoo, proton,
   …). Needs a freemail denylist; keep the no-PII rule (store only the domain).

4. **GitHub badge button throws "Application error" (#29).** With
   `GITHUB_CLIENT_ID`/`SECRET` unset in prod, the github plugin's OAuth redirect
   fails unhandled. Hide the GitHub option (or show "not configured") when creds
   are absent — never surface an unhandled error. Audit other OAuth plugins
   (google) for the same unconfigured-provider foot-gun. (Or populate real
   GitHub OAuth creds; callback `https://ministry.id/badges/new/github/callback`.)

5. **Share Links page: list incoming shares too (#30).** `/shares` shows only
   the links the user created. Add an "incoming / shared with you" section for
   `ShareLink`s shared to the user's email/account.

6. **Email OTP alongside the magic link (#31).** Sign-in emails only a link
   today. Also issue a one-time passcode so a user reading email on their phone
   can type the code to log in on desktop. Keep BOTH (link + OTP); either
   completes auth. Custom flow on top of Auth.js's link-only email provider:
   generate a short single-use code tied to the same verification identity, email
   link + code together, add an "enter code" form on the verify-request page
   (see #26). Security parity with the link: short TTL, single-use, per-identity
   - per-IP rate limiting (a 6-8 char code is guessable in a way a 32-byte link
     token isn't — throttle and lock after N failures), audit-logged.
