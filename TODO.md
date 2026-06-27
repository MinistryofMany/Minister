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

### H-1 (High) - credential quarantine cooldown is not enforced

**Where:** `apps/minister/src/server/credential-actions.ts` (quarantine fields
written at credential-add but never read), and the privileged actions that
should honor the cooldown: `merge-actions.ts` `startMerge` / `confirmMerge`,
`recovery-code-actions.ts` `generateMyRecoveryCodes`, and
`credential-actions.ts` `setPrimaryEmail`.

**What:** A freshly added email/passkey lands `status="quarantined"` with a
`quarantinedUntil` cooldown (DESIGNDECISIONS #5), and the UI shows it, but no
production code reads those fields to gate an operation. The cooldown is
therefore decorative: the blast-radius bound it advertises does not exist. A
session that has just reached AAL2 via a freshly-grafted (still-quarantined)
passkey can immediately start an account merge, generate recovery codes, or
change the primary email.

**Why it matters:** The intended containment for a briefly-compromised account
(an attacker who reaches AAL2 grafts a persistent credential and pivots to merge
/ recovery-code generation before the owner reacts to the "a credential was
added" notification) is inert. It is NOT a new unauthenticated takeover path -
it requires already reaching AAL2 - which is why it was accepted for the alpha
rather than blocking the merge.

**Fix:** Thread the acting credential id onto the session JWT at sign-in, then in
each privileged action reject when that credential row is
`status==="quarantined" && quarantinedUntil > now`. Minimum viable gate: require
the user to hold at least one non-quarantined AAL2 credential before
`startMerge` / `generateMyRecoveryCodes` / `setPrimaryEmail`. Fix this before the
alpha exposes merge or recovery-code generation to real users.

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

---

## Misc small things

- `services/ws-proxy/`: alpine stub; see Stage 6 item above.
- `next.config.ts`: `typedRoutes` is OFF because it rejected `redirect()`
  to external RP `redirect_uri`s. If a typedRoutes-compatible escape
  hatch lands upstream, re-enable.
