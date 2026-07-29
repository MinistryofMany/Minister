# Anonymous identity derivation: master spec

> **SHIPPED 2026-07-16.** This spec was written before implementation and kept
> its pre-build language, including the section-13 hold below. That hold is
> satisfied and historical. The design described here was built, audited, and
> deployed to prod across Minister and all three relying parties, and the SDK
> shipped as `@ministryofmany/*` 0.3.0 on npm.
>
> Where this document and the code disagree, **the code wins**. The frozen
> derivation constants as built are: HKDF salt `ministry/anon/v1`, L2 `info`
> prefix `ministry/v1/ctx/`, a 16-byte root, and a 32-byte per-app secret.
> Golden vectors in `@ministryofmany/identity`
> (`anon-derivation-vectors.json`) pin them. Do not change either string:
> it re-namespaces every commitment in existence.

Status: **build-ready spec, audit findings incorporated**. Consolidates the
decisions settled 2026-07-13; revised the same day to close audit findings
W1-W3 and S1-S4 (unlock-field quarantine, no-POST save path, `rp_mix_secret`
durability, epoch-bound blob AAD, pairing attempt-burn atomicity, the
JS-redirect prohibition on RP callback chains, and auth-code handling in the
consent client). Supersedes the tiered PRF-root/OPRF proposal in
`anon-identity-derivation-design.md` and its companion
`anon-identity-derivation-tradeoffs.md` (both retained as decision history; the
tier model there is dead). Adopts the recommendation of
`anon-seed-daily-key-options.md` (E4 encoding, PM default, PRF-wrapped blob,
memory-only opt-out, option-9 as v2). Nothing in this document is open for
relitigation; open items are marked as such explicitly.

**No code may be written against sections 4-11 until this spec passes an
`auditor` review.** See section 13 for the exact hold list.

---

## 1. Scope and inputs

One Ministry-issued root secret gives a user one unlinkable anonymous authoring
identity per app. This spec pins, exactly:

1. The root seed: size, generation, and the governing invariant (section 2, 4).
2. The E4 codec: base58check string + 12 BIP39 words, with golden vectors (5).
3. Enrollment: forced backup, the 3-word quiz, and the badge gate (6).
4. The layered daily-key stack at ministry.id and its single seam (7).
5. Per-app derivation and fragment delivery to the RP browser (8).
6. The RP-side handoff into Semaphore, including the RP mix secret (9).
7. The cross-device pairing interface (interface only; protocol is its own
   spec) (10).
8. Schema, endpoints, SDK surface (11), invariants + auditor checklist (12),
   hold list (13), and test plan (14).

Repos touched: `Minister` (app + `packages/shared`), `minister-client`
(`@ministryofmany/identity`), `deforum-space`, `FreedInk`, `Discreetly`.

## 2. The governing invariant

> **Ministry must never be able to decrypt or compute the seed.**

If Ministry could compute the seed it could derive every per-app Semaphore
secret and deanonymize the entire population's anonymous authoring. Every
design element below is checked against this. Concretely:

- The seed is generated client-side in the ministry.id page. No Ministry
  endpoint ever receives seed bytes, per-app secret bytes, PRF outputs, or any
  value from which they are computable.
- Ministry may hold **ciphertext only**, and only under a key it cannot
  obtain: the PRF-wrapped blob (7.1), whose KEK derives from a WebAuthn PRF
  output that exists only inside the user's browser during an assertion, and
  transient pairing relay ciphertext (10) under a PAKE-derived key.
- Backup by email was rejected for exactly this reason: the server would see
  plaintext.

What Ministry does hold, stated honestly:

| Artifact                 | Content                                               | Why it does not break the invariant                                 |
| ------------------------ | ----------------------------------------------------- | ------------------------------------------------------------------- |
| `AnonSeedBlob` rows      | AES-256-GCM ciphertext of the seed, IV, credential id | KEK = f(PRF output); PRF output never leaves the browser            |
| `AnonSeedEnrollment` row | timestamps, status, enrollment epoch (a counter)      | metadata (this account uses anonymous authoring), no key material   |
| `OidcClient.anonAppId`   | a public app label                                    | public by design                                                    |
| Pairing relay messages   | PAKE transcript + AEAD ciphertext, transient          | server cannot derive the PAKE key; online-only attack, rate-limited |

**Residual trust, stated once and honestly.** The seed and the derivation live
in JavaScript served from the ministry.id origin. A compromise of that origin's
JS (XSS, supply chain, or a malicious deploy) can steal the seed **at use
time**, while a user is present and unlocking. No storage layer escapes this
(section 7.6); the structural fix is the v2 separate-origin key holder (7.5).
The invariant above is about Ministry's backend and database: a full dump of
Ministry's DB plus all its server-side secrets yields zero seeds. It is not,
and cannot be, a guarantee against the origin actively serving hostile code.
The RP mix secret (9.2) is the one mitigation that survives even that: a
stolen seed alone does not reproduce an RP's Semaphore identities without that
RP's mix secret.

## 3. Architecture at a glance

```
  ministry.id browser (one origin owns the seed)
  ┌──────────────────────────────────────────────────────┐
  │ seed (16 bytes, client-generated, never sent)        │
  │   │  unlock via daily-key stack (7)                  │
  │   ▼                                                  │
  │ per-app secret = HKDF-SHA-256(seed, app_id)  (8.1)   │
  └───────────────┬──────────────────────────────────────┘
                  │ URL fragment on the OIDC redirect (8.2)
                  │ #minister_anon=v1.<base64url>   (never sent to any server)
                  ▼
  RP browser (deforum / FreedInk / Discreetly page)
      per-app secret ⊕ RP mix secret → device seed (9.2)
      device seed → existing @ministryofmany/identity HKDF chain
      → per-context Semaphore identity, commitments, nullifiers
```

Who learns what:

| Party                                | Sees                                                        | Never sees                                                       |
| ------------------------------------ | ----------------------------------------------------------- | ---------------------------------------------------------------- |
| Ministry backend                     | login, consent, blob ciphertext, enrollment status          | seed, per-app secret, PRF output, pairing code                   |
| RP server                            | pairwise `sub`, commitment at join (pre-existing), id_token | seed, per-app secret (fragment never transmitted), RP-mix output |
| RP browser (own page)                | its one per-app secret, its derived identities              | the seed, any other app's secret                                 |
| Network                              | TLS ciphertext                                              | any plaintext secret                                             |
| Browser PM vendor (L2 only, sync on) | the seed, as a saved password                               | - (this is the disclosed trade, 7.2)                             |

One seed, N apps: per-app secrets are HKDF-independent, so no coalition of
apps can link a user across apps from the secrets alone (the OIDC pairwise
`sub` already prevents linkage at the login layer). Because there is exactly
one root and derivation is deterministic, the old design's tier-pinning and
silent-second-identity problems dissolve: same account, same seed, same
identity, on every device and every browser.

## 4. The root seed

- **Size: 16 bytes (128 bits), from `crypto.getRandomValues(new Uint8Array(16))`**
  in the ministry.id page. 128 bits matches the ~128-bit security of Semaphore
  identities over BN254; 256 bits would be theater paid for in backup dread.
- Generated during enrollment (6). Exists in plaintext only: in page memory at
  ministry.id, in the user's backup (string or words), in the browser PM entry
  (L2), and transiently during pairing on the two paired devices.
- The seed is the **root**. Every storage layer in section 7 holds a copy or a
  wrapping of it; losing every layer but the backup loses nothing; losing the
  backup and every layer loses the identity (by design, there is no recovery
  through Ministry, which is the invariant working as intended).

## 5. Codec (E4): one seed, two renderings

The same 16 bytes render two ways. The **string is canonical**: it is what the
password manager saves, what pairing transfers, and what recovery asks for
first. The words appear on the backup sheet as the write-it-down aid, and the
recovery input parses either.

### 5.1 Canonical string: base58check

- **Alphabet** (Bitcoin base58, 58 chars, case-sensitive, no `0OIl`):

  ```
  123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
  ```

- **Version byte: `0x0A`.** Payload: the 16 seed bytes.
- **Checksum:** first 4 bytes of `SHA-256(SHA-256(version || payload))`
  (classic base58check).
- **Encoding:** base58 of the 21-byte value `version || payload || checksum`,
  big-endian, with one leading `1` per leading zero byte (with version `0x0A`
  the leading byte is never zero, so no `1`-padding ever occurs).
- **Length: exactly 28 characters** for every 16-byte payload (this holds for
  any version byte in `0x01..0x0F`; `0x0A` sits inside that window and avoids
  the well-known Bitcoin version bytes). First character falls in `c..g`;
  the checksum, not the prefix, is the integrity mechanism.
- **Decoding:** base58 decode, verify checksum, require decoded length 17 and
  version `0x0A`, output the 16 payload bytes. Checksum or version failure is a
  hard reject with an error naming both accepted forms.

### 5.2 Words: BIP39, 12 words

- Standard BIP39 with the **English wordlist** (2048 words, as shipped by
  `@scure/bip39/wordlists/english`).
- ENT = 128 bits (the seed), CS = 4 bits = the first 4 bits of
  `SHA-256(seed)`, 132 bits split into 12 groups of 11 bits, each indexing the
  wordlist. Exactly the BIP39 standard; any BIP39 implementation interoperates.
- Decode validates words and checksum, then recovers the 16 bytes.

### 5.3 Parser (recovery input accepts both)

1. Trim; collapse internal whitespace runs to single spaces.
2. If the input contains whitespace and splits into 2+ tokens: lowercase and
   parse as BIP39 (12 words expected; word or checksum failure rejects with a
   words-specific message).
3. Otherwise parse as base58check per 5.1 (case-sensitive, no normalization
   beyond the trim).
4. Both branches yield the identical 16 bytes or a hard error. Never silently
   truncate, pad, or "fix" input.

### 5.4 Golden test vectors

Computed with `@scure/base` `createBase58check(sha256)` and `@scure/bip39`,
cross-checked against an independent BigInt base58check implementation, and
(for the words) against the published Trezor BIP39 vectors. The codec
implementation must round-trip all four, both directions, both forms.

| Seed (hex, 16 bytes)               | Canonical string (28 chars)    | 12 words                                                                                        |
| ---------------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------- |
| `00000000000000000000000000000000` | `cfaQY4qf4JZrZUoY4Wn4FeGMa1bq` | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` |
| `7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f` | `eSbkZgY3NtfyMHrqDDddh3qUDXYw` | `legal winner thank year wave sausage worth useful legal winner thank yellow`                   |
| `4d696e6973747279206f66204d616e79` | `dk8QMNVR47r8d2rxXhHFFHLRTj5y` | `estate enter olympic tragic elbow develop like under cake help fortune verify`                 |
| `ffffffffffffffffffffffffffffffff` | `gES9VNd84diwWvnPZs9xn76wnxbF` | `zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong`                                             |

(The third seed is ASCII `Ministry of Many`. The first, second, and fourth
word rows are the standard BIP39 test vectors, which is a free cross-check
against the spec itself.)

### 5.5 Where the codec lives

**`Minister/packages/shared/src/anon-seed-codec.ts`** (`@minister/shared`),
with tests in `anon-seed-codec.test.ts` carrying the 5.4 vectors.

Why there: `@minister/shared` is a source-only workspace package
(`main: ./src/index.ts`, no build, no dist, vitest already wired), importable
from both Minister server code and ministry.id client components, which are
the only consumers (RPs receive raw bytes over the fragment and never touch
the codec). `@ministryofmany/client` was rejected as home because it commits
built `dist/` and the codec has no RP consumer. Dependencies to add to
`@minister/shared`: `@scure/base`, `@scure/bip39`, `@noble/hashes` (audited,
zero-dep, pure ESM; `@ministryofmany/identity` already depends on
`@scure/bip39` for its existing mnemonic module, so this adds no new trust
root to the ecosystem). Hand-rolling base58 or the wordlist is prohibited.

## 6. Enrollment: forced backup, quiz, badge gate

### 6.1 State machine

```
(none) ──generate seed──▶ PENDING_BACKUP ──quiz passed──▶ ACTIVE
   ▲                          │ reset (free)                 │ reset (destructive)
   └──────────────────────────┴──────────────────────────────┘
     every reset: enrollmentEpoch += 1, timestamps nulled, all blobs deleted
```

- `AnonSeedEnrollment` row is created at first seed generation with
  `enrollmentEpoch = 1`, `seedGeneratedAt` set, and `backupConfirmedAt = null`.
  State encoding: `none` = no row or `seedGeneratedAt = null`; PENDING_BACKUP
  = `seedGeneratedAt` set, `backupConfirmedAt = null`; ACTIVE = both set.
- **The row, once created, is never deleted** (user-deletion cascade aside).
  `enrollmentEpoch` is monotonic per user, bumps on **every** reset, and is
  AAD-bound into every PRF-wrapped blob (7.1): after a reset, any blob wrapped
  under a previous epoch fails GCM authentication outright. That is the
  anti-rollback property — a stale, restored, or re-served pre-reset blob
  cannot silently resurrect the old seed. (Residual, stated honestly: a
  Ministry that rolls back the enrollment row itself can re-serve matching
  old blobs; it still cannot decrypt them, and the row rollback is visible in
  the audit log.)
- **No storage layer may accept the seed, and no derivation may run, before
  ACTIVE.** The vault module (7.5) enforces this client-side; the badge gate
  (6.4) enforces the incentive server-side.
- Reset while PENDING_BACKUP is free (nothing derived, nothing lost): bump
  epoch, null `seedGeneratedAt`, delete any stray blobs. Reset while ACTIVE is
  destructive (new seed = new identity in every app, old ones unrecoverable),
  requires a typed confirmation phrase, bumps epoch, nulls both timestamps,
  and deletes all blobs.

### 6.2 Where enrollment runs

- Proactively: `/settings/anonymous-key` at ministry.id.
- Inline: on the OIDC consent page when the client is anon-enabled
  (`anonAppId` set) and the user's status is `none`. The consent flow embeds
  the same enrollment component; approval cannot complete the anon path until
  the user is ACTIVE (they may still approve login without an anonymous
  identity; the fragment is then omitted, see 8.3).

### 6.3 Forced backup, then the quiz

1. Generate the seed; render the canonical string, the 12 words, and two
   actions: **Download** (`ministry-anonymous-key.txt`: the string, the 12
   numbered words, the date, and a plain warning that Ministry cannot recover
   it) and **Print** (a sheet with the same content). Email is not offered.
2. **Quiz:** sample 3 distinct indices from 1..12 via `crypto.getRandomValues`
   (rejection sampling, no modulo bias). The user types the word at each
   index. Comparison is client-side against the just-generated words
   (lowercased, trimmed). All three must match; failure re-prompts with fresh
   indices.
3. On pass, the client calls `confirmSeedBackup()`; the server sets
   `backupConfirmedAt` and the state becomes ACTIVE. Only then does the client
   offer the daily-key layers (7) and run any derivation.

**Honesty note for the auditor:** the quiz is verified client-side because the
server must never see the words (invariant). It is a UX forcing function, not
a security control; a hostile client can skip it and only harms itself. No
security property may ever be built on `backupConfirmedAt`.

### 6.4 Badge gate ("no meaningful badges until done")

While a user's enrollment is PENDING_BACKUP:

- `startWizard()` (`apps/minister/src/server/wizard.ts`) refuses to start any
  badge wizard, returning a typed error that the UI renders as "finish backing
  up your anonymous key first" with a link to `/settings/anonymous-key`.
- A persistent banner shows on profile and badge pages.

Users with status `none` (never enrolled) are unaffected; the gate exists so
nobody builds badge value on an unbackuped seed.

## 7. The daily-key stack at ministry.id

The backed-up seed is the backup, not the daily key. Per RP login, the
authorize/consent page needs the seed once, briefly. Four layers, feature
detected top-down; every layer produces the identical 16 bytes into the same
seam (7.5).

| #   | Layer                                        | Unlock cost                        | Cross-device                                                    | Who holds what at rest                       |
| --- | -------------------------------------------- | ---------------------------------- | --------------------------------------------------------------- | -------------------------------------------- |
| L1  | PRF-passkey + Ministry-held PRF-wrapped blob | 1 biometric tap                    | any device where the passkey syncs (blob fetched from Ministry) | Ministry: ciphertext; authenticator: PRF key |
| L2  | Browser password manager (save-a-login)      | 1-2 taps (autofill)                | wherever the PM syncs                                           | browser/OS PM (and vendor cloud if syncing)  |
| L3  | Memory-only (opt-out)                        | seed entry or pairing, per session | none                                                            | nothing at rest                              |
| L0  | Seed re-entry (string or 12 words)           | typing                             | n/a (it is the backstop)                                        | paper / file                                 |

Selection: at unlock time the client tries L1 if the user has blobs and a
usable credential on this device, else offers L2's autofill field, which
degrades transparently into L3/L0 (same input; the difference is whether the
PM fills it). Users can enable L1 and L2 simultaneously; L3 is an explicit
"never store my key" settings toggle that suppresses both and skips the L2
save step at enrollment.

### 7.1 L1: PRF-passkey unlock + Ministry-held PRF-wrapped ciphertext

**This is not the killed Tier A.** There, the PRF output _was_ the root:
losing the passkey lost the identity. Here PRF wraps a **copy**; the seed
remains the root; losing the passkey costs one seed re-entry and a re-wrap.

Enrollment (offered when ACTIVE and PRF is feature-detected):

1. Detect: `PublicKeyCredential.getClientCapabilities()` where available
   (check the `prf` capability); otherwise probe by evaluating on an existing
   credential and checking for `prf.results.first`.
2. Prefer evaluating PRF on an **existing** ministry.id login passkey via a
   dedicated `navigator.credentials.get()` carrying
   `extensions: { prf: { eval: { first: PRF_EVAL_INPUT } } }` and
   `allowCredentials` limited to the user's registered credential ids. If no
   existing credential yields PRF, `create()` a dedicated seed-unlock
   credential with the `prf` extension, then run a follow-up `get()` for the
   actual evaluation (create-time eval is unreliable across stacks; never
   trust create-time results).
3. `PRF_EVAL_INPUT = utf8("minister/anon-seed/prf/v1")`.
4. `prfOutput` (32 bytes) → `KEK = HKDF-SHA-256(ikm = prfOutput,
salt = utf8("minister/anon-seed/wrap/v1"),
info = utf8("minister/anon-seed/wrap/v1:aes-256-gcm"), L = 32)`.
5. Wrap: AES-256-GCM via WebCrypto, fresh random 12-byte IV per wrap,
   `AAD = utf8("minister/anon-seed/blob/v1:" + userId + ":" + credentialId
   - ":" + wrapVersion + ":" + enrollmentEpoch)`—`credentialId`as the
base64url string stored server-side,`wrapVersion`and`enrollmentEpoch`as base-10 decimal; no part can contain`:`, so the encoding is
unambiguous. `enrollmentEpoch`is the current value from`getAnonSeedState()`. Binding the full tuple means a blob cannot be
     replayed across users, credentials, or wrap formats, and — because every
     reset bumps the epoch (6.1) — a pre-reset blob fails authentication after
     a reset. Plaintext = the 16 seed bytes. Ciphertext including the 16-byte
     tag is exactly 32 bytes.
6. Upload via `putSeedBlob({ credentialId, ciphertext, iv, wrapVersion: 1 })`.
   One blob per (user, credential); at most 5 blobs per user; server rejects
   any ciphertext not exactly 32 bytes or IV not exactly 12 bytes.

Unlock: fetch blob(s), run the same `get()` + KEK derivation, decrypt with
the AAD rebuilt from the **current** `enrollmentEpoch`, feed the seam. GCM
tag or AAD failure is a hard error surfaced as "this passkey cannot unlock
your key on this device", falling through to L2/L0.

**Invariant-critical:** the PRF `get()` for seed unlock is a dedicated call
owned by the vault module. Its assertion response, client extension results
included, is **never transmitted anywhere**. It must not be piggybacked on the
Auth.js login ceremony, whose assertion is serialized and POSTed to the
server; a PRF output riding that payload would hand Ministry the KEK and break
the invariant. This is a named auditor check (12).

Why L1 is preferred where available: one biometric tap, no autofill quirks,
cross-device without placing the seed in a vendor password vault (the synced
passkey reproduces the KEK; Ministry serves only ciphertext), and a real
gesture barrier against at-rest XSS reads.

### 7.2 L2: browser password manager (universal fallback)

Enrollment (immediately after the quiz, unless L3 opt-out). Governing rule:
**the seed string must never sit in a form that can POST to a
Ministry-controlled or Ministry-logged origin.** Even a POST answered 405
transits the body through the TLS edge, proxies, WAF, and access logs before
the app answers; the earlier draft's dead-405-route belt-and-braces is
retracted for exactly this reason.

- **Preferred path, used whenever available:** no form at all —
  `navigator.credentials.store(new PasswordCredential({ id:
"anonymous-writing-key", name: "Ministry anonymous key", password: <string>
}))` (Chromium). The seed never enters a form control.
- **Fallback path (no `PasswordCredential`: Safari, Firefox):** a save form
  is permitted only under all of:
  - The form is network-incapable by construction: `method="dialog"` inside
    a `<dialog>`, no `action` targeting any route — a JS-less or JS-failed
    submit closes the dialog and produces no request. Username field fixed
    to `anonymous-writing-key` (`autocomplete="username"`), password field
    holding the canonical 28-char string (`autocomplete="new-password"`).
  - `preventDefault()` is bound to the form's **`submit` event**, not to a
    button click handler — Enter in the password field dispatches `submit`
    directly and must be intercepted at the event that actually fires.
  - The submit handler then performs the JS navigation to
    `/settings/anonymous-key?saved=1` that PMs treat as a successful login
    and prompt to save. If a browser's save heuristic does not fire on this
    shape, the fallback is instructing a manual PM save — never a
    network-capable form.
- **Explicitly forbidden:** any form whose submission could POST the seed to
  a Ministry origin, dead routes included. If a future change cannot avoid a
  POSTable path, disabling request-body logging at every edge/proxy/WAF hop
  becomes a documented deployment requirement and the change re-enters
  audit; this spec's position is that no such path may exist.

Unlock: a password input rendered by the vault's unlock component on the
consent page (`autocomplete="current-password"`, same origin so the PM offers
the entry); the user taps, autofills (Face ID / Touch ID / Hello if the store
is locked), the vault parses via 5.3 and feeds the seam, then clears the
field. The field is structurally quarantined from the consent submission:

- Rendered **outside** the consent form — never nested in the
  `approveConsent` server-action form or any other `<form>` that can reach a
  server.
- **No `name` attribute**, so no form serialization can ever include it,
  whatever the DOM around it does.
- Its value is read **only** by vault JS, and the field is cleared
  (`value = ""`) before any consent submit is dispatched.
- Consequence, auditor-checked and e2e-asserted: the autofilled seed never
  serializes into the `approveConsent` POST — that request body contains no
  seed material in any encoding.

On Chromium, `navigator.credentials.get({ password: true, mediation: "required" })`
may replace the field; **mediation is `"required"`**, never `"optional"`: the
zero-click variant lets injected JS read the seed with no user gesture, and
that regression is not acceptable for a domain-floor secret.

**Mandatory disclosure, shown at save and in settings, plainly:** "Your key is
stored by your browser's password manager. If your password manager syncs
(iCloud Keychain, Google Password Manager, a third-party manager), a copy of
your key lives in that vendor's cloud and is reachable by anyone who can
recover that account. Ministry never has your key." No euphemisms; Apple or
Google holding the seed is the explicit, accepted trade of this layer, and the
user must see it before saving.

Upside worth stating in the same breath: the PM only offers the entry on the
real ministry.id origin, which kills phishing lookalikes, and saved passwords
are exempt from Safari's script-writable-storage eviction.

### 7.3 L3: memory-only (opt-out)

Settings toggle "never store my key". The seed enters via L0 or pairing, lives
in a module-scoped variable for the page's lifetime, and is gone on
navigation or tab close. No `sessionStorage`, no `localStorage`, no IndexedDB,
ever, for seed material at ministry.id (this prohibition is global, not just
L3: no layer persists plaintext seed or per-app secrets in script-readable
storage). Every browser session costs one seed entry or pairing ceremony;
that is the point, and the UI says so when the toggle is set.

### 7.4 L0: seed entry (backstop, always present)

An "enter your key" input on the unlock component accepting both codec forms
via the 5.3 parser. After a successful L0 entry the client offers to
re-enroll L1/L2 (re-wrap, re-save) unless L3 opt-out is set.

### 7.5 The seam (one derivation entry point, option-9 ready)

The entire stack sits behind **one function** in the ministry.id client vault
module (`apps/minister/src/lib/anon-seed/vault.ts`):

```ts
deriveAppSecret(anonAppId: string): Promise<Uint8Array>  // 32 bytes
```

Rules:

- `deriveAppSecret` internally resolves a layer, obtains the seed, runs the
  8.1 HKDF, zeroizes its seed reference (best effort, see 12), and returns
  only the per-app secret. It refuses unless enrollment is ACTIVE.
- `getSeed()` is module-private. **No code outside `vault.ts` (and the
  enrollment/backup/pairing components it explicitly owns) may hold seed
  bytes.** The consent screen calls `deriveAppSecret` and nothing else. This
  is a grep-able rule and a named auditor check.
- v2 structural hardening (option 9 of the daily-key doc): a static,
  third-party-JS-free key-holder page on `seed.ministry.id`, embedded as an
  iframe, holding storage + HKDF, answering `deriveAppSecret` requests over
  origin-checked `postMessage` with an in-iframe click and rate limit. When it
  lands, only the _implementation_ of `deriveAppSecret` changes (to a
  postMessage RPC); no caller changes. That is why the seam must be exactly
  one function from day one. XSS blast radius then drops from "root seed
  exfiltrated once, game over" to "per-app secrets abused while a user is
  present".

### 7.6 XSS posture per layer (the central threat, faced)

At use time, XSS on ministry.id wins everywhere: while a login is in flight
the seed or a per-app secret is in JS-reachable memory. The layers differ at
rest:

| Layer | Injected JS at rest gets | Gesture needed to escalate                                                                                 | Blast radius on one compromise   |
| ----- | ------------------------ | ---------------------------------------------------------------------------------------------------------- | -------------------------------- |
| L1    | blob ciphertext only     | a biometric tap it must socially engineer                                                                  | seed, after a coerced tap        |
| L2    | nothing directly         | one induced autofill (Chromium exposes filled values post-gesture; Safari needs an explicit QuickType tap) | seed, after a coerced fill       |
| L3    | nothing                  | must capture entry/pairing live                                                                            | seed only if present mid-session |
| L0    | nothing                  | must capture typing live                                                                                   | same as L3                       |

Mitigations required in v1 (auditor-checked): strict CSP on the consent page,
`/settings/anonymous-key*`, and `/pair` (no third-party script, no inline
event handlers); no analytics or error-reporting SDK on those routes; the
mediation and gesture rules above. The structural answer remains option 9
in v2.

## 8. Per-app derivation and delivery

### 8.1 Derivation (client-side, at ministry.id)

```
per_app_secret = HKDF-SHA-256(
    ikm  = seed,                                  // 16 bytes
    salt = utf8("minister/anon/hkdf/v1"),
    info = utf8("minister/anon/v1:app:" + anonAppId),
    L    = 32 )
```

- WebCrypto (`crypto.subtle`) only; no userland hash implementations at
  ministry.id.
- `anonAppId` is the app's stable anonymous-identity namespace:
  `OidcClient.anonAppId`, a lowercase slug matching `^[a-z0-9-]{3,32}$`,
  unique, nullable (null = client not anon-enabled, no fragment ever), set in
  the admin UI at registration and **immutable thereafter** (the admin update
  action refuses changes; rotating a client's `clientId` or secret must not
  touch it, or every user's identity in that app silently forks). Initial
  values: `deforum`, `freedink`, `discreetly`.

Golden vectors (seed = `4d696e6973747279206f66204d616e79`):

| anonAppId  | per_app_secret (hex)                                               |
| ---------- | ------------------------------------------------------------------ |
| `deforum`  | `a6a39187454acc287e62b9eaeabecef8c67bf08500fc53bd5e00912ab0f71a5e` |
| `freedink` | `8f25c90c8c1c9717e16c2e9bf90951f44e4897c1a6ada79af3ba57de2909e0b0` |

KEK golden (7.1, `prfOutput = 0x11 * 32`):
`6c9e4af7ffcf6bc5b544c0fa725cd6d08a8aa0b4dbc2fb0e1dbf120c48a5fd7f`.

### 8.2 Delivery: URL fragment on the OIDC redirect

Today `approveConsent` (`apps/minister/src/server/oidc-actions.ts`) finishes
with a server-side `redirect(buildSuccessRedirect(redirectUri, code, state))`.
The server cannot append the fragment (it never has the secret), so for
anon-enabled clients the last hop becomes client-driven:

1. When `request.client.anonAppId != null` and the user is ACTIVE,
   `approveConsent` **returns** `{ redirectTo }` (the same
   code + state success URL) instead of redirecting.
2. The consent client (`apps/minister/src/components/consent-screen.tsx`)
   calls `deriveAppSecret(anonAppId)`, then navigates:

   ```
   location.assign(redirectTo + "#minister_anon=v1." + base64url(per_app_secret))
   ```

3. Fragment grammar: `minister_anon=v1.<43 base64url chars>` (32 bytes). The
   fragment is parsed as `URLSearchParams` semantics after the `#`. Unknown
   versions must be ignored by RPs (return null, not garbage).
4. **Auth-code handling in the consent client.** `redirectTo` carries the
   single-use authorization code through ministry.id client JS (previously it
   only ever lived in a server-issued `Location` header). Its protections do
   not relax: the code stays PKCE-bound (`S256` only) and `state`-bound,
   single-use, 60-second TTL — pre-existing server-side properties this
   change must preserve. The consent client holds `redirectTo` only in
   transient function scope: it navigates immediately via `location.assign`
   and never writes the URL or the code to `sessionStorage`, `localStorage`,
   IndexedDB, cookies, React state that outlives the navigation,
   `history.pushState`, or any log. Residual, stated honestly: consent-page
   XSS can read the code — but the code is useless without the RP's PKCE
   verifier (or client secret), and the same XSS already steals the per-app
   secret being appended in step 2, the larger prize; the code adds no new
   exposure class.

Why the fragment: browsers never send the fragment to any server, so the RP
server, Ministry, proxies, and access logs never see it; and browsers
**propagate the original fragment across 3xx redirects** whose `Location` has
no fragment of its own, so it survives the RP's server-side callback hop
(e.g. Auth.js `/api/auth/callback/minister` → app page) and arrives at the
final landing page for client JS to read. Fragment preservation is an
HTTP-3xx property **only**: any client-side redirect on the chain —
`location.assign`/`replace`, a meta refresh, a framework router navigation —
silently destroys the fragment, as does any redirect that sets its own
fragment in `Location`. Both are therefore RP integration requirements (9.3):
no fragment-setting redirect, and no JS redirect at all, anywhere in the
callback chain. Loss is fail-closed (SDK returns null, RP shows its connect
state, 8.3) — a reliability bug, not a security one, but load-bearing enough
that per-browser fragment-survival tests are mandatory (14).

### 8.3 Degradation and denial

- User declines consent: unchanged today's path, no fragment.
- User approves but cannot or will not unlock (no layer available, cancels the
  tap, L3 user without the seed on hand): the client navigates to
  `redirectTo` **without** the fragment. Login succeeds; the RP's SDK returns
  null; the RP shows its "connect your anonymous identity" state (retry via
  ministry.id, or pair a device). Fail-open for login, fail-closed for
  identity, never a made-up secret.
- Non-anon clients: `approveConsent` keeps the existing server-side redirect,
  byte-for-byte unchanged behavior.

### 8.4 Fragment hygiene (both ends)

- The RP SDK helper (9.1) must run before any other script touches the URL,
  read the fragment, and immediately `history.replaceState` it away, so the
  secret does not sit in the tab's history entry or leak via `location.href`
  reads by later scripts. RP callback/landing routes must not load third-party
  JS ahead of the scrub.
- Ministry side: `redirectTo` gains the fragment only in `location.assign`;
  it never appears in a ministry.id URL, log, or history entry.
- Residual: a crash between navigation and scrub can leave the fragment in a
  restored-session URL. Blast radius is one app's secret (deterministic, not
  rotatable without a seed reset); accepted, documented, and one more reason
  the per-app secret, not the seed, crosses origins.

## 9. RP handoff: per-app secret → Semaphore identity

### 9.1 SDK surface

New module in **`minister-client/packages/identity`**
(`@ministryofmany/identity`), `src/minister-link.ts`:

```ts
/** Read and scrub the Ministry anon fragment. Null if absent/malformed/unknown version. */
export function extractMinisterAppSecret(opts?: {
  location?: Location; // default window.location
  scrub?: boolean; // default true: history.replaceState removes the param
}): Uint8Array | null; // 32 bytes

/**
 * Mix the RP's own secret; output feeds the existing derive chain as the
 * device seed. rpMixSecret is identity-determining (9.2, I9): provision
 * once, back it up, never rotate or regenerate — loss forks every user's
 * identity in this app and orphans all prior posts.
 */
export async function deriveDeviceSeedFromMinister(
  appSecret: Uint8Array, // 32 bytes, from extractMinisterAppSecret
  rpMixSecret: Uint8Array, // >= 32 bytes, RP-held (9.2)
): Promise<Uint8Array>; // 32 bytes = DEVICE_SEED_BYTES
```

Everything downstream (`deriveIdentity`, membership, proofs, nullifiers, the
vault, revocation) is untouched; this only changes where the device seed comes
from. The v3/RLN expand Discreetly needs already lives behind this package's
seam per the earlier design work.

### 9.2 The RP mix secret

```
device_seed = HKDF-SHA-256(
    ikm  = per_app_secret,
    salt = rp_mix_secret,                       // the RP's own high-entropy secret
    info = utf8("minister/anon/rp-mix/v1"),
    L    = 32 )
```

- Carries over the 2026-07-09 decision: each RP mixes in a secret Ministry
  does not hold, so even a compromise that exfiltrates seeds from the
  ministry.id origin cannot reproduce an RP's identities without also taking
  that RP's secret.
- One env var per RP (suggested name `ANON_RP_MIX_SECRET`, >= 32 random bytes,
  base64url), delivered to the RP's own signed-in page by its own server
  (page props / load function, not baked into a public bundle). The RP server
  holding it is fine: it lacks `per_app_secret`, so it still cannot compute
  `device_seed`. A user can read their own app's mix secret in their own
  browser; it does not help them attack anyone else.
- **Fork-avoidance invariant (I9): `rp_mix_secret` is identity-determining.**
  `device_seed = HKDF(per_app_secret, salt = rp_mix_secret)`, so losing or
  regenerating it silently forks every user's identity in that app — every
  commitment, membership, and nullifier orphans, every prior post becomes
  unownable, and no error fires anywhere. It therefore gets seed-level
  durability discipline, RP-side: provision once at launch (>= 32 CSPRNG
  bytes), back it up immediately in the RP's secret store with the same
  durability as the RP's database, and treat it as **immutable post-launch**
  — there is no legitimate rotation, only the fork. Each RP must have a
  written recovery story (where the backup lives, who can restore it) before
  its integration ships, and the SDK doc for `deriveDeviceSeedFromMinister`
  must carry this warning. The Minister build never holds this value; the
  obligation sits with each RP, which is exactly why the spec, not code
  review, must state it.

Golden vector: `per_app_secret` = the `deforum` vector from 8.1,
`rp_mix_secret` = utf8(`example-rp-mix-secret-32-bytes!!`) →
`device_seed = 09aa876834bad70b4c38e57dbecea98c69f127e240e4eb021ed6d822cab554d5`.

### 9.3 Per-RP integration

| RP                                                     | Today                                                         | Change                                                                                                                                                                                                                                                                          |
| ------------------------------------------------------ | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| deforum (`deforum-space/src/lib/client/device.ts`)     | `loadOrCreateDeviceSeed()`: random 32 bytes in `localStorage` | replace generation with `extractMinisterAppSecret` + `deriveDeviceSeedFromMinister`; keep the existing `localStorage` cache of the device seed keyed by the Minister `sub` (per-app blast radius, unchanged posture); per-sub-forum derivation and join/post pipeline untouched |
| FreedInk (`FreedInk/src/lib/client/vault.ts`)          | per-blog password vault is the primary store                  | vault becomes export/backup only; per-blog identity = derive chain with blog id as context over the Ministry-derived device seed                                                                                                                                                |
| Discreetly (`Discreetly/apps/web/src/lib/identity.ts`) | one identity reused across rooms                              | per-room derivation (context = room id) over the Ministry-derived device seed; closes the known cross-room-reuse leak                                                                                                                                                           |

RP integration requirements (all three): run the extract-and-scrub helper on
the OIDC landing page before any analytics; never send the secret or the
device seed to the RP server; **no client-side redirect anywhere in the
callback chain** — every hop from the OIDC callback to the landing page must
be a server-side HTTP 3xx whose `Location` carries no fragment (a
`location.assign`/`replace`, meta refresh, or router navigation silently
destroys the fragment; fail-closed per 8.3, but a broken chain means no user
ever gets an identity); guard `rp_mix_secret` per the 9.2 fork-avoidance
invariant (provision-once, backed up, immutable, recovery story written);
cache at most the mixed `device_seed`, never the raw `per_app_secret`.

## 10. Cross-device pairing (interface only)

Decided shape: QR code + short code over a PAKE, with seed re-entry as the
backstop. The wire protocol (PAKE choice, message framing, confirmation tags)
is its own spec and its own audit; **this section pins only the interface and
the invariants it must satisfy.**

- Both devices are signed into the same ministry.id account. The **new**
  device (no seed) opens `ministry.id/pair` and creates a pairing session; it
  displays a QR encoding `https://ministry.id/pair#v1.<pairId>.<code>` plus
  the two values for manual entry.
- `pairId`: public session handle (8 chars, server-known, 10-minute TTL).
- `code`: the PAKE password (6 chars, Crockford base32, ~30 bits), shown only
  on-screen and carried only in the QR **fragment**; it must never reach the
  server in any form, hashed included (a hash would be an offline-crackable
  oracle for the PAKE password, letting Ministry MITM the transfer and breach
  the invariant).
- The **old** device (has the seed) scans the QR (fragment read client-side)
  or the user opens `ministry.id/pair`, enters `pairId` + `code`.
- Ministry relays opaque messages via session-gated, rate-limited routes:
  `POST /api/anon/pair` (create), `POST /api/anon/pair/[pairId]/msg` (append),
  `GET /api/anon/pair/[pairId]/msg` (poll). The relay sees only PAKE protocol
  messages and AEAD ciphertext; 3 failed PAKE attempts burn the session
  (online-only attack: p <= 3 * 2^-30 per session).
- Requirements the protocol spec must satisfy, pinned here so the interface
  cannot drift:
  - **Atomic, non-duplicable attempt burn.** The 3-attempt budget is one
    server-side counter per `pairId`, spent atomically (compare-and-swap or
    a single conditional UPDATE). Concurrent relay connections, duplicated
    sessions, and racing pollers share that one counter and can never obtain
    more than 3 total guesses between them; burn is irreversible for the
    `pairId`.
  - **No offline dictionary oracle.** Nothing Ministry stores or relays — no
    hash or MAC of the code, and no PAKE message — may permit offline
    guessing of the ~30-bit code. The PAKE chosen must confine a
    transcript-holding attacker (Ministry included) to online guesses that
    spend the counter.
  - **The code exists only in the QR fragment and on-screen.** Never in a
    URL query or path, never in a request body, never server-side in any
    form.
- The seed (16 bytes) flows old → new under the PAKE-derived key. The new
  device then offers L1/L2 enrollment as after an L0 entry.
- Backstop, always: type the canonical string or the 12 words on the new
  device (L0). Pairing is a convenience layer over that, not a requirement.

## 11. Concrete additions, summarized

### 11.1 Prisma (`apps/minister/prisma/schema.prisma`)

```prisma
model AnonSeedEnrollment {
  userId            String    @id
  user              User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  enrollmentEpoch   Int       @default(1)  // monotonic; +1 on every reset; AAD-bound into blobs (7.1) = anti-rollback
  seedGeneratedAt   DateTime?              // null = none (pre-enroll or post-reset)
  backupConfirmedAt DateTime?              // with seedGeneratedAt set: null = PENDING_BACKUP, set = ACTIVE
  createdAt         DateTime  @default(now())
  updatedAt         DateTime  @updatedAt   // row is never deleted once created (6.1)
}

model AnonSeedBlob {
  id           String   @id @default(cuid())
  userId       String
  user         User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  credentialId String                    // base64url WebAuthn credential id used for the PRF wrap
  ciphertext   Bytes                     // AES-256-GCM(seed), exactly 32 bytes (16 ct + 16 tag)
  iv           Bytes                     // exactly 12 bytes
  wrapVersion  Int      @default(1)
  createdAt    DateTime @default(now())
  updatedAt    DateTime @updatedAt
  @@unique([userId, credentialId])
}

// On OidcClient:
//   anonAppId String? @unique          // 6.2/8.1; immutable once set (enforced in admin actions)
```

### 11.2 Server surface (Minister)

| Piece                             | Kind                              | Notes                                                                                                                                                                                                                                                                           |
| --------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/anon-seed-actions.ts` | server actions                    | `getAnonSeedState()` (returns `enrollmentEpoch`, which the client binds into the wrap AAD), `confirmSeedBackup()`, `putSeedBlob()`, `deleteSeedBlob()`, `resetAnonSeed()` (bumps the epoch, 6.1); Zod-validated, size caps, audit-logged (no secret material in metadata, ever) |
| `approveConsent` change           | server action                     | returns `{ redirectTo }` for anon-enabled clients (8.2); unchanged otherwise                                                                                                                                                                                                    |
| `startWizard` gate                | server                            | 6.4                                                                                                                                                                                                                                                                             |
| `/api/anon/pair*`                 | route handlers                    | 10; rate-limited via `src/lib/rate-limit.ts`                                                                                                                                                                                                                                    |
| Admin: `anonAppId` field          | admin UI + `oidc-client-admin.ts` | create-only, slug-validated, immutable                                                                                                                                                                                                                                          |

### 11.3 Client surface (ministry.id)

| Piece                                 | Home                                             |
| ------------------------------------- | ------------------------------------------------ |
| Codec                                 | `packages/shared/src/anon-seed-codec.ts` (5.5)   |
| Vault module (layers, seam)           | `apps/minister/src/lib/anon-seed/vault.ts` (7.5) |
| Enrollment + backup + quiz components | `apps/minister/src/components/anon-seed/`        |
| Unlock component (consent page)       | same family; rendered by `consent-screen.tsx`    |
| Pairing pages                         | `apps/minister/src/app/pair/`                    |

### 11.4 SDK surface (RPs)

`@ministryofmany/identity` `src/minister-link.ts` (9.1) plus the golden-vector
tests. RPs change per 9.3.

## 12. Security invariants, and what an auditor must check

Invariants (I1-I12):

- **I1.** No Ministry endpoint, action, or log ever receives seed bytes,
  per-app secrets, PRF outputs, quiz words, the pairing code, or any codec
  rendering of the seed. The only seed-derived server-side artifacts are the
  AES-GCM blob and pairing ciphertext.
- **I2.** The per-app secret reaches the RP browser only via the URL fragment
  and is never transmitted by RP code to any server.
- **I3.** No derivation and no storage-layer write occurs before enrollment is
  ACTIVE.
- **I4.** All seed access at ministry.id flows through `deriveAppSecret`;
  seed bytes never escape `vault.ts` and its owned enrollment/pairing
  components.
- **I5.** Layer degradation is explicit: an unavailable layer falls through to
  the next with UI, never to a silently different secret. (There is only one
  seed, so a fork is impossible by construction; what must not happen silently
  is _absence_, see 8.3.)
- **I6.** The id_token, userinfo, and access token never carry any
  anon-identity material (the classic delivery trap).
- **I7.** `anonAppId` is immutable; no admin path can change it once set.
- **I8.** PM-layer users have seen the vendor-cloud disclosure before the
  save (7.2).
- **I9.** `rp_mix_secret` is a fork-avoidance invariant (9.2): RP-side,
  provisioned once, backed up with database-grade durability, immutable
  post-launch, written recovery story before the integration ships; the SDK
  doc for `deriveDeviceSeedFromMinister` carries the warning.
- **I10.** The consent unlock field lives outside every server-posting form,
  carries no `name` attribute, is read only by vault JS, and is cleared
  before any consent submit; the `approveConsent` POST body never contains
  seed material in any encoding (7.2).
- **I11.** The L2 save path cannot generate a network request containing the
  seed: `credentials.store()` where available, else a `method="dialog"`
  network-incapable form with `preventDefault` bound to the `submit` event;
  no POSTable form may exist, dead 405 routes included (7.2).
- **I12.** Blob AAD binds `(userId, credentialId, wrapVersion,
enrollmentEpoch)`; the epoch is monotonic and bumps on every reset, so a
  pre-reset blob fails authentication (6.1, 7.1).

Auditor checklist (each maps to at least one test in 14):

1. Grep-level: no `fetch`/server-action payload, form POST, or log statement
   anywhere in `apps/minister` or the SDK carries seed material (I1). Include
   the L2 save path (I11: no network-capable form exists — `credentials.store()`
   or `method="dialog"` only, `preventDefault` on the `submit` event; a
   network-interception test shows zero requests carrying the seed, Enter-key
   submit included) and the PRF `get()` response (never serialized: check no
   `JSON.stringify` or transport of that assertion, and that the login
   ceremony's WebAuthn path carries no `prf` extension).
2. `approveConsent` anon path returns a URL and the fragment is appended only
   in `consent-screen.tsx`; the fragment string never appears server-side.
   The consent client holds `redirectTo` transiently only (8.2 step 4):
   immediate `location.assign`, no write of the URL or code to storage,
   cookies, surviving state, `history.pushState`, or logs; the code's
   PKCE(S256)/state binding, single-use, and 60s TTL are unchanged
   server-side.
3. Consent unlock field (I10): rendered outside the consent form in the
   actual DOM, no `name` attribute, cleared before submit; e2e asserts the
   `approveConsent` request body contains no codec form of the seed.
4. RP landing pages: scrub ordering (helper before any third-party script),
   `history.replaceState` verified, no fragment-setting redirect and **no
   client-side redirect of any kind** in the callback chain (9.3);
   per-browser fragment-survival tests present and passing (14).
5. `rp_mix_secret` (I9): each RP's provisioning is provision-once with a
   backup and a written recovery story; no rotation or regeneration code
   path exists; the SDK doc warning is present.
6. Codec: golden vectors 5.4 pass both directions; malformed inputs (bad
   checksum, wrong version, 11/13 words, mixed forms) all hard-reject; parser
   never truncates or corrects.
7. Wrap: fresh IV per wrap (re-wrap included); AAD binds the full
   `(userId, credentialId, wrapVersion, enrollmentEpoch)` tuple (I12);
   rollback test: a blob wrapped under epoch N fails authentication after a
   reset to N+1; the epoch bumps on every reset and the enrollment row is
   never deleted; server rejects malformed blob sizes, blob cap enforced,
   GCM failures surface as errors (no silent fallthrough to a wrong seed).
8. HKDF domain separation: the three info/salt families
   (`minister/anon/hkdf/v1` + `minister/anon/v1:app:`,
   `minister/anon-seed/wrap/v1`, `minister/anon/rp-mix/v1`) are distinct from
   each other and from the existing `minister/identity/*` labels; goldens in
   8.1/9.2 pass.
9. Consent, settings, and pair routes: CSP with no third-party or inline
   script; no analytics/error SDKs (7.6).
10. Chromium credential mediation is `"required"` (7.2); no
    `mediation: "optional"` or silent `PasswordCredential` reads anywhere.
11. Pairing: the code never reaches the server plaintext or hashed; the
    3-attempt burn is a single atomic per-`pairId` counter that concurrent
    sessions cannot duplicate (10); TTL enforced; relay contents opaque
    (spot-check payload schemas).
12. Quiz carries no server-side security weight: nothing but UI reads
    `backupConfirmedAt` besides the badge gate (6.3 honesty note).
13. Rate limits on `/api/anon/pair*` and blob actions; audit-log entries carry
    no secret material.
14. Zeroization: `fill(0)` on seed and secret buffers after use at every site,
    with the honest caveat recorded that JS gives no guarantee (GC copies,
    string interning avoided by keeping secrets in `Uint8Array` end-to-end;
    the codec string/words are the unavoidable exceptions, scoped to backup
    and entry components). Confirm secrets are never placed in strings except
    those two surfaces, and never in Redux/state libraries or React state that
    outlives the component.
15. Multi-account edge: two Ministry accounts in one browser cannot cross
    seeds (vault state keyed by userId; blobs AAD-bound to
    userId/credentialId/epoch; RP cache keyed by `sub` per 9.3).
16. Constant-time: not load-bearing anywhere here (no secret-dependent
    comparisons against attacker-supplied values exist: GCM tags are checked
    by WebCrypto, the checksum guards typos, the quiz is client-side).
    Verify no code path introduces one (e.g. a server-side comparison of any
    codec form).

## 13. Held for audit before implementation

The following must not be coded until this spec is signed off by an `auditor`
review (opus/fable, xhigh), and any change the audit forces re-enters review:

1. The codec (5) including its golden-vector tests.
2. The vault module and layer stack (7), especially the PRF wrap (7.1) and the
   L2 no-POST save path (7.2).
3. The `approveConsent` return-shape change and fragment append (8.2-8.4).
4. The SDK `minister-link` module and all three RP integrations (9).
5. The pairing feature in its entirety (10) - which additionally requires its
   own protocol spec (PAKE selection and framing) plus a separate audit pass
   before build.
6. Schema migration + admin `anonAppId` plumbing (11) - mechanically boring,
   but held anyway so the audit sees the whole surface at once.

Explicitly not gated: turning the 5.4/8.1/9.2 golden vectors into failing
test scaffolds is allowed pre-audit (tests only, no implementation).

## 14. Test plan (proof of correctness)

| Area              | Tests                                                                                                                                                                                                                                                                                                                                                        |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Codec             | 5.4 goldens (bytes ↔ string ↔ words, both directions); property test: random 16-byte round-trips; adversarial: flipped chars (checksum catches), swapped words (BIP39 checksum catches), 24-word input rejected, version byte 0x0B rejected, leading/trailing whitespace tolerated, embedded newline in words tolerated                                      |
| Derivation        | 8.1 + 9.2 HKDF goldens in both the ministry.id vault tests and the SDK tests (same vectors, two implementations, must agree)                                                                                                                                                                                                                                 |
| Wrap              | wrap/unwrap round-trip; tamper ciphertext/IV/AAD → GCM failure; wrong PRF output → failure; rollback: blob wrapped under epoch N fails authentication after reset to N+1 (I12); vector: KEK golden (8.1)                                                                                                                                                     |
| Consent flow      | e2e (`apps/minister/e2e/`): anon client → enrollment inline → quiz → unlock → fragment present on RP landing URL and scrubbed after; non-anon client → byte-identical legacy redirect; decline → no fragment; cancel-unlock → login lands without fragment; the `approveConsent` POST body is captured and asserted free of any codec form of the seed (I10) |
| L2 save           | network interception (Playwright): the whole save flow issues zero requests whose body contains the seed in any codec form; Enter in the password field produces no request (submit-event `preventDefault`, `method="dialog"`) (I11)                                                                                                                         |
| Fragment survival | per-engine Playwright (Chromium, Firefox, WebKit): the fragment survives each RP's full callback 3xx chain to the landing page; canary: injecting a JS redirect into the chain drops the fragment and the RP lands in its connect state (8.3), proving the failure mode is fail-closed                                                                       |
| Badge gate        | wizard refuses during PENDING_BACKUP; allowed at `none` and ACTIVE                                                                                                                                                                                                                                                                                           |
| SDK               | `extractMinisterAppSecret`: present/absent/malformed/v2-unknown fragments; scrub verified via jsdom history; integration with existing `deriveIdentity` chain reproduces fixed commitments from the goldens                                                                                                                                                  |
| Invariant harness | a logging fake server (Ministry side) and a logging RP server run through the full flow; assert transcript contains no seed material (the executable form of I1/I2)                                                                                                                                                                                          |
| Pairing           | deferred to its protocol spec; interface-level: code absent from all relay payloads, attempt/TTL limits                                                                                                                                                                                                                                                      |

## 15. Out of scope / v2

- Option 9, the `seed.ministry.id` key-holder iframe: the committed v2
  hardening; v1's obligation is the single seam (7.5).
- `PasswordCredential` with `mediation: "optional"`: rejected (checklist
  item 10 in section 12).
- Passphrase-encrypted IndexedDB vault: dominated, not built.
- "Trust this device" zero-friction unlock: not in v1; if ever, an explicit,
  plainly-warned per-device toggle.
- Wallet-signature factors, OPRF tiers, Signet involvement: dead with the
  tiered design.
- Anonymous credentials at join (hiding `sub` ↔ commitment from the RP at
  registration): pre-existing, orthogonal, larger project.
