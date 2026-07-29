# Anonymous seed: day-to-day key storage - scored options

Status: options writeup for review, 2026-07-13. This decides ONE sub-problem of the
anon-identity model settled 2026-07-09. Settled and not revisited here: one
client-side root secret generated in the ministry.id browser (server never sees
it); per-app secrets via HKDF(seed, app_id) derived in the ministry.id page and
delivered to the RP browser over the URL fragment; forced backup + recall quiz
before meaningful badges; cross-device pairing (QR + short-code PAKE + seed
re-entry) exists separately. The tiered PRF-root/OPRF design is dead and stays
dead. One amendment IS on the table here (2026-07-13 direction): the root's
_encoding_ - originally sketched as a 24-word BIP39 phrase - is re-evaluated below,
because it is tightly coupled to the password-manager storage options.

## The sub-problem

The backed-up root secret is the backup, not the daily key. Nobody re-enters it per
login, so the seed (or a key derived from it) needs a day-to-day home in the
browser at ministry.id, plus an unlock step cheap enough to run on every RP login
redirect.
This doc maps that option space and scores it, UX weighted heavily, security stated
honestly for each.

## The invariant threat: malicious JS on ministry.id

Every option lives inside the ministry.id origin's JavaScript. An XSS or
supply-chain compromise of that origin is the dominant risk, and it splits into
three postures. No option escapes the first:

1. **At use time, XSS always wins.** While a login is in flight, the seed or the
   per-app secret is in JS-reachable memory. Every option concedes this window.
2. **At rest, options differ.** Is the seed silently readable by injected JS at any
   moment (persistent, plaintext-equivalent), readable only after a user gesture
   (autofill tap, biometric), or absent from the device entirely?
3. **Blast radius.** Does one compromise exfiltrate the root seed once and forever,
   or only let the attacker abuse derivation while a user is present? Option 9 is
   the only one that changes this axis.

Read each option below as: what does XSS get, and how much user action does it need.

## Root secret encoding

The root is just entropy, and 128 bits is ample: Semaphore identities over BN254
top out around 128-bit security, so a 256-bit root buys nothing. The encoding
question is pure UX, and it is coupled to the storage options because a
password-manager home wants a password-shaped value.

| Encoding                                   | Size           | Entropy   | Typo protection     | Hand transcription                  | PM fit  |
| ------------------------------------------ | -------------- | --------- | ------------------- | ----------------------------------- | ------- |
| E1: 24-word BIP39                          | ~160-190 chars | 256 bits  | checksum + wordlist | good, but long                      | awkward |
| E2: 12-word BIP39                          | ~80-95 chars   | 128 bits  | checksum + wordlist | good                                | awkward |
| E3a: 22-char base58                        | 22 chars       | ~129 bits | none                | fair (no 0OIl, case-sensitive)      | native  |
| E3b: 28-char base58check                   | 28 chars       | 128 bits  | 32-bit checksum     | fair (case-sensitive)               | native  |
| E3c: 27-char Crockford base32 + check char | 27 chars       | 130 bits  | check symbol        | good (case-insensitive, maps o/i/l) | native  |
| (rejected) 20-char alphanumeric            | 20 chars       | ~119 bits | none                | poor (0/O, 1/l/I ambiguity)         | native  |

- **E1, 24 words (the original sketch):** double the entropy the system can use,
  double the intimidation. Works in a password field but wraps badly in PM UIs and
  reads like a mistake. The checksum and wordlist make paper backup and re-entry
  the most forgiving of any encoding. ★★
- **E2, 12 words:** right-sized entropy, same paper-friendliness, half the dread.
  Still an odd citizen in a password field. ★★★
- **E3, password-shaped string:** slots natively into "Save password?", the
  Credential Management API, and cloud sync - it looks like every generated
  password the user already has. The cost lands on the write-it-down path: random
  chars transcribe worse than words. Bare base58 (E3a) has no typo detection, so
  if a string is canonical it should carry a checksum: base58check (E3b) or
  Crockford base32 with its check symbol (E3c, case-insensitive, the most
  forgiving to hand-enter). ★★★★
- **E4, dual encoding, one canonical:** the same 16 bytes rendered both ways. The
  string is canonical: it is what goes in the password field, what pairing
  transfers, what recovery asks for. The 12 BIP39 words of the same bytes are
  printed on the backup sheet as the write-it-down aid, where words genuinely are
  better. Recovery input accepts both (detection is trivial: whitespace + wordlist
  means words); refusing to parse words we ourselves printed would be a
  self-inflicted failure mode, but the UI presents the string as the one true key,
  not two equal paths. The 3-word recall quiz keeps working against the printed
  words. Cost: a BIP39 encode/decode and a two-branch parser. ★★★★★

Storage-option coupling, in one place: options 1, 2, and 3 (the PM family) want
E3/E4 and merely tolerate words; option 4 (typing per session) and any
paper-recovery path prefer words, which E4 preserves; options 5-9 hold raw bytes
at rest, so encoding only matters at backup and recovery entry.

---

## Option 1: browser password manager via a login-style form

Present a real `<form>` at enrollment (username `anonymous-writing-key`, password =
the canonical root string); the browser's own password manager offers to save it,
and autofills it on the authorize page at each login.

- **Enroll:** right after forced backup + quiz, one extra screen submits the form;
  the browser prompts "Save password?". One tap, zero new concepts.
- **Per login:** user taps the unlock field on the authorize page, picks the
  autofill entry (Face ID / Touch ID / Windows Hello if the store is locked), flow
  continues. 1-2 taps, no typing. Cache in `sessionStorage` for the rest of that
  tab's flow so multi-step consent does not re-prompt.
- **Cross-device:** free wherever the manager syncs (iCloud Keychain, Google
  Password Manager, Firefox Sync, 1Password, Bitwarden). New phone in the same
  ecosystem: autofill just works, no pairing.
- **New/lost device:** nothing lost; the PM entry is a full seed copy, paper backup
  stays root.
- **Security:** at rest the seed sits in the browser/OS password store (and the
  vendor cloud if sync is on, see option 3). XSS gets the seed after inducing one
  autofill: Chrome exposes the filled value to JS after a user gesture, Firefox has
  historically filled with little or no gesture (the 2017 login-manager-sniffing
  attacks), Safari requires an explicit QuickType tap. Treat a PM-stored seed as
  reachable by a patient XSS that renders a fake unlock form. Upside: the manager
  only offers the entry on the real ministry.id origin, which kills phishing pages.
- **Support:** universal, desktop and mobile, every browser, plus third-party
  managers. Not script-writable storage, so Safari's 7-day ITP eviction does not
  apply - the one persistent home Safari never wipes.
- **Encoding:** wants E3/E4. A ~28-char generated-password-looking string is a
  first-class citizen in every save prompt and PM UI; a word phrase works (managers
  store submitted values verbatim, and even 24 words fits length limits) but wraps
  badly and reads like a mistake.
- **Touches:** one enrollment screen and one unlock component in the authorize flow
  in `apps/minister`; no server, no schema. Save-prompt heuristics need a real form
  submission or navigation on Safari/Firefox; Chromium can use option 2's
  `store()` instead.
- **Caveat:** users with the manager disabled, or who decline the save, fall
  through to option 4 (re-enter or pair each session).

**Score: ★★★★★** - the only option that is universal, low-friction, sync-included,
and eviction-proof at once.

## Option 2: Credential Management API (`PasswordCredential`)

Same underlying store as option 1, driven programmatically:
`navigator.credentials.store()` to save (reliable prompt, no form heuristics) and
`navigator.credentials.get({password: true})` to fetch via a browser-drawn account
chooser.

- **Per login:** one click on the chooser; with `mediation: "optional"`, zero
  clicks after the first consent (silent retrieval).
- **Cross-device:** identical to option 1 (same store, Google PM sync).
- **Security:** same at-rest story as 1, with one sharpening: silent mediation
  means injected JS can read the seed with **no user gesture at all** once the user
  consented once. `mediation: "required"` restores the gesture at the cost of a
  click. That choice is a real security/UX dial, flagged in open questions.
- **Support:** Chromium only (Chrome, Edge, Android Chrome). Safari: not
  implemented. Firefox: not implemented (standards position open since 2023,
  nothing shipped). It can only ever be an enhancement layered on option 1, never
  the mechanism.
- **Touches:** a small progressive-enhancement branch in the unlock component.

**Score: ★★★** standalone (half the web missing); worth shipping as a layer on 1.

## Option 3: password-manager cloud sync as the cross-device story

Not a separate mechanism - the consequence of options 1/2 when the user's manager
syncs. The seed becomes an object in the user's Apple/Google/vendor vault, and
cross-device comes free.

- **UX:** this is the whole mainstream cross-device answer. Sign into the same
  Apple ID or Google account on a new device and ministry.id unlocks with a tap.
  Pairing shrinks to a fallback for cross-ecosystem hops (Android to iPhone, Chrome
  to Firefox) and PM-less users.
- **Trust posture, stated plainly:** the seed now rests in a vendor vault.
  - iCloud Keychain: end-to-end encrypted; Apple says it cannot read entries. The
    real surface is Apple account recovery - whoever can recover the Apple ID can
    reach the seed.
  - Google Password Manager: encrypted at rest, but by default Google holds keys
    (recoverable via Google account auth). On-device encryption is opt-in;
    once on, Google cannot read but also cannot recover.
  - 1Password/Bitwarden: end-to-end, user-key derived.
- **Consequence:** the anonymous-authoring identity gains a dependency it did not
  have: an adversary who owns the user's Apple/Google account (or compels a vendor
  that holds keys) can extract the seed and link every pen name. Familiar and
  acceptable for most users; exactly why options 4 and 6/7 exist as opt-outs for
  the rest.
- **Encoding:** with E3/E4 the synced entry is indistinguishable from every other
  generated password in the vault, which is exactly the normalcy we want.

**Score: ★★★★** as the bundled cross-device story (one star docked for the vendor
vault trust it quietly adds).

## Option 4: session-bound, memory-only

The seed enters the browser once per session (typed, or delivered by pairing) and
lives only in a JS variable; nothing is persisted, everything is gone on tab close.

- **UX:** brutal for a wallet-shaped product. Ministry sees bursty use with days
  between logins; every new browser session costs a root-secret entry or a pairing
  ceremony before any RP login works. Encoding matters most here: transcribing
  from paper favors the words (checksum, wordlist autocomplete), so E4's printed
  words earn their keep in exactly this option. `sessionStorage` can stretch one unlock
  across reloads and the redirect round-trip within a tab, but a new tab or browser
  restart starts over. Cross-device: nothing; pair every time.
- **Security:** the best at-rest posture available. A stolen, seized, or imaged
  device holds nothing; injected JS running while the user is not mid-session finds
  nothing. XSS at use time still captures the seed as it is typed or received.
- **Support:** universal, trivially.
- **Touches:** unlock component plus a "never store my key" settings toggle.

**Score: ★★** - wrong default, right opt-in for users who will tolerate it.

## Option 5: local passphrase-encrypted vault (IndexedDB)

Seed encrypted under a user-chosen passphrase (Argon2id, or PBKDF2 if we refuse the
WASM dep, then AES-256-GCM), ciphertext in IndexedDB; passphrase typed once per
session.

- **UX:** invents a new password for a product whose pitch is not having one.
  Enrollment adds "choose a strong passphrase" with all the weak-and-reused
  baggage. Per login: type it once per session. Cross-device: none - the vault is
  per browser profile, so every new device is a pairing or seed re-entry plus vault
  re-enrollment.
- **Two sharp edges:**
  - Safari's ITP deletes script-writable storage, IndexedDB included, after 7 days
    of Safari use without visiting the site. A bursty user's vault evaporates;
    backup covers correctness, but "my key vanished again" is a rotten loop.
    `navigator.storage.persist()` helps on Chromium, not Safari.
  - The ciphertext is exactly as strong as the passphrase. Injected JS can lift the
    ciphertext any time and brute-force weak passphrases offline, or just keylog
    the passphrase field at unlock. Argon2id (via `hash-wasm`) raises offline cost
    meaningfully over native-WebCrypto PBKDF2 and is worth the dependency if this
    is built at all.
- **XSS gets:** ciphertext at any moment; passphrase and seed at unlock time.
- **Touches:** unlock component, vault module, Argon2 WASM dependency.

**Score: ★★★** as an opt-in, and dominated: option 4 beats it for the paranoid,
options 1/6 beat it for everyone else. Recommend not building it unless asked for.

## Option 6: passkey (WebAuthn PRF) as an optional vault unlock

A ministry.id passkey created with the PRF extension yields a 32-byte secret at
each assertion; use it as the KEK to AES-wrap the seed, so unlock is one biometric
tap.

**This is not the killed Tier A.** There, the PRF output _was_ the root secret:
lose the passkey, lose the identity. Here PRF only wraps a _copy_; the 24-word seed
remains the root, and losing the passkey costs one seed re-entry followed by a
re-wrap. Backup semantics are unchanged.

- **UX:** the best per-login feel of any option - one Face ID / Touch ID / Windows
  Hello tap, no typing, no field to find. Enrollment is one "add fingerprint
  unlock" tap after backup. Cross-device: PRF output for a synced passkey is stable
  across devices in the same ecosystem, but the wrapped blob in IndexedDB does not
  sync, so a new device needs one pairing/seed entry and a re-wrap. Option 7 fixes
  that gap.
- **Security:** at rest the seed is wrapped under a key that exists only during a
  WebAuthn assertion. Injected JS cannot decrypt without inducing a biometric tap,
  a real gesture barrier and a stronger one than PM autofill on Chromium/Firefox.
  After the tap, XSS gets the seed like everywhere else. The local blob shares
  IndexedDB's Safari eviction problem.
- **Support (mid-2026):** Chrome/Edge desktop and Android solid; Safari 18+ / iOS
  18+ works with iCloud Keychain platform passkeys (no PRF to roaming security keys
  on iOS/iPadOS); Firefox 139+ for platform authenticators, 148+ for Windows Hello.
  Q1 2026 community testing measured ~100% PRF-on-create success with the big
  synced providers. Good enough to offer behind feature detection, not to require.
- **Touches:** unlock component plus a dedicated WebAuthn `create()`/`get()` path
  carrying the `prf` extension. Minister already ships passkey login via Auth.js;
  whether to enable PRF on the login passkey or mint a second credential is an open
  question below.

**Score: ★★★★** - the premium unlock, layered on the default rather than replacing
it.

## Option 7: Ministry-hosted encrypted blob

Store the wrapped seed server-side (PRF-wrapped, or passphrase-wrapped as a lesser
variant); any logged-in browser fetches the ciphertext and unlocks client-side. The
server holds ciphertext only, never plaintext.

- **UX:** closes option 6's one gap - cross-device without touching the vendor
  password vault. New device: sign into ministry.id, one tap on the synced passkey
  (PRF yields the same KEK), the blob decrypts, done. No pairing, no QR.
- **Security:** the server now holds ciphertext keyed to the account. PRF-wrapped:
  the KEK is high-entropy, there is no brute-force story, and compromise requires
  both Ministry's DB and the user's passkey. Passphrase-wrapped: Ministry's DB
  becomes an offline-crackable oracle for every weak passphrase; do not ship that
  variant without Argon2id and a strength gate, and even then it is the weakest
  leg here. Soft metadata note: Ministry now stores an artifact saying this account
  uses anonymous authoring (existence, not content).
- **XSS gets:** ciphertext freely while logged in; the seed only after the tap.
- **Support:** same PRF matrix as option 6.
- **Touches:** one table (`userId`, wrapped blob, wrap method, timestamps), two
  authenticated server actions or routes, unlock component.

**Score: ★★★★** combined with option 6 (PRF-wrapped); ★★★ for the passphrase
variant.

## Option 8: "trust this device" persistent unlock

Seed wrapped under a non-extractable WebCrypto `CryptoKey`, both stored in
IndexedDB; page JS can unwrap on load, so per-login interaction is zero.

- **UX:** the zero-friction ceiling. RP logins flow through ministry.id with no
  visible unlock at all. Enrollment is a checkbox.
- **Security, honestly:** plaintext-equivalent at rest. The non-extractable
  `CryptoKey` blocks raw key export, but injected JS simply _uses_ the key to
  unwrap and reads the seed - silently, with no gesture, whenever it likes, user
  present or not. This option hands XSS the most: a drive-by compromise exfiltrates
  every trusting user's seed. The non-extractable wrap is still worth doing (it
  defeats copy-the-IndexedDB-file disk exfil); just do not pretend it does more.
  Safari's 7-day eviction applies.
- **Support:** universal (WebCrypto + IndexedDB), with the Safari caveat.
- **Touches:** unlock component and a settings toggle.

**Score: ★★★** - acceptable only as an explicit, plainly-warned per-device opt-in,
never a default.

## Option 9: separate-origin key holder (hardening layer)

Move seed storage and HKDF derivation into a tiny static page on its own origin
(say `seed.ministry.id`), embedded as an iframe; the ministry.id app requests
per-app secrets over `postMessage` and never touches the seed itself.

- **Why it exists:** this is the only option that changes the central threat. XSS
  on ministry.id can no longer read the seed at all; it can only request
  derivations for app ids of its choosing while a user is present, and the iframe
  can require an in-iframe click per derivation and rate-limit. Blast radius drops
  from "root seed exfiltrated once, game over forever" to "per-app secrets abused
  during the compromise window". The key-holder origin must be boring on purpose:
  static files, zero third-party JS, strict CSP, tight release discipline. Its own
  compromise is still game over, but its attack surface is a fraction of the app's.
- **UX:** invisible - it composes with options 6, 7, or 8 for the storage and
  unlock _inside_ the iframe. Note PM autofill (option 1) into a cross-origin
  iframe is unreliable, so the natural pairings are PRF or trusted-device storage
  keyed to the key-holder origin.
- **Costs:** a second origin to build, serve, version, and keep in lockstep; a
  postMessage protocol with strict origin checks; more moving parts on every
  login. Real engineering, and the only line item here that buys down the stated
  dominant risk structurally.
- **Touches:** new static origin plus serving infra, postMessage API, rework of the
  derivation path.

**Score: ★★★★** as a v2 hardening layer. Do not block launch on it.

---

## Summary

| #   | Option                          | Per-login friction               | Cross-device                    | XSS-at-rest exposure              | Support                                          | Score      |
| --- | ------------------------------- | -------------------------------- | ------------------------------- | --------------------------------- | ------------------------------------------------ | ---------- |
| 1   | Browser PM, login form          | 1-2 taps (autofill)              | free with PM sync               | seed, gesture-gated (weakly)      | universal                                        | ★★★★★      |
| 2   | `PasswordCredential`            | 0-1 click                        | same as 1                       | seed, silent read possible        | Chromium only                                    | ★★★        |
| 3   | PM cloud sync (property of 1/2) | -                                | the mainstream answer           | adds vendor-vault trust           | wherever PM syncs                                | ★★★★       |
| 4   | Memory-only session             | 24 words or pairing, per session | none                            | none                              | universal                                        | ★★         |
| 5   | Passphrase vault, IndexedDB     | passphrase per session           | none                            | ciphertext at passphrase strength | universal; Safari evicts                         | ★★★        |
| 6   | PRF-wrapped local vault         | 1 biometric tap                  | ecosystem passkey + one re-wrap | biometric-gated                   | Chrome, Safari 18+, FF 139+; no iOS roaming keys | ★★★★       |
| 7   | Server-hosted wrapped blob      | same as its wrap                 | any logged-in device            | ciphertext, server-side           | as 6                                             | ★★★★ (PRF) |
| 8   | Trust this device               | zero                             | none                            | seed, full and silent             | universal; Safari evicts                         | ★★★        |
| 9   | Separate-origin key holder      | unchanged                        | n/a (layer)                     | derivation abuse only             | universal                                        | ★★★★ (v2)  |

## Interaction with pairing

- Options 1+3 mostly replace pairing _inside_ an ecosystem: iCloud/Google PM sync
  moves the seed for us. Pairing remains for cross-ecosystem hops, PM decliners,
  and option 4/5 users.
- Options 6+7 replace pairing wherever the passkey syncs, and work for users who
  refuse password saving.
- Options 4 and 5 lean on pairing hardest: every new device is a ceremony.
- Nothing here removes pairing. It stays as the universal backstop, just exercised
  less.

## Recommendation

**Canonical encoding: E4 with a 128-bit root.** One 16-byte secret, rendered
canonically as a checksummed password-shaped string (base58check, ~28 chars, or
Crockford base32 with check symbol if we prefer case-insensitive hand entry), and
additionally as the 12 BIP39 words of the same bytes on the printed backup sheet.
The string is what the password manager saves, what pairing transfers, and what
recovery asks for; the words are the write-it-down aid, and recovery parses either.
This replaces the original 24-word sketch: 256 bits was security theater on a
128-bit curve, paid for in user dread.

**Default (v1): option 1, with 2 layered on Chromium, and 3 embraced as the
cross-device story.** After forced backup + quiz, one more screen submits the
canonical string as a saved login; the browser offers to save; each RP login
autofills it in 1-2 taps on the authorize page. Universal support, zero new
concepts, immune to Safari storage eviction, cross-device rides PM sync. Say the
trade out loud in the UI copy: "your key is stored by your browser's password
manager and syncs wherever it does."

**Fast follow (v1.x): options 6+7, PRF-wrapped, as the premium unlock.** "Unlock
with Face ID" - one biometric tap, cross-device via synced passkey plus
server-held ciphertext, no dependence on autofill quirks or the vendor password
vault. Offered where PRF feature-detects; falls back to the default elsewhere.

**Opt-out for the paranoid: option 4** ("never store my key") as a settings
toggle. Skip building option 5; it is dominated on both flanks.

**Explicit non-default: option 8** only as a labeled "keep me unlocked on this
device" toggle, if ever.

**Hardening backlog (v2): option 9.** It is the only structural answer to the
ministry.id-XSS threat; schedule it once the flow is stable, and design the v1
unlock component so the derivation call sits behind one seam.

## Open questions for a reviewer

1. `PasswordCredential` mediation on Chromium: `"optional"` (zero-click after first
   consent, but silent XSS reads) or `"required"` (always one gesture)? UX-first
   says optional; is the silent-read regression acceptable?
2. String alphabet: base58check (compact, case-sensitive, Bitcoin-familiar) or
   Crockford base32 with check symbol (longer, case-insensitive, kindest to hand
   entry)? Draft leans base58check since E4's printed words carry the
   hand-transcription role anyway.
3. Do the 12 words appear on the backup sheet at all, or is the sheet
   string-only? Dropping them simplifies the sheet and the recovery parser but
   gives up the most typo-tolerant paper path (and the word-based recall quiz
   would need a string-based replacement).
4. Option 6: enable PRF on the existing Auth.js login passkey at creation, or mint
   a dedicated second credential? Reuse is fewer ceremonies but couples login auth
   to seed unlock, and needs verifying against the current WebAuthn stack.
5. Is the option 7 server-side metadata (account X has an anon-authoring blob)
   acceptable, or should blob presence be padded or made universal?
6. Is `sessionStorage` caching of the unlocked seed for the remainder of a tab's
   flow acceptable, or memory-only within the page lifecycle?
7. Enrollment ordering: do we block badge earning until the PM save (or an explicit
   decline) in addition to the 3-word quiz?
8. When option 9 lands, which storage lives inside the key-holder origin? PM
   autofill in a cross-origin iframe is unreliable, so likely PRF or
   trusted-device.

## References

- PRF support matrix and Q1 2026 field data: corbado.com/blog/passkeys-prf-webauthn
- `PasswordCredential` availability: MDN PasswordCredential; caniuse.com/credential-management;
  mozilla/standards-positions#842 (unimplemented in Firefox)
- Safari 7-day script-writable-storage cap: WebKit ITP announcements (iOS 13.4 /
  Safari 13.1, still in force); note saved passwords are not script-writable
  storage and are exempt
