# Anonymous identity derivation: tradeoffs and UX (decision companion)

Status: decision companion to `anon-identity-derivation-design.md`. This one is
written for a decision, not for a build. Plain language, no crypto background
assumed. If you want the formal construction and the scored primitive options,
read the design doc; this doc exists so you can decide with confidence and so a
reviewer can attack the choices.

## TL;DR

**The problem.** Today FreedInk, Discreetly, and Deforum each make the user back
up a per-app secret (a 24-word phrase or an encrypted vault) to hold their
anonymous authoring identity. Lose it, lose every anonymous post you ever made in
that app, forever. We want to **derive** that secret from the user's Ministry
login instead, so there is nothing to back up, while keeping the secret
unknowable to **both** Ministry and the app.

**The shape being proposed.** Three tiers, picked by what the user can reproduce:

- **Tier A (WebAuthn PRF):** for passkey users. The secret comes out of the
  passkey itself. Ministry holds nothing. Strongest posture, best "nothing to back
  up" story. Not universal (some browsers/passkey stacks lack the PRF feature).
- **Tier B (Signet OPRF):** for magic-link / no-passkey users. The secret is a
  keyed hash of the user's Ministry id, computed with Signet's key, where Signet
  never sees the input and never sees the output. Universal, but weaker: it rests
  on Ministry and Signet not colluding.
- **Tier C (encrypted vault):** the status-quo backup, kept only as an opt-in
  escape hatch and belt-and-suspenders.

**The one hard truth, up front.** For a user whose only reproducible credential is
their Ministry login (magic-link, no passkey), you cannot have both "reproduces
from just a Ministry login" and "unknowable to Ministry and its key custodian."
Such a user brings no secret of their own, so the identity provider side is
_necessarily_ one of the factors. Tier B contains that by splitting the secret
across three custodians (Ministry, Signet, the app), but it is a real, permanent
limit, not a gap we can close with a cleverer primitive. Everything about Tier B
is downstream of accepting or rejecting that.

**My editorial lean, stated once:** Tier A plus Tier C is probably the whole v1.
Tier B is the most new cryptography in the design (a from-scratch JS OPRF client,
a security-audit gate, a relay endpoint, and delivery plumbing) and it serves a
minority we can shrink further by nudging them to add a passkey. Ship A + C, then
build Tier B only if the leftover magic-link-only population is actually worth it.
See "Is this over-built?" at the end. The rest of this doc gives you what you need
to disagree with me.

---

## 1. The UX, front and center

This is the part that matters most, so it goes first. Four journeys.

### Journey 1: passkey user (Tier A)

First sign-in to Deforum via Ministry. Behind the OIDC login, the SDK does one
extra passkey tap and pulls a 32-byte secret straight out of the authenticator.
It derives the app identity from that. The user joins a sub-forum. **No backup
prompt, ever.** No 24 words, no vault password.

New phone, same Apple or Google account: the passkey syncs, one tap, identical
secret, identical identity. Nothing to restore, it just works.

Lost the phone but still has the iCloud / Google account: recover the passkey the
normal way (ecosystem account recovery), get the same identity back.

Friction lands in exactly two places: one extra passkey tap (which we can cache
per session so it is not every action), and the 2026 reality that some passkey
stacks do not support the PRF feature at all (see the primer). When PRF is
missing, this user is not a Tier A user on that device, which is where the
failure mode below bites.

### Journey 2: magic-link user (Tier B)

First sign-in via a magic link to email. There is no passkey, so no secret in an
authenticator. Instead the SDK obtains the user's Ministry id (delivered to the
browser only, never to the app server), blinds it, and asks Signet to evaluate its
OPRF. Signet returns a blinded result plus a proof it used the honest key; the
browser unblinds it into the 32-byte secret and derives the identity. **Again no
backup prompt.**

New device: sign into Ministry again (new magic link), same Ministry id, same
OPRF output, same identity. The user only ever manages their email login.

The catch is not in the flow, it is in the guarantee. This user's anonymity rests
on Ministry (which knows their id) and Signet (which holds the key) not combining
their halves. That is strictly weaker than Tier A, where Ministry holds nothing.
It is still much better than the status quo (today that user backs up a vault by
hand), and it splits the secret across three parties, but be honest with yourself
that it is a _non-collusion_ assumption, not a _cannot_ assumption.

### Journey 3: returning user on a new device (the crux)

The client signs into Ministry. Ministry serves back a small, non-secret hint:
"for this user at this app, you are Tier A, enrolled credential C." The client
reproduces the **same** tier and the **same** identity.

If it can (passkey synced, or OPRF reachable): seamless, same identity.

If it cannot reproduce the pinned tier on this device (pinned Tier A, but this
browser has no PRF): the client **must not** quietly drop to Tier B. It stops and
tells the user "use your passkey, or a device that has it, or restore your backup."
Silently dropping a tier is the single worst bug in this whole design, described
next.

### Journey 4: the user who loses everything

Tier A user who used one authenticator, never synced it, and lost it: the secret
lived only in that authenticator, so the identity is gone. Same as losing a lone
hardware security key. This is why Tier C (the optional vault) exists as a hedge.

Tier B user who lost their devices but still has their email: they recover fully,
because all they ever needed was the Ministry login. This is Tier B's one real
advantage over Tier A.

So the asymmetry is worth internalizing: **Tier A is stronger against a breach but
weaker against user loss** (if unsynced); **Tier B is weaker against a breach but
stronger against user loss.** Tier C is the opt-in backup for anyone who wants
loss-recovery without leaning on Signet.

### The silent second-identity failure (read this twice)

Your anonymous identity in an app is 100% determined by the derived root secret
`R_rp`. `R_rp` depends on which tier produced the input secret. If the same human
lands in a **different tier on a different device** (Tier A on the laptop where the
passkey works, Tier B on the phone where the passkey did not sync), the two tiers
produce two different secrets, two different identities, two different Semaphore
commitments.

Nothing crashes. The app just quietly treats you as a **brand-new member**: it
registers a second membership leaf, and your old posts' authoring identity is
stranded. You can no longer produce its nullifiers, cannot prove you are the same
anonymous author, cannot edit or delete your old content. You now hold two
anonymous identities in the same forum with no way to merge them. It is invisible
because there is no error; the derivation simply returned different bytes.

**The fix: per-(user, app) tier pinning.** Ministry stores a non-secret hint per
user per app: "tier = A, enrolled credential = C." Every login, Ministry serves it.
The client uses it to (1) reproduce the exact enrolled tier and credential, and
(2) **refuse to silently fall to a lower tier.** If it cannot satisfy the pinned
tier on this device, it stops and guides the user instead of minting a fresh
identity. Tier selection becomes deterministic per _user_, not per _device_, which
is the whole point.

Two honest notes on the pin. First, it hands Ministry a new piece of linkable
metadata ("this pairwise sub is a Tier-B magic-link user at Deforum") that is
non-secret by design but is still something Ministry did not hold before. Second,
Tier A has its own version of this bug: a user with both an Apple passkey and a
Google passkey has _two_ PRF outputs. The pin must lock one enrolled credential and
refuse the other, not fork. Both belong in the reviewer's crosshairs.

---

## 2. Primer: the primitives, in plain language

One short paragraph each. For each: what it does, what secret it protects, and who
can learn what.

**WebAuthn PRF extension.** A standardized feature that lets your browser ask a
passkey to compute a deterministic 32-byte secret from a fixed label, during an
ordinary passkey tap. Same passkey plus same label always yields the same bytes.
_Protects:_ the Tier A input secret. _Who learns what:_ the value is computed
inside the authenticator and handed only to your browser's JavaScript. Ministry
never sees it, the app server never sees it, the network never sees it (nothing is
sent). A thief with your unlocked device and passkey could produce it, same as if
they stole the passkey. _Caveat:_ it only exists on PRF-capable passkey stacks; a
_synced_ passkey reproduces the value across your devices in one ecosystem (iCloud,
Google), a _non-synced_ security key does not.

**HKDF.** A standard key-blender. It takes one secret plus a non-secret salt and a
context label, and deterministically produces one or many independent subkeys. It
is not itself a source of secrecy; it cannot make a public input secret. It only
stretches and domain-separates a secret you already have. _Protects:_ nothing on
its own. In our design it combines the tier's input secret, the app's salt, and the
context into the final per-app, per-context key so different apps and contexts get
unlinkable keys. _Who learns what:_ anyone holding all the inputs can recompute the
output; the security comes entirely from the input secret being secret.

**OPRF (RFC 9497).** "Oblivious pseudorandom function." A two-party keyed hash: a
server holds a secret key, a client holds an input, and they run a protocol so the
client learns `F(key, input)` while **the server learns nothing about the input**
and the client learns nothing about the key. It is a hash you can only evaluate by
talking to the key-holder, without ever showing the key-holder your input.
_Protects:_ the Tier B input secret. In our use Signet holds the key and the browser
holds the user's Ministry id. _Who learns what:_ Signet never sees the input or the
output (only a scrambled value); the browser never sees the key. To recompute the
secret offline you need **both** Signet's key **and** the input (which lives in
Ministry's database). RFC 9497 is the IETF standard that pins the exact math and
wire format; Signet already implements it.

**VOPRF vs plain OPRF.** The "V" is _verifiable_. In a plain OPRF the client cannot
tell whether the server used the honest key or a sneaky per-user key. A VOPRF adds
a short proof (a DLEQ proof) that the server used the key matching a published
public key, without revealing the key; the client checks the proof and rejects a
mismatch. _Protects:_ against a malicious or coerced Signet trying to **tag** one
user with a distinguished key to make that user's output recognizable. _Who learns
what:_ same secrecy as a plain OPRF, plus the client gets cryptographic assurance
the server did not cheat on the key. Signet's implementation is a VOPRF with these
proofs.

**"Blind" OPRF / blinding.** The trick that makes an OPRF oblivious. Before sending
its input, the browser multiplies it by a random secret factor, so the server sees
a value that looks completely random and reveals nothing about the real input. The
server evaluates on that scrambled value; the browser divides its random factor
back out to recover the true result. _Protects:_ your input from the evaluator.
_Who learns what:_ the server (Signet) sees only the scrambled value, which is
indistinguishable from random; the random factor never leaves the browser, so no
one else can unscramble it. This is precisely why the input can be relayed **through
the app's own server** safely: the app server also sees only the scrambled value.

**Encrypted device vault.** The status-quo backup. The secret is encrypted under a
key stretched from a user password (PBKDF2, 600k iterations) with AES-GCM, stored as
a blob, with a 24-word phrase as an offline backup. To restore on a new device the
user supplies the password (and blob) or types the 24 words. _Protects:_ the secret
at rest against anyone without the password. _Who learns what:_ no server ever sees
the plaintext or the password; security rests entirely on the user's password
strength and on them keeping the blob or phrase. This is exactly the friction we
are removing from the default path, which is why it survives only as an opt-in
escape hatch.

---

## 3. The tiered model at a glance

|                                    | **Tier A: WebAuthn PRF**                          | **Tier B: Signet OPRF**                                           | **Tier C: Encrypted vault**                               |
| ---------------------------------- | ------------------------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------- |
| **Serves**                         | passkey users on PRF-capable stacks               | magic-link / no-passkey users (universal)                         | anyone, opt-in escape hatch                               |
| **Enrollment**                     | one extra passkey tap; pin the credential         | blind the Ministry id, one OPRF round trip                        | set a password, keep the 24 words                         |
| **New device**                     | passkey syncs -> same identity, one tap           | log into Ministry -> same id -> same identity                     | supply password + blob, or type 24 words                  |
| **Lost everything**                | gone unless synced or backed up to Tier C         | recovers from just the email login                                | recovers iff the user kept the backup                     |
| **What Ministry learns**           | nothing that derives the secret                   | the OPRF input (the user id), not the key                         | nothing                                                   |
| **What the app server learns**     | nothing (never in the PRF)                        | only blinded values + a public proof                              | nothing (only ciphertext at rest)                         |
| **What a network attacker learns** | nothing (computed locally)                        | only TLS ciphertext + blinded values                              | only ciphertext                                           |
| **Breach blast radius**            | zero from Ministry; needs the device              | needs Ministry **and** Signet **and** the app salt                | needs the blob **and** the password                       |
| **Fail-closed behavior**           | no PRF on this device -> refuse, do not downgrade | bad DLEQ proof -> reject, mint nothing                            | wrong password -> decrypt fails, mint nothing             |
| **Infra / code touched**           | SDK WebAuthn-PRF module; Ministry tier pin        | Signet OPRF endpoint; JS OPRF client; relay endpoint; id delivery | existing `@ministryofmany/identity` vault (already built) |

The common derivation underneath every tier, unchanged from the design:

```
R_rp = HKDF-SHA256(
         ikm  = S_user,      // the tier's input secret (PRF / OPRF / vault)
         salt = RP_salt,     // the app's own secret contribution
         info = "minister/anon/v1:" + app_id + ":" + context )
```

`R_rp` then feeds the **existing** per-context identity derivation in
`@ministryofmany/identity` (`packages/identity/src/derive.ts`), unchanged. We only
change where the input secret comes from.

---

## 4. The three open forks (for the reviewer, genuinely open)

Each of these is a real decision with real tradeoffs. I state a lean where I have
one, but none is settled.

### Fork 2a: how the Tier-B OPRF input reaches the browser without the app server seeing it

The OPRF input (the user's Ministry id, or a stand-in for it) must reach the
browser but **never** the app server, because the app server plus the app salt would
otherwise be enough to attack the secret. Two ways to deliver it.

**Option A: URL fragment on the login redirect.** Ministry appends the input to the
redirect URL after a `#`. Browsers never send the fragment to servers, so the app
server cannot see it; only client JavaScript reads it. _Pros:_ no cookie
dependency, works under Safari ITP and post-third-party-cookie Chrome, rides the
redirect you already do. _Cons:_ the app's callback page must run client JS to grab
the fragment (server-rendered apps need a small client shim on that route); the
input lands in browser history and could be captured by a careless analytics or
error tool on that page, so you must scrub it from the URL promptly. Because the
input is a _stable_ per-user value (it has to reproduce), it is in history on
every login, a mild shared-computer concern.

**Option B: direct browser-to-Ministry authenticated fetch.** After login the app
page fetches the input from Ministry using the user's Ministry session cookie.
_Pros:_ clean, no fragment handling, input never in the URL or history. _Cons:_ this
is a cross-site request, so the Ministry cookie is a **third-party cookie**. Safari
ITP blocks it outright and Chrome is killing third-party cookies, so the fetch
arrives unauthenticated and Ministry cannot identify the user. The workarounds
(Storage Access API, CHIPS partitioned cookies, FedCM) are fragile, per-browser,
and add real complexity. In 2026 this path fights the platform.

**My lean:** fragment, because it sidesteps cookies entirely, at the cost of a
client shim per app and history hygiene. But consider a third shape: do not deliver
the raw user id at all. Deliver a stable, per-user **opaque derivation id**
(Ministry-stored, distinct from the real user id) via the fragment and use _that_
as the OPRF input. Same reproducibility, and if the fragment leaks it does not
directly name the Ministry user.

### Fork 2b: relay Ministry's blinded OPRF evaluation through the app server?

The flow: the browser blinds the input, hands the **blinded** element to the app
server (same origin, already holds the app session), the app forwards it to Signet,
relays the blinded result plus the DLEQ proof back, and the browser unblinds and
verifies. The app sees only blinded values (uniformly random, revealing nothing
about the input) and a public proof; the blinding factor and the final secret never
leave the browser, so the app cannot unblind.

On confidentiality this is **safe**: relaying blinded values leaks nothing usable,
and it dodges the third-party-cookie problem by reusing the existing same-origin app
channel. The honest caveats:

- **The DLEQ proof must be verified in the browser** against a pinned public key. If
  the client trusted the relay's output, a malicious app could feed a doctored
  result. Verified in-browser, a tampered relay fails closed (wrong output rejected,
  no identity minted).
- **The app becomes a metadata observer and the rate-limit chokepoint.** It sees
  when and how often a session derives (marginal, it already knows the user logged
  in) and it is the party that must throttle. If the app owns throttling, a
  malicious app could also grind the OPRF as an oracle for chosen inputs, but so can
  anyone who can reach Signet; input-secrecy (the app does not know the user id)
  plus Signet-side rate-limiting bound this.
- **The unglossed sub-fork: relay to whom?** (i) App -> Signet directly is the
  fewest hops, but Signet is currently mTLS-gated to Ministry only, so letting every
  app call Signet widens Signet's trust surface to all apps. (ii) App -> Ministry ->
  Signet keeps Signet's mTLS surface to Ministry, and Ministry sees only the blinded
  element plus the pairwise sub (blinded reveals nothing, and Ministry minted the
  sub anyway), so it is clean and lets Ministry own the per-sub rate-limit at the
  cost of an extra hop. **The design's "app -> Signet" phrasing quietly picks (i); I
  would push back and prefer (ii).**

**My lean:** the relay is safe for the invariant. The real open question is the
two-hop sub-fork and who owns rate-limiting, not whether relaying blinded values
leaks.

### Fork 2c: the app's secret salt, cheap env var vs per-app blind OPRF

Each app mixes in a secret Ministry does not hold, so a Ministry breach alone
cannot deanonymize the population. Two ways.

**Option (ii): per-app secret env var.** The app holds a high-entropy secret in its
environment and hands it to its own page as the HKDF salt. _Pros:_ near-zero infra,
one env var per app, degrades gracefully to a public salt if it ever leaks (you lose
the Ministry-breach separation but not the scheme), and it is held by a party that
still cannot deanonymize from it alone (the salt does not yield the identity secret).
_Cons:_ the salt reaches the browser, so a determined user can read _their own_ app's
salt (which does not help them attack anyone else, since each user's key needs their
own input secret), and an app-server breach leaks the salt (but the attacker still
needs the input secret: for Tier A that is in the authenticator, for Tier B it needs
Signet plus the user id).

**Option (iii): per-app blind OPRF.** The app runs its _own_ OPRF with a key that
never leaves the app server, even to the browser; the browser blinds, the app
evaluates and proves, the browser unblinds and mixes. _Pros:_ the app secret never
reaches the browser, and the operation is rate-limitable and revocable per app.
_Cons:_ it is a whole OPRF service, key custody, and proof-verifying client **per
app**, real recurring infra for a thin marginal gain. Recall the app already learns
the sub-to-commitment link at join; the salt's only job is Ministry-breach
separation, and the env var already delivers that.

**My lean:** for FreedInk, Discreetly, and Deforum as they stand, the env-var salt
is almost certainly right and per-app blind OPRF is over-built. The only case that
would justify (iii): an app that is itself a high-value deanonymization target and
wants defense against its own server breach being combined with a Signet breach.
None of the three current apps is obviously that. Ship (ii) everywhere; treat (iii)
as a "call us when you actually need it" upgrade.

---

## 5. Pieces this touches (the blast radius)

Concrete components that change, by home. File paths are from the current repos.

**Ministry (`Minister/`)**

- **Schema.** A new per-(user, app) tier pin: tier, enrolled credential id (for Tier
  A), created-at. Either a new model (e.g. `AnonDerivation`) or columns hung off the
  OIDC grant. In `apps/minister/prisma/schema.prisma`.
- **A derivation-hint endpoint** that serves the pin (and, for Tier B, the OPRF
  input) to the client post-login. This is the delivery decided in Fork 2a; if
  fragment, it is injected into the authorize redirect rather than a standalone
  route.
- **A relay endpoint** if Fork 2b lands as app -> Ministry -> Signet: an
  authenticated route that forwards a blinded element to Signet and relays the result
  back, rate-limited per pairwise sub. Reuses the existing pairwise-sub HMAC.
- No change to the pairwise-sub computation itself; it is reused as the rate-limit
  key.

**Signet (`Signet/`)**

- **Expose the client-blinded VOPRF for the anon-derivation input under a NEW domain
  tag**, distinct from the existing nullifier and pairwise key schedule, so the two
  never share a key. The VOPRF machinery already exists in `src/prf.rs` (RFC 9497,
  ristretto255-SHA512, DLEQ); this is a new handler in `src/handlers.rs` plus a new
  `info`/domain separator, and the mTLS gating for whichever relay shape 2b picks.

**`@minister/client` SDK (`minister-client/`)**

- **`packages/identity`:** add a `deriveRootSecret({ factor, rpSalt, rpId, context })`
  combiner in front of the existing `derive.ts`; add the v3/RLN
  `R_rp -> (trapdoor, nullifier)` expand alongside the existing v4 path (Discreetly
  needs it); re-expose the existing vault (`vault.ts`, already built) as the Tier-C
  surface. Golden test vectors for every derivation.
- **A new WebAuthn-PRF module:** the raw `navigator.credentials.get(...)` PRF
  assertion, capability detection, and the enrolled-credential pin. The Auth.js
  Passkey provider does not expose PRF, so this is a separate WebAuthn call the SDK
  owns.
- **A new ristretto255 VOPRF client:** blind, finalize, and DLEQ-verify against a
  pinned public key. Note the existing `packages/blind-token` is blind-**RSA**, not
  reusable here, so this is new but small and pinned to Signet's RFC 9497 test
  vectors.
- **A relay client** that talks to the app-server (or Ministry) relay endpoint.

**Each relying party**

- **Deforum (`deforum-space/`):** replace `loadOrCreateDeviceSeed()`
  (`src/lib/client/device.ts`, random in localStorage) with the tiered
  `reconstructRootSecret()`. Per-sub-forum derivation and the whole
  join/anon-post pipeline are untouched. The settings "device seed / recovery phrase"
  section collapses into a tier-status readout plus an advanced Tier-C export
  (`src/lib/client/vault.ts` becomes the export).
- **FreedInk (`FreedInk/`):** the per-blog encrypted vault
  (`src/lib/client/vault.ts`) stops being the primary store and becomes the Tier-C
  export. Per-blog identity derives from `R_rp` with the blog id as context. Signup's
  "create/enter your identity vault" step becomes "sign in with Ministry."
- **Discreetly (`Discreetly/apps/web/`):** the single reused identity
  (`src/lib/identity.ts`) is replaced by per-room derivation from `R_rp` (context =
  room id), which also closes the known cross-room-reuse leak. The password vault
  becomes the Tier-C export.
- **Each app's login/callback handler** gains the fragment reader or the
  derivation-hint fetch (Fork 2a) and calls `reconstructRootSecret()`.
- **Each app gains a secret salt env var** (Fork 2c), delivered to its own page.

**Browser (runs inside each app)**

- The WebAuthn PRF `get()` handler, the fragment reader on the callback page, and the
  VOPRF blind/unblind. All client-side; nothing sensitive is sent to any server in
  the clear.

---

## 6. Is this over-built? (real signal, not reassurance)

1. **You may not need Tier B in v1.** Phase 1 of the design already ships A + C.
   Until Tier B exists, magic-link users keep the mandatory vault (Tier C), the same
   friction as today for that minority, no worse. Tier B is by far the most new
   cryptography here: a from-scratch JS VOPRF client, a security-audit gate, a relay
   endpoint, and the id-delivery plumbing. Ship A + C, measure how many real users
   are magic-link-only **and** refuse a passkey, and only then decide if the OPRF is
   worth building. Do not build Tier B speculatively.

2. **Nudge magic-link users toward a passkey and Tier B may never clear the bar.**
   Ministry already supports passkeys as primary. The derivation onboarding is a
   natural place to say "add a passkey so your anonymous identity restores itself."
   Every magic-link user who enrolls becomes Tier A and leaves the Tier-B population.
   It will not hit zero (some stacks lack PRF, some users refuse), but it shrinks the
   case for Tier B, possibly below the build threshold.

3. **Tier C is not really a peer "tier."** It is the backup that either live tier can
   lean on. Calling it a third tier slightly overstructures the model. In practice A
   or B is your live derivation and C is an optional export layered under either. The
   pin only ever chooses between **two** live tiers (A, B); C is a recovery input,
   not something the pin has to reproduce.

4. **The pin is the load-bearing safety, and it is cheap.** One non-secret row per
   (user, app). It matters more to get right than any single primitive, because the
   silent second-identity bug is the worst UX failure in the design and it is
   invisible when it happens. Prioritize the pin and the "refuse to silently
   downgrade" client logic over the OPRF.

---

## 7. Questions for the reviewer

What I most want a Fable-max reviewer to stress-test, in priority order:

1. **The fundamental limit for magic-link users.** Is splitting the secret across
   Ministry (the id) + Signet (the key) + the app (the salt) an acceptable anonymity
   floor for a user who brings no secret of their own, or is "your anonymity rests on
   Ministry and Signet not colluding" a guarantee we should not offer at all, i.e.
   force those users to a Tier-C vault and drop Tier B entirely? This is the core
   policy call and everything about Tier B hangs on it.

2. **Is Tier B worth building in v1?** Stress-test the claim in section 6 that A + C
   plus a passkey nudge is sufficient. Are we about to build audited cryptography for
   a population we can make disappear with an onboarding prompt?

3. **Fork 2b two-hop.** App -> Signet directly (widens Signet's mTLS trust to every
   app) vs app -> Ministry -> Signet (extra hop, Ministry owns the rate-limit, sees
   only blinded values plus the sub). Which trust surface is correct? Is there a leak
   in either I have missed?

4. **Fork 2a leak surface.** Is putting a stable, per-user OPRF input in the browser
   URL fragment (hence browser history) an acceptable leak, or do we need the
   opaque-derivation-id indirection? Does the direct-fetch option have any 2026 path
   that is not fighting the platform?

5. **Tier pinning and its metadata cost.** Is a Ministry-served, non-secret
   per-(user, app) tier hint the right home for the pin, given it hands Ministry new
   linkable metadata ("this sub uses Tier B at Deforum")? Is there a way to pin the
   tier _without_ Ministry learning it (client-stored with a vault fallback), and is
   that worth losing "a new device just works"?

6. **Tier A's own pinning bug.** A user with both an Apple passkey and a Google
   passkey has two PRF outputs. The design pins one enrolled credential per (user,
   app). Does that pin hold when the user is on a device that only has the _other_
   passkey? Does it correctly refuse rather than fork a second identity? This is Tier
   A's version of the silent-second-identity failure and deserves the same scrutiny.

7. **Domain separation.** Confirm the new anon-derivation OPRF domain tag cannot
   collide with, or let one oracle answer for, Signet's existing nullifier and
   pairwise key schedules. A shared key schedule here would be a quiet cross-protocol
   break.

8. **Key handling.** The design's audit gates call for constant-time VOPRF
   blind/unblind and zeroization of the input secret and `R_rp` after use, matching
   the vault module's existing discipline. Confirm the JS client can actually deliver
   both (JavaScript makes both hard: no guaranteed constant time, no guaranteed
   zeroization of garbage-collected buffers), and if it cannot, say what the residual
   exposure is.
