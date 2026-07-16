# Identity secrets: the problem statement

What this is: the requirements for how a user gets and keeps the secret their
zero-knowledge identities are derived from. Written down because the discussion
kept sliding between two different things that are not the same problem.

This document states the problem and the constraints. It does not pick a
solution. Where a question is open, it says so.

## Two separate things that keep getting confused

**Badge identity (the user identity).** The pairwise `sub` Ministry issues to
each relying party over OIDC, and the badge verifiable credentials disclosed
alongside it. Ministry mints these. Cross-app linking here is already solved:
each relying party gets a different `sub` for the same user, so two apps
comparing notes have nothing to join on. See `oidc-privacy.md`.

**Identity secret (the zero-knowledge identity).** The secret behind a Semaphore
or RLN identity commitment at a relying party. Ministry never sees it. The app
never sees it either, only the commitment. This is a completely separate object
from the `sub`, it lives in a different namespace, and nothing about pairwise
subjects protects it.

Everything below is about the second one. Solving the first tells you nothing
about the second.

## What Ministry is

An identity wallet holding badges (verifiable credentials), usable as an OIDC
provider to sign in to other sites. A user's badges must not be linkable between
sites. Some of those sites use Semaphore, RLN, or other zero-knowledge systems
that need an identity secret and publish an identity commitment.

## What an identity secret is, and why it is awkward

An identity secret can be nothing more than a random number the user keeps. The
user publishes a hash of it (the commitment) to the relying party, and that
commitment is tied to their badges as their profile at that app.

The awkwardness is multi-device. A random number generated on the phone is not on
the laptop. There are exactly three ways out:

1. Copy the secret between devices.
2. Derive it from a higher-order seed the user already has on both.
3. Let a user hold several identity commitments, one per device.

**Option 3 is rejected: it breaks RLN.** The rate limit is one message per
identity per epoch, enforced because a second message reuses the nullifier. Three
commitments is three nullifiers, so three times the messages, and the server
cannot cap across them without linking them, which is the anonymity RLN exists to
protect. One identity per user per context is what makes the rate limit work.

**A per-identity seed phrase is rejected on user experience grounds.** A user
should not generate a new secret and save a new backup for every identity they
create. They will lose them, they will mix them up, and it is miserable. This is
not a minor preference; it is the reason the whole design exists.

## The requirements

1. **One secret.** The user has a single secret tied to Ministry. Every identity
   secret they will ever need is derived from it. They back up one thing, once.
2. **Only in plaintext on their own devices.** The secret exists in the clear
   nowhere else.
3. **Neither Ministry nor any relying party ever sees the secret material.**
4. **Deterministic, hierarchical derivation**, so the user can hold many
   identities across many sites without holding many secrets.
5. **It must reach the user's other devices**, without a miserable ceremony.
6. **Recovery or rotation when the user loses the secret.** Loss is the common
   case, far more common than theft, and the design has to survive it.
7. **Smooth signup.** The setup cannot feel like a security ceremony.

## The derivation

Hierarchical, one-way, domain-separated. A child reveals nothing about its
parent or its siblings:

```
root                                                    (user's devices only)
 └─ per_app_secret = HKDF(root, "ministry/v1/rp/" + app_id)
     └─ context     = HKDF(per_app_secret, "room/" + room_id)     e.g. Discreetly
     └─ context     = HKDF(per_app_secret, "blog/" + blog_id)     e.g. FreedInk
```

**Not BIP32.** BIP32 exists for public derivation, deriving child public keys
from an extended public key without the private key. We never need that, because
derivation always happens in a browser that already holds the parent. BIP32 also
carries secp256k1 structure, and Semaphore identities are on a different curve.
HKDF with the path as the domain string gives the same one-way separation with
none of the baggage. Revisit only if public derivation ever becomes a real
requirement.

**Cross-app linking of identity secrets.** Two colluding apps hold
`HKDF(root, "a")` and `HKDF(root, "b")`. Neither can compute the other from what
it has, and there is no shared value to compare, so they cannot link. This holds
as long as no relying party ever receives the root itself. The per-app secret is
delivered to the app's page in the URL fragment; the root is never transmitted.

**Devices do not appear anywhere in the derivation.** Identities come from the
root, so every device the root is on computes the same identity. That is what
makes multi-device work at all, and it is also what keeps one identity per user
per context, which is what RLN needs.

## Decided: how an app gets its branch

**Ministry hands each app its branch of the tree, once, at login. The app derives
everything below it locally, forever, without asking again.**

```
at login, via the existing top-level redirect:
    per_app_secret = HKDF(root, "ministry/v1/rp/discreetly")   -> handed to the app

thereafter, entirely inside the app, no round trip:
    room_secret    = HKDF(per_app_secret, "room/" + room_id)
```

That is the whole point of a hierarchy: holding a node gives you everything under
it. Ministry is involved once per app, not once per identity.

**Why not an iframe.** The natural design (the app embeds a hidden ministry.id
frame and asks it to derive) does not work, because browsers partition storage by
top-level site. An embedded ministry.id frame on discreetly.chat gets a separate,
empty bucket keyed to that pair, not ministry.id's real storage. Chrome ships this
as Storage Partitioning, Safari has done it since Intelligent Tracking Prevention,
Firefox as Total Cookie Protection. Blocking exactly this is the point of the
feature. It is also why the current design uses a top-level redirect and returns
the secret in the URL fragment: the redirect makes ministry.id top-level for a
moment, so it can read its own storage.

**If per-derivation round-trips are ever wanted** (so a compromised app leaks only
the rooms the user actually visited, not its whole branch), the mechanism is a
**popup, not an iframe**. `window.open` creates a top-level context with real
first-party storage, derives, posts the result back to the opener, and closes. A
"join" click is a user gesture, so popup blockers permit it. The Storage Access
API exists for the iframe case but it prompts and Safari restricts it heavily;
Related Website Sets is Chrome-only. Both rejected.

## Decided: how the root reaches a second device

**QR pairing, as the main path, not a fallback.** Sign up on the first device and
back up the one seed. On a second device: sign into Ministry, choose to get the
identity from another device, point the camera at the first device's screen. Once
per device, forever. This is the interaction people already know from linking a
Signal or WhatsApp desktop.

Requirements on it: the QR code must carry the key material that authenticates the
channel, and it needs a proximity check. Without one it is remotely phishable, an
attacker displays a QR from their own session on the real ministry.id origin and a
victim who scans it seals their root to the attacker. Any relay in the middle
carries ciphertext only and must never introduce the two devices to each other,
because whoever vouches for identity can vouch for themselves.

**Passkey PRF stays, as an optimization, never as a dependency.** Where a passkey
supports it, that device wraps its own copy of the root and stops asking, so the
QR step happens once per device instead of once per session. Where it does not,
nothing about the design changes. Build and test the QR and seed paths as though
PRF does not exist, then let PRF skip a step for whoever it works for. See the
support caveats below.

Password manager autofill stays as a bonus for the roughly one third of people who
have one. Typing the seed is the floor when there is no second device.

## Why the alternatives were rejected

To place a secret on a device that has nothing, it must come from one of:

- **Something the user memorizes** (rejected: see the PIN section below).
- **Something a third party syncs for them** (a password manager, a synced
  passkey).
- **Another device they still hold** (QR pairing).

**Passkey PRF is not available enough to depend on.** It would be the ideal
answer: a synced, PRF-capable passkey on every device would make this problem
disappear. That is not the state of the world. There is no published telemetry on
PRF success rates from any vendor. Bitwarden as a passkey provider returns no PRF
output at all. Users on Linux, GrapheneOS, and hardware keys on iOS are exactly
the population this product attracts and exactly the population PRF fails. Treat
PRF as an opportunistic optimization that skips a step when it happens to work,
never as a mechanism the design rests on.

**A memorized PIN cannot work.** A six-digit PIN is about 20 bits. Anyone who can
test guesses locally wins, and no key-stretching closes that gap. The three
systems that made a PIN work (Apple's Cloud Key Vault, WhatsApp's, Signal's SVR)
all needed hardware enforcing the guess limit _against the operator_. Signet
cannot do this: Ministry is root on the host that holds its key, and a rate limit
enforced in software Ministry can redeploy is a policy, not a property.

**Password manager save-and-autofill is unreliable.** Roughly a third of people
use any password manager. The `<form method="dialog">` approach cannot fire a
save prompt in any of the three browser engines. `navigator.credentials.store` is
Chromium-only.

**QR pairing** works but must not be hand-rolled. A relay that introduces the two
devices can introduce one of them to itself, so whoever vouches for identity can
vouch for themselves. The QR code must carry the key material that authenticates
the channel, and any hand-rolled version is remotely phishable unless it includes
a proximity check: an attacker can display a QR from their own session on the
real origin, and a victim who scans it seals their root to the attacker.

## Open: recovery when the root is lost

Losing the root always means new identity secrets. There is no scheme that
recovers a secret nobody else holds.

What survives loss: the **Ministry account**. Email, badges, and everything
Ministry stores are untouched. Each relying party knows the user by their
pairwise `sub`, not by their identity commitment, so an app can swap a user's old
leaf for a new one and keep their membership and badges.

What does not survive: the ability to prove old posts were theirs. For ephemeral
rooms that costs nothing. For authorship it is the real loss.

So recovery is not "recover the seed," it is "re-key into every app you are in."
Whether that is sufficient is a product decision per app, not a cryptography
decision.

## What Signet cannot do here

Signet is an oblivious pseudorandom function service Ministry runs. An oblivious
function buys exactly one thing: a second party who must participate and who does
not learn what was asked. **Ministry operates Signet, so it is not a second
party.** Its key is an environment variable on a box Ministry is root on.

An oblivious function becomes worth building the moment its key is held by
someone who is not Ministry. Then Ministry genuinely cannot derive anyone's
identity alone, regardless of what it ships. That is a "find an independent
operator" problem, not a cryptography problem. It is tracked as the MPC idea in
`TODO.md`.

It would also cost: derivation becomes a network call, so an outage means nobody
can derive an identity or post, and the key becomes as immutable as the root,
since rotating it forks every user in every app.

## The honest security claim

Ministry serves the JavaScript that touches the root. A Ministry that shipped a
seed generator deriving from a Ministry-held key instead of from randomness would
recompute every user's secret forever, with nothing observable in the database
and nothing detectable by inspecting the output. This is not a proposal or a
plan; it is the reason the claim has a ceiling.

So do not write "Ministry can never compute your identity." Write what is true:
Ministry holds nothing that lets it compute your identity. Closing the remaining
gap is a code-delivery problem (reproducible builds, a separate origin, a signed
binary), not a cryptographic one, and it is a separate project.

## The per-relying-party mix secret should be dropped

`device_seed = HKDF(per_app_secret, salt = rp_mix_secret)`, where `rp_mix_secret`
is one value per app, delivered to every signed-in user's page (spec 9.2). The
stated intent, from the 2026-07-09 decision, is that each app mixes in a secret
Ministry does not hold, so a Ministry compromise cannot reproduce that app's
identities.

**It does not do that.** Ministry can create an account at the app like anyone
else and read the mix secret out of its own page. It is one global value, shipped
to every signed-in browser.

**And there is no attacker left for it to stop.** Ministry's server never holds
the root; the root lives only on the user's devices. So a Ministry breach yields
no roots, and there is nothing for the mix to protect. The only party who could
use it is someone who already stole a user's seed, and they can get the mix by
signing up.

Meanwhile it costs a lot. It is identity-determining, so it can never be rotated,
and losing it silently forks every user in that app: every commitment, membership,
and nullifier orphans, every prior post becomes unownable, and no error fires
anywhere (spec invariant I9). That is the worst operational hazard in the design,
carried for no benefit.

**Recommendation: delete it, and delete invariant I9 with it.** `device_seed`
becomes `per_app_secret` directly.

If it is kept for defense in depth, it must at least become per-user: derived on
the app's server from a master secret that never ships, keyed by that user's
pairwise `sub`, so Ministry signing up learns only its own. Note that this makes
the `sub` identity-determining, which promotes `SubjectOverride` (it preserves a
donor's `sub` per app through an account merge) from a continuity mechanism to a
load-bearing identity one.

## The membership anchor: the pairwise `sub`, not the commitment

Each relying party knows a user by their OIDC pairwise `sub` (a per-RP subject
identifier Ministry issues, a different value at each app, carried in the
id_token). Every app derives a per-context anchor by hashing that `sub` with the
context, and stores the user's identity commitment against that anchor. Verified:

- deforum: `poseidon2(toField(sub), toField(subforumId))` per sub-forum.
- Discreetly: `joinNullifier = poseidon2([toField(sub), rlnIdentifier])` per room.
- FreedInk: the membership row keyed by the user id derived from `sub`.

This is a distinct value from the _badge disclosure_ nullifier (the unlinkability
value on the credential side); the membership key is the `sub`, not the badge
nullifier.

Because the anchor is the `sub` and not the commitment, re-key needs nothing from
the user but their login: the app resolves the row from the `sub`, sees the stored
commitment is not the freshly derived one, and replaces it in place.

## Decisions locked, 2026-07-16

The full plan, the per-repo change lists, and the security audit are in the
planning report (scratchpad `identity-plan-report.html`). These are the decisions
the product owner made against it.

1. **QR pairing ships on the web** (O-7). Accept the mitigation stack: the QR
   payload is not a URL, the relay is blind, and the server enforces that the
   scanning device and the displaying device are the same account. That account
   check is load-bearing, not defense in depth, and it blocks the remote phish.
   Residual: an attacker already holding a live session as the user could escalate
   to permanent root theft by self-pairing. Do not ship claiming the confirmation
   code stops an attack; it does not.
2. **The root is for identity only** (O-3). It is never the account-recovery
   credential. Account recovery keeps BOTH existing paths, which cover different
   failure modes and are not redundant: threshold badge re-proving (nothing to
   back up, but requires live-re-provable badges clearing the weight threshold) as
   the primary path, and Argon2id recovery codes (a saved secret that works with no
   badges and no surviving external accounts) as the universal fallback.
   **`RecoveryCode` is NOT deleted.** Verification on 2026-07-16 found the two are
   not redundant, and the codebase itself treats recovery codes as the universal
   path. `RecoveryProvider` is shared ticket infrastructure that badge recovery also
   rides, so it stays regardless. The root stays identity-only; the settings
   consolidation groups both account-recovery paths under one section, kept separate
   from the private-identity page.

   **Required fix, a real bug independent of this decision:** badge recovery is
   currently DEADLOCKED. `canAddPasskey` (`credential-actions.ts:569`) refuses a
   recovered AAL1 session the passkey it needs to climb to AAL2 whenever the account
   already has passkey rows, which it always does after device loss (losing a device
   does not delete the `Authenticator` row). So a user re-proves their badges, gets
   the recovered session, and is then stuck. Fix: let `session.recovered === true`
   past that gate; the new passkey lands quarantined for 72 hours as intended. This
   matches the function's own comment and DESIGNDECISIONS #9, which both already say
   a recovered session should be allowed. Add a test for "recovered AAL1 session,
   existing passkey rows present, enrolls a quarantined climb passkey."

3. **No server-side root check value** (O-4). Ministry holds nothing derived from
   the root. The epoch carried in the backup string (the W1 fix) catches a stale
   key loudly with no server artifact.
4. **No custody choice in onboarding** (M-1). Everyone backs up the one root; PRF
   silently wraps a copy where it works. The IndexedDB root store fixes the
   re-prompt the custody choice originally worked around.
5. **Backup is the 28-character base58check string only** (O-2). The 12-word BIP-39
   codec and the `@scure/bip39` dependency are deleted on both sides. Fixed length,
   version byte plus checksum, password-manager friendly, does not look like a
   crypto seed.
6. **Both app password vaults are deleted** (O-1). The branch arrives at every
   login and the root is the backup, so a per-app password guards a re-derivable
   value. Every password prompt in FreedInk and Discreetly disappears.
7. **Discreetly `maxDevices` is deleted** (D-2), one leaf per user hardcoded. It
   was a rate-limit multiplier in the clear.
8. **deforum collapses to one leaf per membership** (D-1). `deviceId` leaves the
   derivation and the schema; `revokeDevice` (which could not actually revoke,
   since every device derived an identical commitment) is deleted.
9. **Discreetly trapdoor and nullifier derive flat** (K-1), two direct derivations
   from the branch with the room id in each info string
   (`ministry/v1/ctx/room/<roomId>/trapdoor` and `.../nullifier`), not a nested
   room-secret level. The golden vectors are frozen for this shape.
10. **FreedInk consumes the identity package from the npm registry** (K-2), not the
    vendored tarball, matching how it already takes the other Ministry packages.
11. **Re-key is global** (O-6). Losing the root re-keys every app; the epoch bumps
    once and each app re-keys on the user's next interaction. The derivation path
    stays per-app-capable (the epoch is per-app in the info string) so a per-app UI
    can be added later with no forking migration, but there is no per-app UI now.

### Being fixed, not decided (from the audit)

- **Leaf replacement is gated on the signed epoch strictly advancing**, never on a
  bare commitment mismatch (C1, and Discreetly's D-3). Mismatch is the symptom; the
  id_token epoch is the authority. This stops an attacker looping replacements to
  defeat RLN, and stops a stale device clobbering the new commitment with an old
  one (W1). The app stores the epoch it last keyed at and replaces only when the
  token epoch is greater.
- **The QR account check is made load-bearing and tested** (C2); the pairing `aad`
  `userId` is derived from each side's own authenticated session, never from the
  relay response.
- **The middleware merges the Content-Security-Policy into the auth branch**, never
  returns the pass-through before the auth redirect (C3, which as written would
  have made every gated route public once the matcher widened to the origin).
- **FreedInk's and deforum's `safeNext` strip the fragment** (C4), closing the
  one-link silent identity fork that is live in both today.
- **The passkey relying-party ID is pinned** to `ministry.id` in production and the
  `AUTH_URL` hostname for localhost, so it cannot vary per request off
  `x-forwarded-host`.
- **The docs move off `docs.ministry.id`** to the default GitHub Pages URL, out of
  the passkey trust boundary.
- **The `canAddPasskey` recovery deadlock is fixed** (`credential-actions.ts:569`):
  a recovered AAL1 session may enroll its climb-to-AAL2 passkey even when passkey
  rows already exist. Without this, threshold badge recovery cannot complete for
  anyone who ever had a passkey, which is nearly everyone who has recovery to do.
  This is the one item that came from the recovery verification, not the audit.
