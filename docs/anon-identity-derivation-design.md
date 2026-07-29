# Anonymous RP identity derivation from Ministry credentials

Status: design proposal for review. Domain-floor (crypto/privacy). No code yet.
Author-intent: replace every relying party's per-app client-side seed/vault with a
secret derived **client-side** from the user's Ministry credentials, so the user
manages one identity (Ministry) and never backs up a per-app seed. Deep-solver
design; must pass an `auditor` review before any build.

Prior decision this builds on (memory, 2026-07-09): cross-app anon-identity
recovery is a **hybrid** - derive-from-Ministry by default plus an opt-in device
vault - and each RP mixes in its own server-side secret so a Ministry breach alone
cannot deanonymize everyone. The open question was _where the derivation runs_.
Tyler has answered: **client-side**. This doc turns that answer into a concrete
construction, scores the primitive options, and recommends one.

Ground truth this design was written against (all verified in-repo):

- `@ministryofmany/identity` (`minister-client/packages/identity`) already derives a
  per-context Semaphore identity from a 32-byte seed via
  `HKDF-SHA256(seed, salt="minister/identity/hkdf/v1", info="minister/identity/v1:"+context)`
  and already ships the encrypted vault (PBKDF2-600k + AES-GCM) and 24-word BIP-39
  backup. Today the seed is **random per app** (`generateDeviceSeed`) and stored in
  browser `localStorage`. The whole downstream identity/membership/proof stack
  consumes that seed and is untouched by this design. We only change _where the seed
  comes from_.
- Deforum: v4 device seed -> per-sub-forum identity; seed in `localStorage`; backup
  = BIP-39 / vault (`deforum-space/src/lib/client/{device,vault}.ts`).
- FreedInk: per-blog v4 identity in an encrypted vault blob
  (`FreedInk/src/lib/client/vault.ts`, PBKDF2-600k + AES-GCM).
- Discreetly: a **single** v3/RLN identity reused across rooms
  (`Discreetly/apps/web/src/lib/identity.ts`), password-encrypted in `localStorage`.
  Cross-room reuse is a known leak the per-context derivation already fixes.
- Signet already runs a **production RFC 9497 VOPRF**, ciphersuite
  `ristretto255-SHA512`, mode 0x01, with DLEQ proofs (`Signet/src/prf.rs`), keyed
  from a master seed held under **separate custody from Minister's DB** (sealed in
  Signet, mTLS-gated). This is the single most important asset for the fallback
  path below.
- Minister auth: **passkeys (WebAuthn) primary, email magic-link fallback, no
  passwords** (`Minister/CLAUDE.md`). So a nontrivial minority of accounts have _no_
  authenticator-held secret at all.
- OIDC token exchange is **server-side** in every RP (Auth.js / `@minister/client`
  `exchangeCode` with `client_secret`). The id_token lands on the **RP server**.
  Anything Ministry puts in the id_token is visible to the RP server. This kills the
  naive "deliver the secret in the id_token" idea (see option (b)).

---

## 1. Problem, goals, threat model

### 1.1 Problem

Each RP forces the user to manage a separate, unrecoverable client-side secret.
Lose the Deforum device seed -> permanent lockout from every sub-forum you joined.
Same for FreedInk (per blog) and Discreetly (per identity). The user must back up a
24-word phrase or an encrypted vault **per app**. That is the entire friction we are
removing. The user should manage only their Ministry identity; logging into Ministry
on any device should transparently reconstruct every RP secret.

### 1.2 Goals

1. The per-RP root secret `R_rp` is derived **client-side** from material the user
   reproduces by logging into Ministry. No per-app backup in the default path.
2. A brand-new device with only a Ministry login reproduces the identical `R_rp`
   (hence identical commitments and nullifiers) for every RP the user uses.
3. **The load-bearing invariant:** neither Ministry nor an RP server can compute the
   user's per-context Semaphore **secret**, and therefore cannot link a user's
   Ministry identity to their anonymous _authoring_ identity (their nullifier-based
   posts/votes/messages).
4. **Blast-radius containment:** a breach of Ministry's database _alone_ must not let
   the attacker recompute `R_rp` for the whole population. Each RP mixes in a secret
   Ministry does not hold.
5. Clean bones. Zero production users -> no migration, no backward-compat. Design the
   system we would want to have built.
6. Preserve an **opt-in device-vault escape hatch** (the hybrid decision) for users
   who cannot or will not lean on Ministry.

### 1.3 Non-goals

- Hiding the `sub <-> commitment` link that exists **at join**. See 1.4: gated
  membership inherently reveals to the RP server which commitment a logged-in user
  registered. Fixing that needs anonymous credentials at join (blind-signed
  membership), a strictly larger project. Out of scope here; called out honestly.
- Anonymity _within_ Ministry (Ministry always knows who its own user is).
- Replacing the ZK membership/nullifier machinery. We change seed provenance only.
- Password-based Ministry auth (Ministry has none; do not add one for this).

### 1.4 The precise linkage surface (read this before the threat table)

This is the part most easily gotten wrong. In all three RPs, membership is **gated**:
to join, you authenticate to the RP via Ministry OIDC, and you register a Semaphore
commitment as a Merkle leaf. Concretely, Deforum's `join()` stores the leaf
(`deforum_membership_leaves.identityCommitment`) against a membership row that
carries `user_id` and the pairwise-`sub`-derived nullifier. **So the RP server
already knows `sub <-> commitment` for every device leaf.** That linkage is not
created by this design and cannot be removed by it.

What actually stays anonymous is the **authoring tier**: an anonymous post proves
membership in ZK _without revealing which leaf_, and reveals only a per-content
nullifier. The RP server cannot tie an anonymous post to a specific commitment (hence
to a `sub`) as long as it cannot reconstruct the user's per-context **secret** (the
Semaphore private key). If it could reconstruct that secret, it could recompute the
user's nullifier for every content id and de-anonymize every post.

Therefore the derivation's real job is narrow and sharp: **keep the per-context
secret computable only inside the user's browser.** Everything below is judged
against that.

### 1.5 Threat model: what each party can and cannot learn

Let `R_rp` be the user's per-RP root secret, `sk_ctx = f(R_rp, context)` the
per-context Semaphore private key, `C_ctx` its public commitment (a Merkle leaf),
`n = g(sk_ctx, content)` an authoring nullifier.

| Party                               | Learns today (unchanged)                                                                                             | Must NOT learn (invariant)                                                                           | How this design enforces it                                                                                                                                                                                                                                                                                              |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Ministry (IdP)**                  | Who the user is; that they logged into RP X at time T; the pairwise `sub` it minted for X.                           | `R_rp`, `sk_ctx`, `C_ctx`, `n`. i.e. cannot derive or recognize the user's anon authoring at any RP. | Ministry never receives `R_rp` or any factor that alone yields it. In the strong path it holds _nothing_ that derives `R_rp`; in the fallback path it holds one factor of two, and the RP holds the other.                                                                                                               |
| **RP server**                       | The user's pairwise `sub`; `C_ctx` for each leaf the user _registers at join_; every anon nullifier `n` it verifies. | `R_rp`, `sk_ctx`. i.e. cannot go from a stored anon post back to the `sub` that authored it.         | `R_rp` is computed only in the browser. The RP server sees, at most, blinded protocol messages and its own public/secret salt, never the Ministry-side factor and never `sk_ctx`.                                                                                                                                        |
| **Network attacker**                | Ciphertext + TLS metadata.                                                                                           | Any secret factor, `R_rp`, `sk_ctx`.                                                                 | All factor exchanges are over TLS; the Ministry factor is blinded (OPRF) or authenticator-local (PRF); nothing sensitive is sent in the clear.                                                                                                                                                                           |
| **Malicious / curious RP operator** | Same as RP server, plus active tampering.                                                                            | `sk_ctx`. Also must not be able to _swap in a key that tags users_ in the RP-side blind step.        | RP-side blind OPRF (if used) is DLEQ-proven against a pinned public key; the client verifies the proof before accepting the output, so a per-user distinguished key is detected.                                                                                                                                         |
| **Ministry DB breach (alone)**      | Ministry's entire DB, incl. userIds, pairwise secret, OIDC state.                                                    | Enough to recompute `R_rp` for the population.                                                       | Strong path: nothing (Ministry holds no derivation factor). Fallback path: the OPRF key lives in **Signet**, not Minister's DB, under separate custody; and each RP's secret salt is not in Minister's DB. So a Minister-DB breach alone is insufficient; it must be combined with a Signet breach _and_ each RP's salt. |

The one honest asterisk: for a user whose _only_ reproducible credential is their
Ministry login (magic-link, no passkey, no wallet), no amount of cryptography can
make `R_rp` both "reproducible from just a Ministry login" and "unknowable to
Ministry+its key custodian." Such a user brings no secret of their own, so the IdP
side is necessarily _a_ factor. We contain that with the RP salt and the OPRF key
custody split, and we offer them the vault. This is a fundamental limit, not a defect
in any particular primitive. It is exactly why the hybrid keeps the vault.

---

## 2. What client-side material is available, and the primitive options

### 2.1 Available reproducible secret material, by user population

| Source                                | Reproducible on a fresh device by...                                                        | Ministry can see it?           | Coverage                                                           |
| ------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------ | ------------------------------------------------------------------ |
| WebAuthn PRF off a **synced passkey** | doing a passkey assertion (the passkey syncs via iCloud Keychain / Google Password Manager) | No (stays in authenticator)    | passkey users on PRF-capable stacks (majority and rising, not all) |
| A **Ministry-served** per-user factor | logging into Ministry (Ministry re-delivers / re-evaluates it)                              | Yes (it is the one serving it) | everyone, incl. magic-link                                         |
| A **wallet** deterministic signature  | signing a fixed message with the same wallet                                                | No                             | wallet-holding users only                                          |
| An **encrypted vault** (status quo)   | entering a password + having the vault blob                                                 | No                             | anyone who kept the backup                                         |

No single source covers everyone with strong properties. The design is therefore a
**tiered composition**, and each tier maps onto one of the primitives below. The four
primitives are scored on their own merits first; the recommended composition is 3.

The common shape for all of them:

```
R_rp = HKDF-SHA256(
         ikm  = S_user,                       // the Ministry-side / authenticator-side factor
         salt = RP_salt,                      // the RP's own contribution (2.6)
         info = "minister/anon/v1:" || rp_id || ":" || context,
         L    = 32 )
```

`R_rp` then feeds the **existing** `@ministryofmany/identity` per-context HKDF and the
app's identity constructor unchanged. The only thing the options below disagree on is
**how the browser obtains `S_user` reproducibly without the RP server or Ministry
being able to derive it too.**

### 2.2 Option (a): WebAuthn PRF off the user's passkey

`S_user = PRF(passkey, salt="minister/anon/prf/v1")`. The WebAuthn PRF extension (a
standardized surface over CTAP2 `hmac-secret`) returns a deterministic 32-byte value
for a given (credential, salt). It is evaluated in the browser during a passkey
assertion and never leaves the authenticator boundary.

- **Fresh device:** the passkey syncs within its ecosystem (Google Password Manager,
  iCloud Keychain), so the same credential + same salt -> same PRF output ->
  same `R_rp`. Verified 2026 state: synced-passkey PRF is deterministic across the
  user's devices in one ecosystem ("100% PRF-on-create success" on synced providers;
  Android GPM most robust; Apple 18.4+/macOS 15+ supported).
- **RP salt without linkage:** trivially. The RP salt is an HKDF salt applied in the
  browser; the RP server never participates in the PRF at all, so it cannot learn
  `S_user` or `R_rp`. Cleanest possible mixing.
- **Ministry breach:** **zero blast radius.** Ministry holds no PRF factor; the secret
  is in the authenticator. This is the strongest breach posture of any option.

Costs and caveats (all verified, load-bearing):

- **Coverage gaps.** Magic-link-only accounts have no passkey -> option (a) cannot
  serve them. It can never be the _sole_ path.
- **Browser/ecosystem fragmentation.** Firefox on Android: none. Windows Hello before
  the Feb-2026 25H2 update: no `hmac-secret`. Roaming security keys: PRF only if the
  flag was set at creation, and current Safari/WebKit has open CTAP2-key PRF interop
  bugs. Create-time PRF is inconsistent; a second `get()` is often required.
- **Cross-ecosystem is not stable.** A user with an Apple passkey _and_ a separate
  Google passkey has two credentials -> two PRF outputs -> two different `R_rp`. Same
  human, different anon identity depending on which device/ecosystem they are on. The
  composition must pin one enrolled credential per (user, RP) and re-use _that_ one.
- **Implementability:** requires raw `navigator.credentials.get({publicKey:{extensions:{prf:{eval:{first:salt}}}}})`.
  The Auth.js Passkey provider does not expose PRF; this is a separate WebAuthn call
  the SDK owns, decoupled from the login ceremony.

Score: **4 / 5.** Best-in-class security and the truest fit for "manage only your
Ministry identity, nothing to back up" - _when it works_. Docked one star for coverage
gaps and 2026-era browser fragmentation that forbid it from being universal. It is the
strategic core of the recommendation, not a standalone answer.

### 2.3 Option (b): Ministry-issued client-held long-term secret over OIDC

Ministry generates a random 32-byte `S_user` per user, stores it, and delivers it to
the client; the client derives `R_rp = HKDF(S_user, RP_salt, info)`.

- **Fresh device:** Ministry re-delivers `S_user` on login. Works for everyone,
  including magic-link. Best coverage of any option.
- **RP salt without linkage:** the RP salt is applied client-side, so the RP server
  need not participate. **But the delivery of `S_user` is the trap:** the id_token is
  exchanged **server-side**, so if `S_user` rides in the id_token/userinfo, the **RP
  server sees it**, and RP-server + RP-salt = `R_rp`. Invariant broken. `S_user` must
  reach the _browser only_, never the RP server: via a URL-fragment front-channel on
  the login redirect (fragments are not sent to servers), or a direct
  browser->Ministry authenticated fetch (third-party-cookie fragile under Safari ITP /
  Chrome). This delivery constraint is the option's defining weakness.
- **Ministry breach:** **whole population.** Ministry stores `S_user` in plaintext (or
  reversibly); a DB breach yields every user's `S_user`, and with each RP's salt,
  every `R_rp`. The RP salt is the _only_ thing standing between a Ministry breach and
  total de-anonymization.

Score: **2 / 5** standalone. It is the simplest thing that could possibly work and the
only one with universal coverage, but it stores the crown jewels at the IdP and has a
delivery hazard that silently breaks the invariant if implemented naively. It earns
its place _only_ as a fallback, and even then option (c) dominates it (same coverage,
no plaintext secret at rest, splittable key custody, rate-limiting). Do not ship (b)
as the fallback if (c) is available.

### 2.4 Option (c): client <-> Ministry OPRF (Signet blindly evaluates)

The browser holds an input `x`, blinds it, and asks the Ministry-side OPRF (hosted in
**Signet**, which already implements exactly this) to evaluate. Signet returns the
blinded evaluation plus a DLEQ proof; the browser unblinds and verifies:
`S_user = OPRF_{k}(x)`, where `k` is Signet's key. Signet sees neither `x` nor
`S_user`; it sees only a blinded ristretto255 element.

- **Fresh device:** re-run the OPRF with the same input `x` -> same `S_user`.
  Requires `x` to be reproducible on the new device. That is the crux (below).
- **RP salt without linkage:** two clean ways.
  1. RP-salt applied client-side as the HKDF salt (as in (a)/(b)); the RP server never
     touches the OPRF.
  2. **Relay the OPRF through the RP server.** The browser blinds `x`, hands the
     _blinded element_ to the RP server (same-origin, with the RP session), the RP
     server forwards it server-to-server to Signet, and passes the blinded evaluation
     - DLEQ back. The RP server cannot unblind (no blind factor) and cannot see `x` or
       `S_user`. This **dodges the third-party-cookie problem** that dogs (b), reusing
       the existing RP<->Ministry server channel, while leaking nothing usable to the RP.
       This is a genuinely elegant fit.
- **Ministry breach:** **the key `k` is in Signet, not Minister's DB, under separate
  custody (sealed, mTLS).** A Minister-DB breach alone cannot evaluate the OPRF. To
  recompute `S_user` an attacker needs Signet's key _and_ the input `x`. Materially
  better blast radius than (b) even before the RP salt.

The crux is what `x` is, and it decides the _residual_ blast radius:

- If `x = userId` (Ministry knows it; the RP server does **not** - it only holds the
  pairwise `sub`): then Minister-breach gives `x` but not `k`; Signet-breach gives `k`
  but not `x`; neither alone recomputes `S_user`. **Minister + Signet** together do.
  Coverage: universal (works for magic-link). The browser must obtain `userId` to blind
  it - deliver it front-channel to the browser (fragment) so the RP server never sees
  it; if the RP server learned `userId` it could blind it and query the OPRF itself.
- If `x = PRF_output` (option (a) available): then `S_user` needs the authenticator
  _and_ Signet - but if PRF is available you are already in the strong tier and do not
  need the OPRF for secrecy (only for rate-limiting/revocation).
- If `x = vault_secret`: that is the escape-hatch tier (2.5), not a Ministry-recovery
  path.

Extra properties the others lack: the OPRF is an **online, rate-limitable,
revocable** operation. Ministry can throttle evaluations per account and refuse them
for a revoked session, so a stolen static factor cannot be turned into `S_user`
offline. The **DLEQ proof** stops a malicious Ministry/Signet from using a per-user
distinguished key to tag users; the client rejects an evaluation that does not verify
against the pinned public key.

Costs: needs a **VOPRF client in JS** (blind/finalize for ristretto255-SHA512 -
Signet's server side and RFC test vectors already exist, `@ministryofmany/blind-token`
is blind-**RSA** so this is new but small and well-specified), a relay endpoint, and
`x`-delivery plumbing for the universal case.

Score: **4 / 5.** With Signet already in production and its key under separate custody,
this is the strongest _universal_ path: it removes the plaintext-secret-at-rest of
(b), splits the breach across two custodians, adds rate-limiting and DLEQ integrity,
and the relay trick solves delivery cleanly. Docked one star because for the
magic-link population it still cannot beat the fundamental limit (Minister+Signet
together recover it), and it carries the most new client crypto of the four.

### 2.5 Option (d): deterministic signature over a fixed message (passkey / wallet)

`S_user = HKDF(Sign_{sk}(fixed_message))`.

- **Passkey variant is not viable.** WebAuthn assertion signatures are over
  `authenticatorData || clientDataHash`, and `authenticatorData` includes a signature
  counter, so the signed message and the signature change every call. Not reproducible.
  Use the PRF extension (option a), not the signature.
- **Wallet variant is viable but niche.** An EIP-191 `personal_sign` over a fixed
  message is reproducible **iff** the wallet signs deterministically (RFC 6979).
  MetaMask and Ledger do; some mobile/hardware wallets randomize `k` or add entropy,
  which breaks determinism silently. Mitigation: sign twice at enrollment and compare;
  if not byte-identical, refuse this factor and fall back to the vault.
  - **Fresh device:** any device with the same wallet reproduces the signature.
  - **RP salt / Ministry breach:** identical posture to (a): Ministry never sees
    `sk`, so **zero Ministry blast radius**; RP salt mixed client-side.
- **But it is orthogonal to the goal.** Tyler's frame is "manage only your _Ministry_
  identity." A wallet is a _second_ thing to manage, and Minister does not currently
  do SIWE/wallet auth, so a wallet factor is not tied to the Ministry login at all.

Score: **3 / 5.** Cryptographically as clean as (a) for the wallet-holding subset, and
a fine _optional_ factor for wallet-native users, but the determinism footgun plus the
fact that it reintroduces a non-Ministry thing to manage keep it off the default path.
Offer it; do not build the recovery story on it.

### 2.6 Sub-problem: mixing the RP's secret without the RP server learning linkage

The hybrid decision requires each RP to contribute a secret Ministry does not hold.
Three ways, scored:

- **(i) Public per-RP salt** shipped in the RP's client bundle. Domain-separates RPs,
  costs nothing, but is _public_ - Ministry can fetch the bundle - so it gives
  essentially **no** breach separation from Ministry. **2 / 5.** Use only as the floor.
- **(ii) Secret per-RP salt env var, delivered to the browser, mixed client-side as
  the HKDF salt.** The RP server holds a high-entropy env secret and hands it to its
  own page (it already trusts that browser with the session); the browser uses it as
  the HKDF salt. Ministry never receives it -> Minister-breach-alone cannot recompute
  `R_rp`. The RP server has the salt but not `S_user`, so it cannot compute `R_rp`
  either. Degrades gracefully to (i) if the salt ever leaks. Near-zero new infra.
  **4 / 5.** Recommended default RP factor.
- **(iii) RP-side blind OPRF.** The RP runs its own OPRF with a key that never leaves
  the RP server, even to the browser; the client blinds, the RP evaluates, DLEQ-proves,
  the client unblinds and mixes. Strongest (the RP secret never reaches the browser,
  so a malicious end-user cannot exfiltrate it) and rate-limitable, but it is a whole
  OPRF service and key-management burden **per RP**. **3 / 5.** Reserve as a
  high-assurance upgrade for an RP that wants it; not the default.

---

## 3. Recommendation: a tiered composition

Do not pick one primitive. Compose them into a client-side derivation with a stable,
per-(user, RP) **tier** that degrades by what the user can reproduce. The client picks
the highest tier it can satisfy at _enrollment_, Ministry records a non-sensitive
`derivation_tier` hint (so a fresh device reproduces the _same_ tier, which is
essential: a different tier means a different `R_rp`), and the same HKDF and app
identity constructor run underneath every tier.

```
R_rp = HKDF-SHA256(ikm = S_user, salt = RP_secret_salt, info = "minister/anon/v1:"+rp_id+":"+context)
```

- **Tier A - WebAuthn PRF (option a). The default for passkey users.**
  `S_user = PRF(passkey, "minister/anon/prf/v1")`. Fully client-side; Ministry holds
  nothing; cross-device via passkey sync. Ministry-breach blast radius: **zero**.
- **Tier B - Signet OPRF (option c), universal fallback.** For magic-link / no-PRF
  users. `S_user = OPRF_{k_signet}(userId)`, relayed through the RP server (2.4 path
  2), DLEQ-verified, rate-limited. Blast radius: needs **Minister DB + Signet + the RP
  salt**, three custodians. Strictly better than storing a served secret (option b),
  which we therefore do **not** build.
- **Tier C - encrypted device vault (status quo), opt-in escape hatch.** The existing
  `@ministryofmany/identity` PBKDF2+AES-GCM vault and BIP-39 backup, applied to
  `S_user`. Needed precisely for: non-syncing roaming security keys, PRF-unsupported
  stacks, users who want zero IdP dependence, and belt-and-suspenders backup of a Tier
  A/B secret. This is the hybrid's opt-in device vault, kept verbatim.
- **RP factor:** the **secret per-RP salt** (2.6-ii) everywhere; RP-side blind OPRF
  (2.6-iii) as an opt-in upgrade.
- **Wallet (option d):** offered as an _alternate_ Tier-A factor for wallet-native
  users, with the sign-twice determinism check, not the default.

### Why this and not a single primitive

PRF alone strands magic-link users and is browser-fragmented in 2026. A served
secret alone puts every secret at the IdP. The OPRF alone still cannot beat the
fundamental limit for credential-less users and carries the most new crypto. The
composition gives the **majority** (passkey users) the strongest possible posture
(zero Ministry blast radius, nothing to back up), gives **everyone else** a fallback
that is genuinely better than the status quo and splits the breach across three
custodians, and keeps the vault for the tails - while every tier feeds the same,
already-built HKDF and identity stack. It leans on infrastructure that already
exists (Signet's VOPRF, the identity package's HKDF/vault) instead of inventing a new
trust root. That is the "good bones" answer.

---

## 4. What replaces the per-app seed in each RP

The seam is narrow: replace "load-or-generate a random device seed" with
"reconstruct `R_rp` via the tiered derivation." Everything downstream (per-context
HKDF, commitment, membership, proofs, nullifiers) is unchanged. Discreetly's v3/RLN
constructor needs a small `R_rp -> (trapdoor, nullifier)` expand added alongside the
existing v4 `R_rp -> privateKey` one; both live behind the identity package.

- **Deforum.** `loadOrCreateDeviceSeed()` (browser `localStorage`, random) becomes
  `reconstructRootSecret()` (tiered). Per-sub-forum derivation and the whole
  join/anon-post pipeline are untouched. Settings "Device seed / recovery phrase"
  section collapses: no more mandatory 24-word backup. It becomes "Your anon identity
  is tied to your Ministry account" + a **derivation status** readout (Tier A passkey
  / Tier B Ministry-recovery) + an optional "Export an encrypted backup (advanced)"
  that is the Tier-C vault. The per-device manager (list/revoke leaves) stays as-is.
- **FreedInk.** The per-blog encrypted vault
  (`{idc, public_key, ciphertext, salt, ...}`) stops being the _primary_ store and
  becomes the Tier-C export. Per-blog identity derives from `R_rp` with the blog id as
  context. Signup's "create/enter your identity vault" step becomes "sign in with
  Ministry"; the vault UI moves under an advanced/backup panel.
- **Discreetly.** The single reused identity is **replaced** by per-room derivation
  from `R_rp` (context = room id), which also closes the known cross-room-reuse leak
  for free. The password-vault becomes the Tier-C export. Its settings identity panel
  becomes the same "tied to Ministry + optional encrypted backup" shape.

Common settings-page shape after this change: a one-line derivation-tier status, a
"this reconstructs automatically when you sign into Ministry" reassurance, and a
single **advanced** disclosure holding the Tier-C encrypted-backup export/restore. The
mandatory, scary "write down these 24 words or lose everything" flow is gone from the
default path for all three.

---

## 5. Phased build plan

Sequenced so each phase is independently shippable and testable, strong path first.

**Phase 0 - derivation contract + Tier C rename (SDK).** In `@ministryofmany/identity`:
define `S_user`/`R_rp`, add the `deriveRootSecret({ factor, rpSalt, rpId })` combiner
and the v3/RLN `R_rp -> (trapdoor, nullifier)` expand, and re-expose the existing
vault as the Tier-C surface. Golden vectors for every derivation. No app changes yet.

**Phase 1 - Tier A (PRF) end to end.** SDK: a `webauthn-prf` module doing the raw
`get()` PRF assertion, capability detection, and the enrolled-credential pin. Minister:
store the `derivation_tier` + enrolled credential id hint and serve it post-login.
One RP (Deforum) switches its seed load to the tiered path with Tier A + Tier C only
(no Tier B yet). Ship, dogfood, measure PRF coverage in the wild.

**Phase 2 - Tier B (Signet OPRF).** Signet: expose the client-blinded VOPRF for the
anon-derivation input under a new domain tag (reuse `src/prf.rs`, distinct `info` from
the nullifier keypair so the two never share a key schedule). SDK: a ristretto255
VOPRF **client** (blind/finalize + DLEQ verify against a pinned pkS), plus the
RP-server relay client. Minister/RP: the relay endpoint (browser -> RP server ->
Signet -> back), rate-limited per pairwise `sub`. RP: `userId` front-channel delivery
to the browser. Turn on Tier B for the magic-link population.

**Phase 3 - roll out to FreedInk + Discreetly**, including Discreetly's per-room
migration off the single reused identity, and the RP-side blind-OPRF (2.6-iii) as an
opt-in for any RP that wants it.

**Cross-cutting:** the secret per-RP salt env var lands with each RP's phase; the
`derivation_tier` pin and its "same tier on every device" invariant are enforced from
Phase 1.

---

## 6. Security / audit gates (must pass before each phase ships)

1. **`auditor` (opus xhigh) review of this design** before any code. Domain-floor.
2. **Invariant test, adversarial:** construct an RP server that logs everything it
   sees (id_token, relay traffic, salt) and prove it cannot compute `sk_ctx` or link a
   sampled anon post to a `sub`. Same for a simulated Ministry-DB dump.
3. **Delivery leak test:** assert `S_user` / `userId` never appear in any id_token,
   userinfo, access token, server log, or RP-server-visible payload (the option (b)
   trap). This is the single easiest place to silently break the whole thing.
4. **VOPRF conformance:** the JS client must round-trip Signet's existing RFC 9497
   ristretto255-SHA512 vectors byte-for-byte, and must **reject** an evaluation whose
   DLEQ proof is against the wrong key (Signet already has this test server-side;
   mirror it client-side).
5. **Tier-stability test:** same (user, RP) across simulated devices/ecosystems yields
   the same `R_rp` within a tier, and a tier change is detected, not silently forked
   into a second identity.
6. **Blast-radius assertion:** encode "Minister-DB-alone is insufficient" as a test:
   with Signet's key withheld and the RP salt withheld, `R_rp` is unrecoverable.
7. **Constant-time / key-handling review** of the VOPRF client blind/unblind and all
   HKDF inputs; zeroize `S_user` and `R_rp` after use, matching the vault module's
   existing discipline.

---

## 7. Open questions that need Tyler's decision

1. **Tier-B `userId` delivery to the browser.** The universal fallback needs the OPRF
   input (`userId`) in the browser but never on the RP server. Cleanest options: (a) a
   URL-fragment front-channel on the Ministry login redirect (robust, but adds a
   client-side handler to server-rendered RPs), or (b) a direct browser->Ministry
   authenticated fetch (simple, but third-party-cookie fragile under Safari ITP /
   Chrome). Which delivery mechanism do we commit to? (This is the load-bearing
   plumbing decision for Tier B.)
2. **Do we accept the OPRF-relay-through-RP-server model (2.4 path 2) as the standard
   Tier-B transport?** It is elegant and dodges third-party cookies, but it routes the
   blinded Ministry-side evaluation through the RP's infrastructure. I judge it safe
   (the RP learns only blinded values), but it is a trust-surface call worth making
   explicitly rather than by default.
3. **RP secret salt: secret env var (2.6-ii) as the default, or go straight to RP-side
   blind OPRF (2.6-iii) for the flagship RPs?** The env-var path is near-free and
   degrades gracefully; the blind-OPRF path is stronger (the salt never reaches the
   browser) but is real per-RP infra. My recommendation is env-var default + blind-OPRF
   opt-in, but if a flagship RP is a high-value de-anon target, we may want (iii) from
   day one.

Minor, decidable later: whether to offer the wallet factor (option d) at all in v1,
and the exact `derivation_tier` hint storage (Ministry-served vs. RP-stored).
