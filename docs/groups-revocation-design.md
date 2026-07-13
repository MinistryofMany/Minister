# Badge revocation — design (per-RP status lists)

Status: draft for security review. 2026-07-12. Owner: Tyler. Companion to
`docs/groups-design.md` ("Membership lifecycle and revocation" reserves the
`credentialStatus` seam this doc fills). Nothing here is built; the Groups
backend (branch `worktree-agent-aade02475a027fe68`, commit `ee84349`) already
enforces revocation at _mint_ time — this designs the mechanism that reaches
credentials and entitlements a relying party **already holds**.

**Recommendation up front:** per-relying-party **sharded Bitstring Status
Lists** (W3C Bitstring Status List v1.0 shape), published pull-only at
unguessable per-RP URLs, hardened with a signed monotonic version + short
validity window (the freshness discipline of a CT-style log), and a
revocation-latch in the SDK. Candidate B's hash-linked delta log is
deliberately folded down to its freshness properties; candidate C
(background per-user refresh) is rejected as a _transport_ because its only
private form collapses into this pull model — the full verdict is in §4.

---

## 1. Problem and requirements

A `group-membership` badge is disclosed to a relying party as a per-RP
re-minted VC (pairwise subject). The RP verifies it once and typically
derives a **durable entitlement** from it — a Discreetly room membership, a
Deforum sub-forum grant — that outlives the VC bytes. When a group admin
kicks a member, that entitlement must die too.

Hard requirements (from Tyler, 2026-07-12):

1. **No user-facing re-proving.** The member never re-does a login or
   disclosure to _keep_ access. Short-TTL-forced-re-disclosure is rejected.
2. **Fast revocation.** A kick is enforced at the RP within minutes, not a
   24h session TTL.
3. **Pairwise-safe.** The revocation handle must get exactly the per-RP
   discipline the pairwise `sub` and `jti` already get. A single shared
   status slot per badge is a cross-RP join key — rejected.
4. **Bounded RP-side cost.** What an RP fetches is sized to _its own_
   disclosures, never a global ever-growing list.
5. **Minimize what Ministry learns.** Publish-and-pull (RP downloads a
   per-RP artifact, checks locally, herd-private) over the RP polling
   Ministry with its roster.

And two secondary requirements from the task framing:

6. **Generalizes** to any revocable badge (fraudulently-issued badge recall,
   compromised-credential withdrawal), not just groups.
7. **Slug release** on group deletion only after revocation has fully
   propagated.

### 1.1 What the RP actually holds (why this is an entitlement problem)

The disclosure path (`apps/minister/src/lib/oidc-claims.ts:loadApprovedBadgeJwts`
→ `packages/vc/src/issue.ts:reMintVc`) already makes every disclosed VC a
short-lived, per-RP artifact:

| Field                                     | Value at disclosure                                                                           | Cross-RP linkable?                                                                                                                                                                     |
| ----------------------------------------- | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sub` / `credentialSubject.id`            | `did:web:<host>:u:<pairwiseSub>`, pairwise per (user, clientId)                               | No                                                                                                                                                                                     |
| `jti`                                     | `HMAC(secret, "jti:"+badgeId+":"+clientId)` via the pairwise seam                             | No                                                                                                                                                                                     |
| `iat` / `nbf` / `exp`                     | disclosure-time stamped; `exp` presentation-shaped, TTL = 1h (`BADGE_DISCLOSURE_TTL_SECONDS`) | No (varies per disclosure)                                                                                                                                                             |
| `credentialSubject.issuanceMonth`         | coarse `YYYY-MM` bucket                                                                       | ~3.7 bits, accepted (MIN-1)                                                                                                                                                            |
| `credentialSubject.nullifier`             | per-RP Sybil tag (when ref-bearing)                                                           | No                                                                                                                                                                                     |
| claim values (`group`, `role`, `groupId`) | the disclosed fact itself                                                                     | **Yes — inherent.** Two RPs both told `group: "acme"` share that fact; for a small group the claim content alone is a strong correlator. Out of scope for this design; noted honestly. |

So the RP-held VC dies within the hour on its own. What persists is the
RP's _derived state_: Discreetly gates a room once, at join, and the room
membership then lives in Discreetly's DB. **Revocation therefore means:
give the RP a durable, per-RP, cheap-to-check handle it records next to the
entitlement, and a Ministry-published feed of which handles are dead.**
That handle is the `credentialStatus` entry this doc designs.

Two layers, to be explicit about what already exists:

- **Layer 1 (built, branch `ee84349`):** at every disclosure, Minister
  re-checks the live `GroupMembership` row. No row → the badge is omitted
  from the mint (fail-closed). A kicked member can never _newly_ disclose.
- **Layer 2 (this design):** the status list reaches entitlements derived
  from disclosures that happened _before_ the kick.

---

## 2. Prior art surveyed, and what transfers

- **W3C Bitstring Status List v1.0** (and its predecessor StatusList2021):
  the standard VC answer. `credentialStatus` carries a
  `BitstringStatusListEntry` (list URL + index); the list is a signed VC
  wrapping a GZIP-compressed bitstring. Herd privacy: the verifier fetches
  the whole list, so the publisher can't tell which subject was checked.
  Spec-relevant details used below: `statusPurpose: "revocation"` is
  **irreversible** ("this status is not reversible" — we lean on that
  monotonicity for rollback defense); indexes SHOULD be assigned randomly;
  the 131,072-bit minimum size applies "unless a different lower bound is
  established by a specific ecosystem specification" (this document is that
  ecosystem specification — see §5.3); `ttl` is a refresh hint that never
  overrides the validity period. The spec's warning that a malicious issuer
  could make per-credential lists to track verifiers is addressed in §5.3
  (our partition unit is the RP, which is self-identifying anyway — never
  the credential or the subject).
- **IETF Token Status List** (draft-ietf-oauth-status-list): the JOSE-native
  sibling (`typ: statuslist+jwt`, `status_list: {bits, lst}`, `ttl`/`exp`
  caching rules, "token claims win over HTTP caching headers"). We keep the
  W3C envelope (Minister is a W3C JWT-VC shop and `groups-design.md` named
  the `credentialStatus` seam) but adopt its caching discipline: the signed
  `exp`/`ttl` govern freshness, HTTP headers are advisory only.
- **Certificate Transparency (RFC 6962):** signed tree heads, monotonic
  growth, and the split-view/equivocation problem. What transfers: signed
  heads with freshness + client-side monotonic high-water marks. What does
  not: gossip/auditing against issuer equivocation — Ministry _is_ the
  trusted issuer of these facts; an equivocating Ministry could equally just
  not revoke, so CT's audit machinery buys nothing against our threat model
  (a third party serving stale data is the real threat; §5.6).
- **CRLite / delta-CRLs / Bloom-filter cascades:** built for global-scale
  universes (all of WebPKI) where full lists are megabytes. Filter cascades
  need the complete universe of live certs to build, and false positives
  need a fallback per-item query — which is exactly the per-item leak we
  refuse. At per-RP KB scale, none of this earns its complexity.
- **Anonymous-credential revocation (dynamic accumulators, Camenisch-
  Lysyanskaya; AnonCreds revocation registries):** holder proves
  non-revocation in zero knowledge against a global accumulator. That solves
  _holder-presentation unlinkability_ — a problem Minister does not have,
  because the holder never re-presents: Ministry re-mints per-RP, and the
  per-RP partition delivers unlinkability structurally. Accumulators also
  need holder-side witness updates (the user's agent online), which violates
  requirement 1's spirit. Not applicable.
- **OCSP:** per-credential status queries — the anti-model (per-check
  metadata leak; requirement 5). OCSP _stapling_ (issuer attaches a fresh
  status proof at presentation) is, in our world, just short-TTL re-mint:
  already rejected as re-proving.

---

## 3. Candidate mechanisms

### A. Per-RP Bitstring Status List (baseline — recommended, hardened)

One status-list namespace per relying party, sharded into fixed-size
bitstrings, each published as a signed JWT-VC at an unguessable per-RP URL.
The re-minted VC carries a `credentialStatus` entry pointing at (its RP's
list, its randomly-assigned index). RP polls with ETag; a 304 costs nothing;
a change is a ~KB fetch. Kicking a member flips one bit.

### B. Per-RP hash-linked delta log (CT-style; "RSS per RP" is this with weaker transport)

Ministry appends revocation events to a per-RP hash-chained log; a signed
head carries `(seq, chainHash, publishedAt)`. RP compares heads (O(1)),
fetches only deltas, verifies the chain, fast-forwards. Tamper-evident
history; edge-triggered semantics.

An RSS/Atom feed per RP is exactly this minus the hash chain and signed
head — same privacy shape, strictly weaker integrity. Treated as a degraded
B, not a separate candidate.

### C. Background auto-refresh / batched TTL poll (Tyler's lean)

The RP silently refreshes membership server-to-server on a timer — badges
get short TTLs but the RP renews them on the user's behalf, so the user
never re-proves. Pressure-tested in §4.

### Comparison

Axes: privacy (what Ministry learns; cross-RP correlation), security
(forgery / replay / tamper-evidence / rollback-freshness), scalability,
complexity, and requirement 1.

| Axis                     | A. Per-RP bitstring                                                                                                                                                                                                                    | B. Per-RP delta log                                                                                                                             | C. Background refresh                                                                                                                                                                                                                                     |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| What Ministry learns     | List-fetch events per RP (not per user); CDN caching blurs even that. Nothing new — Ministry already knows what it disclosed to whom.                                                                                                  | Same as A (head polls).                                                                                                                         | **Which users are still active at the RP, continuously** — the RP's standing roster + churn + check cadence. A new, ongoing per-user metadata channel the pairwise model exists to avoid. Breach/subpoena at Ministry then exposes historical RP rosters. |
| Cross-RP correlation     | Per-RP lists + per-RP random indices: nothing joinable by construction. Residual: revocation-_timing_ joins across lists (§5.7, mitigated with epochs + jitter).                                                                       | Same residual, slightly worse: events are individually timestamped, so timing joins are handed to the observer rather than inferred by diffing. | Per-user refresh handles must be minted per-RP (pairwise) — doable — but the _server-side query trail_ correlates users across time at Ministry.                                                                                                          |
| Forgery / replay         | List is a signed VC (badge key, DID-pinned kid); `sub` = list URL binds it to its list; replay across lists impossible. Flipping a bit _on_ needs Ministry; clearing needs Ministry (and purpose `revocation` is irreversible — §5.6). | Signed heads + hash chain: strictly stronger _history_ integrity (tamper-evident log).                                                          | Standard OAuth-style: forged refresh responses need the token key. Nothing pull-able to audit.                                                                                                                                                            |
| Rollback / stale-serve   | Needs explicit hardening: signed `exp` (max-age), monotonic version, SDK revocation latch — all specified in §5.6. With them, a MITM can delay a kick by at most the validity window.                                                  | Monotonic seq gives this near-natively; still needs signed-head max-age.                                                                        | The RP's own poller controls freshness; a MITM dropping refreshes causes fail-open or fail-closed per RP policy — same knob as A, no better.                                                                                                              |
| Scalability / RP cost    | O(RP's own disclosures), KB-scale, mostly 304s. Ministry: one small signed blob per RP-shard per epoch.                                                                                                                                | O(delta) — marginally better bandwidth than A's already-trivial KBs; more moving parts (snapshots, compaction, resync-when-behind).             | O(roster) queries per period against Ministry — the _most_ expensive for both sides, and per-user.                                                                                                                                                        |
| Complexity / infra       | Low-moderate: one table, one publisher job, one GET route, one SDK checker. Standard W3C shape RP tooling can recognize.                                                                                                               | Moderate-high: log storage, head signing, sync protocol, behind-resync, compaction policy. Bespoke shape.                                       | Moderate: refresh-token-like handles Ministry doesn't issue today (an explicit v1 non-goal), per-RP schedulers, retry semantics.                                                                                                                          |
| Req 1 (no re-proving)    | Yes — checking is RP-server-side only.                                                                                                                                                                                                 | Yes.                                                                                                                                            | Yes — that is its one virtue.                                                                                                                                                                                                                             |
| Req 5 (publish-and-pull) | Yes, natively.                                                                                                                                                                                                                         | Yes, natively.                                                                                                                                  | **No** — RP-initiated, per-user, roster-revealing.                                                                                                                                                                                                        |

### Verdict

**A**, with **B's freshness discipline grafted on** (signed monotonic
version + short validity window + client high-water mark) — call it **A′**.
B's remaining advantage over A′ is a tamper-evident _history_ (third-party
auditability of Ministry's revocation behavior over time). That is a
non-requirement today, and per-RP lists are so small that B's bandwidth win
never materializes. If audit-grade history is ever wanted, B can be layered
_under_ A later (publish the same bit-flips into a log) without changing
the RP-facing contract.

---

## 4. The honest verdict on C (background auto-refresh)

The idea's core is right: **renewal must be server-to-server and invisible
to the user.** Requirement 1 is satisfied. But as a transport it fails
requirements 3–5, and the failures are structural, not fixable with care:

1. **It inverts who reveals what.** Today Ministry learns about a
   (user, RP) relationship only when the _user_ acts (a disclosure). Under
   C, the RP must present some durable per-user handle to Ministry on a
   timer — so Ministry continuously learns the RP's live roster, its churn,
   and its refresh cadence. That is precisely the metadata channel the
   pairwise model was built to avoid, and it accrues at Ministry as a
   queryable history (breach and subpoena surface).
2. **It needs refresh-token infrastructure Minister deliberately lacks.**
   No refresh tokens is a recorded v1 non-goal (`CLAUDE.md` Non-goals);
   Ministry would have to mint, store, rotate, and revoke per-(user, RP)
   refresh handles — a whole new credential class whose _only_ purpose is
   to let RPs ask about users, i.e. the leak in (1).
3. **Batching doesn't rescue it.** Sending the whole roster in one nightly
   batch still _is_ the roster. Anonymizing the query (PIR or an OPRF over
   membership handles) is heavyweight machinery to make a query private —
   when the query can simply be replaced by a download.
4. **The genuinely private version of C is A.** If the RP refuses to name
   users and instead asks "give me everything that changed for my
   disclosures," Ministry must pre-compute a per-RP artifact the RP pulls —
   that is candidate A, exactly. C collapses into the pull model the moment
   you make it private.

**Disposition:** reject C as a transport; keep two of its instincts:

- _Server-side renewal:_ badge renewal (a 1-year VC expiring while the
  membership row still lives) is Ministry-internal re-issuance with a
  **stable status handle across renewal** (§6.3) — the user never re-proves,
  and the RP never has to re-gate. This delivers what C actually wanted.
- _Latency:_ an optional content-free "poke" webhook ("your list changed —
  pull") preserves pull privacy while cutting poll latency, if the default
  60s poll is ever not enough (§5.8). Not in v1.

---

## 5. The design (A′)

### 5.1 Status anchors — what a bit means

A bit does **not** represent a badge row. It represents a **status
anchor**: the revocable fact underneath the badge.

- `group-membership` → anchor `gm:<groupMembershipId>` (one per
  (group, user) membership row incarnation).
- generic revocable badge → anchor `badge:<badgeId>`.

Why the indirection: badge rows are re-issued on renewal (1-year VC expiry
while the membership persists). If the handle were keyed on `badgeId`,
renewal would orphan every RP's recorded handle — the old bit would never
flip, and the RP would honor a stale entitlement forever, or would have to
re-gate the user (re-proving, forbidden). Keyed on the anchor, renewal
inherits the same (list, index) at each RP, and revoking the anchor flips
the one bit every RP is already watching. Kick-then-re-add creates a _new_
membership row → new anchor → new index; the old bit stays set forever
(monotonic, §5.6).

Per-RP discipline check: the anchor is Ministry-internal and never leaves
Minister. What leaves is (listId, index) — allocated independently per RP.
Within one RP the handle is stable across renewals, which adds no linkage
the RP doesn't already have via the stable pairwise `sub`. Across RPs there
is nothing to join.

### 5.2 Data model (Ministry)

```prisma
model StatusList {
  id          String   @id @default(cuid())  // public listId — unguessable, opaque, NOT derived from clientId
  clientId    String                          // owning RP (Ministry-internal mapping)
  shardNo     Int
  sizeBits    Int      @default(8192)
  version     Int      @default(0)            // monotonic, bumped on EVERY republication (content or heartbeat)
  bits        Bytes                           // current raw bitstring (1 KiB)
  signedJwt   String                          // latest signed BitstringStatusListCredential
  publishedAt DateTime
  @@unique([clientId, shardNo])
}

model BadgeStatusEntry {
  id           String    @id @default(cuid())
  statusAnchor String                          // "gm:<membershipId>" | "badge:<badgeId>"
  clientId     String
  listId       String
  bitIndex     Int
  revokedAt    DateTime?                       // set => bit must be published as 1
  revealAfter  DateTime?                       // per-(event,list) jitter floor (§5.7)
  createdAt    DateTime  @default(now())
  @@unique([statusAnchor, clientId])           // one handle per (fact, RP)
  @@unique([listId, bitIndex])                 // no index reuse, ever
}
```

Plus `Badge.statusAnchor String?` (null = non-revocable badge; set at
issuance for revocable types) and a `revocable: boolean` flag on
`BadgeTypeMeta` in `packages/shared/src/badge-types.ts` (mirrored in
`@minister/client/badges`; the drift-check must carry it).

**Allocation** is lazy, at first disclosure of a revocable badge to a given
RP, inside `loadApprovedBadgeJwts`: find-or-create the entry for
(statusAnchor, clientId); on create, pick a **cryptographically random**
free index in the RP's current shard (retry on `@@unique` conflict; open a
new shard past ~75% fill to bound retries). Random assignment is what the
W3C spec recommends, and it keeps the index from encoding join order in a
long-lived artifact. Allocation does **not** change the published bitstring
(bits only flip on revocation), so an observer diffing a list learns
revocation events only — never disclosure activity.

Same-badge-same-RP re-disclosure is idempotent (unique on
(statusAnchor, clientId)). Same badge at two RPs → two independent entries.
Two badges of one user at one RP → two entries (per-fact, matching the
per-badge `jti` discipline).

**Revocation chokepoint** — one primitive everything routes through:

```
revokeStatusAnchor(anchor, reason):
  tx: set revokedAt = now() on all BadgeStatusEntry rows for anchor
      set revealAfter = now() + uniform(0, JITTER_MAX) per row   // independent per list
      audit(reason)
  (publisher picks the rows up on its next epoch)
```

Callers: `removeMember` / `setMemberRole`-demotion-with-revoke semantics if
ever needed, group deletion (all anchors of the group), admin badge
revocation (fraud/compromise), user account deletion, badge self-removal by
the user, and merge-dedupe aliasing (§6.4). Role _changes_ are not
revocations — the live-role re-mint (layer 1) handles them, and an RP that
must react to demotions in minutes should gate the admin surface per-access
on a fresh disclosure rather than a durable entitlement (documented RP
guidance, not mechanism).

### 5.3 Sharding, size, and the KMS ceiling

Shards are fixed at **8,192 bits (1 KiB raw)**, all-zero at creation,
published at full size from birth (so growth never leaks allocation).

Two constraints meet here:

- **KMS signing ceiling.** Status lists are signed with the **badge key
  #key-2** (KMS-backed, the trust anchor RPs already pin via the DID
  document's `assertionMethod` — see `docs/kms-signing.md`). KMS `Sign`
  with `MessageType=RAW` caps the message at 4,096 bytes, and Ed25519
  requires RAW. Worst case (adversarially incompressible bitstring):
  GZIP(1,024 B) ≈ 1,047 B → base64url ≈ 1,397 chars encodedList → JSON
  payload ≈ 1,850 B → JWS signing input (b64url(header).b64url(payload)) ≈
  2,610 B — comfortably under 4,096 with ~1.4 KB envelope margin. A
  16,384-bit shard busts the ceiling in the worst case (≈ 4,300 B); 8,192
  is the safe unit. The publisher must still hard-assert
  `signingInput.length ≤ 4096` before calling KMS and fail loudly, with a
  unit test pinning the worst case (random bits, zero compression).
- **W3C minimum size.** The spec's 131,072-bit floor exists so that _which
  list is fetched_ cannot identify a subject. It explicitly yields to "a
  different lower bound … established by a specific ecosystem
  specification" — this document is that specification, and the deviation
  is sound because our smallest fetchable unit identifies **the RP** (which
  the fetch already identifies via its route) and never a subject: the RP
  always fetches **all** of its shards (they are ~KB), so the herd for any
  status check is the RP's entire disclosed population, exactly the herd
  the spec's minimum is protecting. The spec's malicious-issuer warning
  (per-credential lists to track verifier processing) does not apply: the
  partition is per-verifier, not per-credential, and adding more
  credentials to the same RP's list never shrinks anyone's herd.

Why sign with #key-2 and not the unbounded in-process token key #key-3: a
status list is an **access-control artifact** — forging one (specifically,
serving a list with a kicked member's bit clear) keeps a revoked member
inside a room. #key-2 is the KMS-held, non-extractable trust anchor the SDK
already pins for exactly this class of decision; #key-3 lives in process
memory. The 8,192-bit shard is the price of the stronger key, and it is
cheap. (Fallback if operations ever demand bigger shards: sign with
#key-3 and document the reduced anchor — a #key-3 attacker can already
forge whole logins, but keep the decision explicit, not accidental.)

### 5.4 The `credentialStatus` shape on the re-minted VC

`reMintVc` gains a `credentialStatus` option; `loadApprovedBadgeJwts`
passes it for revocable badges after allocation:

```jsonc
// inside the disclosed JWT-VC payload's `vc` object (VC 2.0), sibling of credentialSubject
"credentialStatus": {
  "id": "https://ministry.id/status/<listId>#<bitIndex>",
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "<bitIndex>",                       // base-10 string per spec
  "statusListCredential": "https://ministry.id/status/<listId>"
}
```

Rules, mirroring the reserved-claim discipline already in `reMintVc`:

- It lives at the **`vc` level, not inside `credentialSubject`** — the
  strict per-type Zod claim schemas are untouched, and old SDK versions
  (which read only `vc.type` and `vc.credentialSubject`) ignore it cleanly.
- **Stored VCs never carry `credentialStatus`.** The stored artifact keeps
  the stable subject and never leaves Minister; `reMintVc` must **strip**
  any `credentialStatus` found on the original (same posture as the
  reserved `nullifier`/`issuanceMonth` strip — a DB-write attacker or a
  future import path must not be able to smuggle a status pointer into a
  disclosure) and stamp only the caller-supplied per-RP entry.
- The `listId` is an opaque random cuid. It is not derived from the
  clientId (no offline-guessable mapping if any secret leaks), and the URL
  functions as a weak capability: only Ministry and that RP know it. Leak
  impact is bounded — an outsider holding the URL sees opaque bit flips and
  counts, with no index→user mapping (that mapping exists only in the RP's
  own records and Ministry's DB).
- Per-RP field inventory after this change (extends the §1.1 table):
  `credentialStatus` is per-(fact, RP) — allocated randomly per RP, stable
  within an RP across renewals (equivalent to the stable pairwise `sub` the
  RP already holds), unjoinable across RPs. No other field changes.

Share links: **v1 attaches no `credentialStatus` on the share-link re-mint
path** (the `sharelink-*` pairwise families). A share link is a 7-day,
human-to-human artifact, not a standing entitlement, and per-shareLink
lists would explode the bookkeeping for no consumer that checks them.
Accepted gap, flagged for the auditor (§9): a revocable badge shown via
share link is un-recallable for the remainder of its ≤1h presentation
window and the link's validity — same exposure the presentation TTL already
bounds today.

### 5.5 Publishing (Ministry side)

- `GET /status/<listId>` (route handler `app/status/[listId]/route.ts`)
  returns the stored `signedJwt` as `application/vc+jwt` (the pre-signed
  blob — the hot path does zero crypto), with `ETag: "<version>"`,
  `Cache-Control: public, max-age=60`, and 304 support. Unauthenticated:
  Ministry-side herd privacy comes from whole-list fetches, and Cloudflare
  caching then even blurs _which RP instance_ polled and when (origin sees
  ~1 request/list/max-age regardless of poller count). `noindex`, no
  directory enumeration, 404 for unknown ids (uniform with not-found).
- The **StatusListCredential** is a JWT-VC signed by #key-2:

  ```jsonc
  {
    "iss": "did:web:ministry.id",
    "sub": "https://ministry.id/status/<listId>",   // binds the credential to its URL — replay across lists impossible
    "iat": <publication epoch seconds>,
    "exp": <iat + VALIDITY_WINDOW>,                  // hard freshness bound (15 min)
    "jti": "<random per publication>",
    "statusListVersion": <monotonic integer>,        // bumped on EVERY republication, heartbeats included
    "vc": {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "type": ["VerifiableCredential", "BitstringStatusListCredential"],
      "credentialSubject": {
        "id": "https://ministry.id/status/<listId>#list",
        "type": "BitstringStatusList",
        "statusPurpose": "revocation",
        "encodedList": "u<base64url(GZIP(bits))>"    // multibase, per spec
      },
      "ttl": 60000                                    // refresh hint (ms), advisory per spec
    }
  }
  ```

  `typ: "vc+jwt"`, `kid` = #key-2. Cross-type confusion is closed from both
  directions: a status-list JWT replayed as a badge fails the SDK's
  `badgeTypeOf` (no Minister badge type) and carries no
  `credentialSubject` claims that parse; a badge replayed as a status list
  fails the required `BitstringStatusListCredential` type and the
  `sub == fetched URL` check.

- **Publisher job** (an interval worker in the single-instance app, or a
  scheduled script — single-writer either way), two duties:
  1. _Epoch publication_ (every `EPOCH = 60s`, only for dirty lists): fold
     in every `BadgeStatusEntry` with `revokedAt != null`,
     `revealAfter <= now()`, and bit not yet published; set bits;
     `version++`; sign; store; audit.
  2. _Heartbeat re-sign_ (every `VALIDITY_WINDOW / 3 = 5 min`, all live
     lists): re-sign unchanged bits with fresh `iat`/`exp`, `version++`.
     Without heartbeats, max-age would force RPs into fail-open/fail-closed
     limbo during quiet periods. KMS cost: one `Sign` per list per 5 min —
     at the current RP count, negligible.

  A list stays "live" (heartbeat-maintained, resolvable) as long as any
  anchor in it could still back an RP entitlement; since storage is ~1 KiB
  - a row per list, the simple policy is: **never retire a list**. Indices
    are never reused (§5.2), so correctness never depends on retirement.

### 5.6 Freshness and rollback defense (RP side)

Threat: a MITM, a poisoned cache, or a compromised CDN serves an old (but
validly signed) list in which the kicked member's bit is still 0, to keep
them inside. Ministry-side equivocation is _not_ the threat here — an
issuer that wants a member unrevoked can simply not revoke them; the
status list adds no new trust in Ministry beyond what badge issuance
already grants.

Four stacked defenses, all mandatory in the SDK:

1. **Signature + URL binding.** Verify the JWT against the DID
   `assertionMethod` (#key-2 pinned — the resolver in
   `minister-client/src/verify-badge.ts` already exists to reuse), require
   `vc.type` ∋ `BitstringStatusListCredential`, `statusPurpose:
"revocation"`, and `sub` exactly equal to the URL the SDK fetched.
2. **Hard max-age.** Reject any list with `exp` in the past (30s clock
   tolerance, matching the id_token verifier). A stale-served list is
   therefore useful to an attacker for at most `VALIDITY_WINDOW` (15 min)
   past its publication.
3. **Monotonic version high-water mark.** Per listId, remember the highest
   `statusListVersion` seen; reject regressions. In-memory per process by
   default (honest limitation: a restart resets it, leaving defense 2 as
   the floor); an optional persistence hook lets the RP keep it in its own
   storage.
4. **Revocation latch.** Because `statusPurpose: "revocation"` is
   irreversible by spec, the SDK latches: once _any_ validly-signed list
   showed an index revoked, that handle is revoked forever in the RP's
   local state, no matter what later lists say. This converts every
   rollback variant into, at worst, a _delay_ of one validity window —
   never an un-revocation. (This is also why `suspension` — which is
   reversible — is explicitly out of scope; if suspension is ever wanted
   it must be a separate purpose/list with its own, weaker analysis.)

Combined bound: **kick → enforced ≤ jitter (≤ 4 min) + epoch (≤ 1 min) +
CDN max-age (≤ 1 min) + RP poll interval (≤ 1 min) + RP sweep latency**,
worst-case ≈ 7–8 minutes with defaults, and a MITM can stretch that by at
most 15 more minutes once, before the RP sees either a fresh list or a
hard staleness signal. Meets "minutes, not a 24h TTL."

**Failure policy** (list unfetchable or stale past `exp`): default
**fail-open on last-known state with loud staleness telemetry** — the RP
keeps honoring entitlements as last confirmed. Rationale: fail-closed turns
any Ministry/publisher outage into a mass eviction whose recovery _is_
re-proving (every user re-discloses), violating requirement 1 via the back
door; browsers made the same call for CRLs. A `staleFailMode: "closed"`
knob and a `maxStaleMs` hard cap are provided for RPs whose rooms warrant
it. The auditor should weigh this default (§9).

### 5.7 The residual cross-RP channel: revocation timing

The one correlator per-RP lists cannot remove by construction: the same
kick flips bits in several RPs' lists at _around the same time_. Two
colluding RPs (or an outsider holding two leaked list URLs) can join "a
bit flipped in my list at epoch T" ↔ "a bit flipped in yours at ≈T" into a
probabilistic link between two pairwise identities.

Mitigations, and their honest limits:

- **Epoch batching** (60s): all changes inside an epoch publish together,
  so the anonymity set of one flip is "every revocation that epoch" —
  usually 1 on a small instance. Necessary, insufficient.
- **Per-(event, list) jitter** (`revealAfter = now + uniform(0, 4 min)`,
  independent per RP list): decorrelates the _publication_ instants of one
  event across RPs. Widening the jitter strengthens this and directly
  weakens requirement 2; 4 minutes is the proposed balance, tunable.
- **Perspective:** for `group-membership` specifically, the claim content
  (`group: "acme"`) is already a cross-RP correlator far stronger than a
  timing join for any small group (§1.1). The timing channel matters most
  for the _generic_ revocable badge case (large anonymity sets), which is
  exactly where "several revocations per epoch" also blunts it.

Accepted as a quantified residual; a low-traffic instance leaks
probabilistic revocation-time links to observers that already hold both
per-RP artifacts. The alternative — a shared global list — is a
_deterministic_ join key, which is why it stays rejected.

### 5.8 The SDK check side (`@minister/client`)

- `verifyMinisterBadge` additionally parses `vc.credentialStatus` when
  present: strict shape check (type, purpose, https URL on the configured
  issuer origin, integer index within `0..2^20`); malformed → the badge
  fails closed (issuer drift, same posture as a malformed nullifier);
  well-formed → exposed as `status: { uri, index }` on `VerifiedBadge`.
  Badges _without_ `credentialStatus` are unchanged.
- New export `createMinisterStatusChecker({ issuer, pollIntervalMs?,
maxStaleMs?, staleFailMode?, persistHighWater? })`:
  - `check({ uri, index })` → `"valid" | "revoked" | "stale"` from the
    cached list, refreshing per ETag + `exp`/`ttl` (token claims override
    HTTP headers, per the IETF discipline);
  - implements §5.6 defenses 1–4 (latch included);
  - herd-private by construction: it only ever fetches whole lists.
- **RP contract for durable entitlements** (documented in the SDK README):
  when granting a durable entitlement from a badge that carries `status`,
  persist `(uri, index)` next to the entitlement; run a periodic sweep
  (Discreetly: a 60s job over room memberships granted via
  `group-membership`) calling `check`; on `"revoked"`, drop the
  entitlement; on `"stale"`, apply the configured fail mode. RPs that
  ignore `status` (old SDK pins) keep today's behavior: layer-1 mint-time
  revocation only. The planned shared/client drift-check must cover the
  `revocable` flag and the new field so vocabulary drift can't silently
  strip status handling.

---

## 6. Generalization beyond groups

### 6.1 Registry flag

`BadgeTypeMeta.revocable: boolean`. `group-membership` ships `true`; all
existing types ship `false` (their disclosed facts are prove-once). The
mechanism is type-agnostic from day one: flipping the flag on a type makes
new issuances mint a `statusAnchor` and disclose with `credentialStatus`.

### 6.2 Fraud / compromise recall

Admin action "revoke badge" (and user self-service "remove badge", and
account deletion cascades) call `revokeStatusAnchor("badge:<id>", reason)`
plus the existing row handling. This reaches every RP that was ever
disclosed to for _revocable_ types. For badges issued before their type
became revocable (no anchor, no entries), recall remains what it is today:
mint-time only, exposure bounded by the 1h presentation TTL and the RP's
own entitlement policy. That gap closes organically as anchors roll out;
it is not retro-fixable without re-issuing old rows (a one-time backfill
job can do that per type when the flag flips — include it in the flag-flip
runbook).

### 6.3 Renewal (the C-instinct, done privately)

A background Ministry job re-issues a revocable badge whose VC nears its
1-year `exp` while its anchor's underlying fact still holds (membership row
alive). New badge row, **same anchor** → same (list, index) at every RP.
No user action, no RP re-gating, no new disclosure event visible anywhere.
This is required before the first group badges age out (issue + 1y), not
in v1 — tracked in the build plan.

### 6.4 Account-merge interplay

Anchors are keyed to facts, not users, so a merge (badges moving to the
survivor, `SubjectOverride` preserving the donor's pairwise `sub` per RP)
leaves every (anchor, clientId) entry valid — handle continuity holds. The
one wrinkle: both accounts holding membership in the _same_ group. The
`@@unique([groupId, userId])` constraint forces one row to be dropped at
merge; naively revoking the dropped row's anchor would evict the survivor
from rooms joined under the donor identity, and re-granting would require
re-disclosure (re-proving). Instead the dropped anchor is **aliased** to
the surviving one: an `aliasOf` column on `BadgeStatusEntry`'s anchor
registry (or a tiny `StatusAnchorAlias` table) so that revoking the
survivor's membership later flips _both_ families of bits. Auditor
attention flagged (§9).

---

## 7. Slug release on group deletion

### 7.1 Why early release is unsafe

RP gates match on the **slug** (`where: { group: "acme" }`), not the
`groupId` — deep-link prefills use the slug, and nothing forces an RP
policy to pin `groupId`. If `acme` is deleted and immediately re-founded by
someone else:

- any RP **entitlement** granted under old-acme and not yet swept revoked
  now satisfies gates that mean new-acme (access bleed between unrelated
  communities);
- any still-live disclosed VC (≤ 1h presentation window) from old-acme
  passes new-acme gates on its face — `groupId` in the claims protects
  only RPs that check it, which the v1 policy shape does not.

So the slug may be re-founded only when **no artifact of the old group can
still satisfy a gate anywhere**.

### 7.2 The propagation-complete condition

On `deleteGroup(G)` at time `T0`:

1. Memberships cascade-delete → layer 1 stops all new disclosures at once.
2. Every anchor of G is revoked via the chokepoint (bits queued, jittered).
3. `Group` row is replaced by a `GroupTombstone { slug, groupId, deletedAt,
releasableAt }`; founding checks tombstones alongside the reserved-slug
   denylist.

Ministry can **prove** publication completeness from its own bookkeeping —
this is the load-bearing bit: propagation is _checkable_, not assumed. The
slug is releasable when all of:

- **Published:** no `BadgeStatusEntry` of any G-anchor remains with
  `revokedAt` set but its bit unpublished (i.e., every owning list has
  published a version at or after each entry's fold-in). The publisher
  keeps this queryable (`pendingCount(anchorPrefix) == 0`).
- **Consumed (bounded, not observed):** conforming RPs are only guaranteed
  to have _seen_ those bits once their cached copies have aged out —
  `VALIDITY_WINDOW` (15 min) past the last relevant publication. Ministry
  cannot observe RP consumption (pull model, by design) and must not try
  (that would be C's leak); it relies on the freshness contract instead.
- **In-flight VCs dead:** `BADGE_DISCLOSURE_TTL_SECONDS` (1h) past `T0`
  covers every disclosed VC minted before the delete.
- **Grace:** the security floor is therefore
  `T0 + JITTER_MAX + EPOCH + VALIDITY_WINDOW + BADGE_DISCLOSURE_TTL`
  ≈ **T0 + ~80 minutes** with defaults — _plus_ the pending-count check
  above, whichever is later. On top of the floor, set a **product-level
  tombstone** (recommended: 30 days) against re-founding confusion and
  squat-the-corpse attacks; the floor is the hard minimum, the tombstone
  is policy. A background job flips `releasableAt` reached + pending-zero
  into actual release (delete the tombstone).

Note what this does _not_ cover, deliberately: an RP running an old SDK
that never checks status keeps its stale entitlements regardless of any
waiting period — no delay fixes a consumer that doesn't consume. The
tombstone protects conforming RPs; the SDK contract (§5.8) is what makes
an RP conforming.

---

## 8. Phased build plan

Each phase lands green (tests written and passing) before the next starts.

- **Phase 0 — schema + chokepoint (Ministry).** `StatusList`,
  `BadgeStatusEntry`, `Badge.statusAnchor`, `GroupTombstone`, migration;
  `revocable` flag in `packages/shared` (+ mirror note); anchors minted at
  group-badge issuance; `revokeStatusAnchor` wired into
  removeMember/deleteGroup/admin-revoke/account-deletion. Bits recorded,
  nothing published yet. Tests: chokepoint coverage per caller, anchor
  uniqueness, kick/re-add anchor separation.
- **Phase 1 — publisher + route + disclosure stamping (Ministry).**
  Allocation in `loadApprovedBadgeJwts` (random index, shard rollover);
  `credentialStatus` option in `reMintVc` (with strip-then-stamp reserved
  handling and the stored-VC strip); publisher job (epoch + jitter +
  heartbeat + version bump), the KMS `≤ 4096` hard assert with a
  worst-case-bits unit test; `GET /status/[listId]` with ETag/304/max-age.
  Tests: full kick→bit→signed-list cycle, rollback vectors (old version,
  expired list, wrong-`sub` list), epoch/jitter timing, allocation
  invisibility (published bytes unchanged by allocation).
- **Phase 2 — SDK (`minister-client`).** `credentialStatus` parse/expose in
  `verifyMinisterBadge` (fail-closed on malformed); `createMinisterStatusChecker`
  with defenses 1–4 (latch, high-water, max-age, URL binding), fail-mode
  knobs, offline tests with injected keys (no network, per the suite's
  contract). Build `dist/`, commit, re-pin consumers. Update the drift
  check.
- **Phase 3 — consumer adoption + e2e.** Discreetly: persist
  `(uri, index)` on badge-gated room grants, 60s revocation sweep, eviction
  on `"revoked"`. Deforum equivalent. Cross-app e2e: add → join room →
  kick → evicted within the bound, with zero user action.
- **Phase 4 — slug tombstone release.** `GroupTombstone` gating in the
  founding action, the pending-publication query, the release job, and
  tests for the ~80-minute floor arithmetic.
- **Phase 5 — follow-ons (ordered, not scheduled).** Renewal job (§6.3 —
  must land within a year of first group-badge issuance); merge aliasing
  (§6.4); backfill runbook for flipping `revocable` on an existing type;
  optional poke webhook; optional B-style audit log under the lists.

Domain floor: Phases 0–2 and 4 are crypto/protocol/correctness work —
`engineer` (opus) minimum to implement, `auditor` review before merge, per
the routing rules.

---

## 9. What the auditor must scrutinize

Correlation:

1. **Allocation invisibility.** Confirm no code path republishes a list on
   allocation (bits must change only on revocation) — otherwise list diffs
   leak disclosure activity, not just revocations.
2. **Flip-timing joins** (§5.7): is `JITTER_MAX = 4 min` defensible against
   the instance's actual revocation volume? Is the jitter drawn
   independently per (event, list) from a CSPRNG, and is `revealAfter`
   enforced by the publisher (not advisory)?
3. **Index randomness**: crypto-random source, uniform over free slots,
   retry logic can't bias toward low indices under contention; shard
   rollover threshold can't be used to infer fill levels externally.
4. **listId capability hygiene**: unguessable, never logged alongside
   clientId in RP-visible surfaces, uniform 404s, no enumeration.
5. **The stable-across-renewal handle** (§5.1/§6.3): verify it truly adds
   no intra-RP linkage beyond the existing stable pairwise `sub`, including
   after account merge and `SubjectOverride`.
6. **Share-link gap** (§5.4): confirm the accepted-residual framing holds —
   no consumer treats a share-link VC as a durable entitlement.

Rollback / freshness:

7. **The latch** (§5.6.4): exact semantics under process restart, cache
   eviction, and multi-instance RPs (is the latch per-process? is that
   acceptable given defense 2?). The in-memory high-water-mark reset on
   restart is a named weakness — is `exp` alone a sufficient floor?
8. **Heartbeat liveness**: a silently dead publisher makes _every_ list go
   stale → with the fail-open default, revocation is silently disabled
   platform-wide while everything else stays green. Alerting on publisher
   lag must be treated as a security control, not ops nicety. Also weigh
   the fail-open default itself (§5.6) against fail-closed-after-cap.
9. **Clock skew** handling on `exp`/`iat` (30s tolerance parity with the
   id_token verifier) and the epoch arithmetic in §7.2's release floor.

Forgery / confusion:

10. **Key choice and pinning**: #key-2 via DID `assertionMethod` only
    (never raw JWKS — the #key-3 exclusion argument in
    `verify-badge.ts` applies identically here); the `sub == fetched URL`
    binding; type-confusion in both directions (badge↔status-list) —
    adversarial JWTs for each direction in the test suite.
11. **The KMS 4096 assert**: prove the worst case (incompressible bits at
    full shard) stays under, and that the failure mode of the assert is
    loud (alert + refuse to publish), never silent truncation or a
    fallback to a weaker key.
12. **`reMintVc` strip-then-stamp** for `credentialStatus`: a stored VC,
    a hostile sanitizer output, and a forged import row must each be unable
    to inject a status pointer into a disclosure.

Bookkeeping:

13. **Allocation races**: concurrent first-disclosures of one badge to one
    RP (unique-violation retry correctness), concurrent shard rollover,
    and the publisher racing `revokeStatusAnchor` (a revocation landing
    mid-publication must appear in that or the next epoch — never lost).
14. **No-index-reuse invariant** under all paths, including group
    deletion, account deletion, and merge aliasing (§6.4) — the alias
    table's revocation fan-out in particular.
15. **Fail-closed omission audit noise**: revocation-driven mint-time
    omissions (layer 1) vs. status-driven RP evictions (layer 2) must be
    distinguishable in audit logs, or a systematic layer-2 failure hides
    inside layer-1 noise.

---

## 10. References

- W3C, _Bitstring Status List v1.0_ — https://www.w3.org/TR/vc-bitstring-status-list/
  (entry/credential shapes, irreversible `revocation` purpose, random index
  recommendation, 131,072-bit default minimum + ecosystem-override clause,
  herd-privacy and malicious-issuer considerations, `ttl` semantics).
- IETF OAuth WG, _Token Status List_, draft-ietf-oauth-status-list —
  https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/
  (`statuslist+jwt`, `ttl`/`exp` caching precedence over HTTP headers).
- RFC 6962, _Certificate Transparency_ (signed heads, monotonicity,
  split-view limits of a trusted-issuer setting).
- Mozilla CRLite / delta-CRL literature (why filter cascades don't fit a
  per-RP KB-scale partition).
- Camenisch & Lysyanskaya, _Dynamic Accumulators and Application to
  Efficient Revocation of Anonymous Credentials_ (CRYPTO '02) —
  https://cs.brown.edu/people/alysyans/papers/camlys02.pdf (why
  accumulator/ZK non-revocation targets a problem the per-RP re-mint model
  doesn't have).
- In-repo: `docs/groups-design.md` (the seam this fills),
  `docs/kms-signing.md` (two-key model, KMS RAW 4096-byte cap),
  `docs/oidc-privacy.md`, `apps/minister/src/lib/oidc-claims.ts`,
  `packages/vc/src/issue.ts` (`reMintVc` reserved-claim discipline),
  `apps/minister/src/lib/pairwise-backend.ts` (per-RP derivation seam),
  `minister-client/src/verify-badge.ts` (DID assertionMethod pinning).
