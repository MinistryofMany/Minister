# Groups — design

Status: draft (v1 scope locked from the 2026-07-12 design discussion; three calls
taken as recommended — short-TTL revocation, loose deep-link provisioning, public
directory deferred to v2). Owner: Tyler. Implementer: Cipher.

## What this is

Anyone with enough of an anti-sybil footing can found a **group** on Ministry.
Belonging to a group is expressed as a **badge** the member holds
(`group-membership`, with the group name and the member's role as claims), so the
whole thing rides Ministry's existing badge + disclosure + policy-gating
machinery. Relying parties (Deforum, Discreetly) gate rooms and sub-forums on
group membership exactly the way they already gate on any other badge.

This turns Ministry from "prove a fact about yourself" into "prove an
affiliation," which is the feature that gives the network gravity and the
clearest path to revenue (paid tiers, purchased names, enterprise sub-groups).

### Goals (v1)

- Found a group (name + display metadata), gated on a minimum anti-sybil bucket,
  capped at 3 owned groups per user.
- Roles: **owner** (one; manage all roles, rename, delete), **admin** (add/remove
  members, promote/demote members), **member**.
- Membership issues a **revocable** `group-membership` badge; removal revokes it.
- Members can gate/create RP surfaces (Discreetly room, Deforum sub-forum) on
  their group via a **deep link** — the RP owns the surface, Ministry only issues
  the badge.

### Non-goals (v1, explicitly deferred)

- **Public `/groups/{name}` member directory** — deferred to v2 (see "Deferred").
  It is the one feature in tension with Ministry's anti-correlation model; ship
  private groups + gating first, add the directory once the correlation story is
  settled.
- Paid tiers (pro = 20 groups, buy-a-name, enterprise sub-groups, custom
  per-group DNS). Design the **framing** now (unverified-by-default names), build
  the tiers later.
- FreedInk (blog) provisioning — FreedInk requests no badge scopes today and
  would need to learn badge-gating first. Deforum + Discreetly only in v1.

## The badge

**One badge type, not one per group.** A single `group-membership` type in
`packages/shared` (mirrored in `@minister/client`), claims:

```jsonc
// credentialSubject
{
  "id": "did:web:ministry.id:users:<userId>",   // the holder's STABLE Minister DID
  "group": "acme",                                // the group's canonical slug
  "role": "owner" | "admin" | "member",
  "groupId": "<opaque group id>"                  // pins the claim to a specific group row
}
```

- `sybilResistance: "none"`, **`sybilWeight: 0`** — HARD requirement. Membership is
  self-asserted by a group's admins; Ministry verifies nothing about it, so it can
  never contribute anti-sybil score. Otherwise "found a group, add 100 sock
  puppets" farms score for free — the exact attack the sybil system exists to
  stop. (The founding _gate_ is what carries the sybil requirement; the members
  gain nothing on the sybil axis.)
- Gating uses the existing policy `where` clause: `{ badge: "group-membership",
where: { group: "acme" } }` for members; `{ ..., where: { group: "acme", role:
"admin" } }` for admins. No new policy machinery.
- `groupId` is included so a renamed or deleted-and-recreated slug can't let a
  stale VC satisfy a gate for a different group under the same name.

## Data model (Prisma)

```prisma
model Group {
  id            String   @id @default(cuid())
  slug          String   @unique             // canonical [a-z0-9-], the badge `group` claim
  displayName   String
  description   String?
  ownerUserId   String
  owner         User     @relation("GroupOwner", fields: [ownerUserId], references: [id])
  verified      Boolean  @default(false)     // false => renders as "unverified" (see Namespace)
  createdAt     DateTime @default(now())
  memberships   GroupMembership[]
  @@index([ownerUserId])
}

model GroupMembership {
  id        String   @id @default(cuid())
  groupId   String
  group     Group    @relation(fields: [groupId], references: [id], onDelete: Cascade)
  userId    String
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  role      String   // "owner" | "admin" | "member"
  isPublic  Boolean  @default(false)          // opt-in to the (v2) public directory; default private
  addedBy   String?                           // acting admin/owner userId, for audit
  createdAt DateTime @default(now())
  @@unique([groupId, userId])
  @@index([userId])
}
```

The owner has both a `Group.ownerUserId` pointer and an owner-role
`GroupMembership` row (so membership queries are uniform). The `User` model gains
`ownedGroups` / `groupMemberships` back-relations.

## Roles and permissions

| Action                                           | member | admin | owner |
| ------------------------------------------------ | ------ | ----- | ----- |
| Hold the membership badge                        | ✓      | ✓     | ✓     |
| Add / remove members                             |        | ✓     | ✓     |
| Promote/demote member↔admin                      |        | ✓     | ✓     |
| Rename, edit description, transfer/demote admins |        |       | ✓     |
| Delete the group                                 |        |       | ✓     |

- One owner per group. Ownership transfer is owner-only (promotes a target to
  owner, demotes self to admin) — v1 can ship without transfer if it's tight;
  flag as a fast-follow.
- Admins cannot remove the owner or other admins (owner-only), preventing an
  admin coup.
- The "admins can be moderators" idea is automatic: RP surfaces gate moderator
  powers on `role: admin` via the same badge claim.

## Membership lifecycle and revocation

Revocation is the one genuinely new requirement — most current badges are "prove
once, keep forever," but kicking a member must actually kill their badge.

**Chosen mechanism: short TTL + re-issue on a live membership check** (rides the
existing `reMintVc` path; no new revocation infra).

- The `group-membership` VC is issued with a **short `exp`** (e.g. 24h).
- At disclosure time (the OIDC re-mint / `verifyMinisterBadges` path), Ministry
  re-checks the live `GroupMembership` row before re-minting. No row (removed) →
  no badge disclosed. Role changed → the re-minted VC carries the new role.
- Net effect: removal takes effect within the TTL window at the RP, and
  immediately for any fresh disclosure. Good enough for v1; a status-list /
  instant-revocation upgrade is a documented future option if the window proves
  too loose.
- Add member → create `GroupMembership` + issue VC. Remove → delete row (next
  disclosure discloses nothing). Role change → update row (next disclosure
  re-mints with the new role). All audit-logged.

## Founding quota and the sybil gate

- **Found a group:** requires anti-sybil bucket **≥ 2** (tunable via the existing
  sybil-config admin surface — do not hardcode; add a `groupFoundingMinBucket`
  config knob) AND fewer than **3** owned groups.
- Hitting the cap: the UI blocks founding and points at "delete or transfer a
  group to free a slot." Deleting a group cascade-deletes memberships (revoking
  every member's badge on their next disclosure).
- Later tiers raise the cap (pro), or sell a name, or unlock enterprise
  sub-groups — all future, all just change the cap / verified flag.

## Namespace and verification (decide the framing now)

Global first-come slugs invite a land-rush (someone grabs `ethereum`, `openai`).
Bake the distinction in conceptually from day one, even though the paid path is
later:

- Every free group is **`verified: false`** and the UI renders it as an
  _unverified_ group (a muted "unverified" affordance next to the name), the way a
  handle differs from a checkmarked one.
- A reserved-slug denylist blocks obvious impersonation targets from free
  founding (configurable).
- `verified: true` is set only through an out-of-band path (admin grant now; a
  paid / org-proof flow later). Custom per-group DNS later is literally `did:web`
  per group, which the issuer model can already express.

## Cross-app provisioning (loose — the load-bearing architectural call)

Ministry does **not** reach into Deforum/Discreetly to create surfaces (that would
mean Ministry holding admin creds to every app and driving them — a coupling and
security mess). Instead:

- Ministry issues the `group-membership` badge; the RPs already gate on badge
  policies.
- "Create a chat for this group" / "create a sub-forum" is a **deep link** into
  the RP's own create flow, pre-filled with the group gate
  (`where: { group: "<slug>" }`). The owner clicks through and owns the surface
  _in the RP_.
- Deforum's create-sub-forum and Discreetly's create-room flows accept a
  pre-filled gating policy via query param (both already have the gating UI; this
  is a prefill + a link, not new gating).
- The group page in Ministry shows "Chat · Forum" quick-create buttons that build
  those deep links.

## Deferred to v2: the public directory

`/groups/{slug}` listing members who set `isPublic = true` on their membership.
Why deferred and what to resolve first:

- A `group-membership` badge's subject is the holder's **stable** Minister DID
  (not a pairwise sub). A public directory therefore lists the same stable DID
  across every group a user makes public — by construction an **affiliation
  graph**, which is what Ministry's pairwise/anti-correlation model exists to
  prevent.
- It is opt-in (per-membership `isPublic`, default false), so it is defensible —
  but it must be a _loud_, deliberate opt-in, and we should state plainly that
  "public group member" means "choosing to be correlatable within the affiliation
  graph."
- v2 work: the correlation UX (warn at opt-in), whether the directory shows the
  stable DID or a group-scoped pseudonym, and rate-limited/enumerable access.

## Security considerations

- **Anti-sybil farming** (primary): `group-membership` = `sybilWeight 0`,
  `sybilResistance none`. Non-negotiable.
- **Revocation window**: short-TTL re-issue means a removed member's badge can
  satisfy a gate for up to the TTL at an RP that cached a disclosure. Acceptable
  for v1; documented; upgrade path noted.
- **Impersonation/squatting**: unverified-by-default framing + reserved denylist.
- **Admin coup**: admins can't remove owner/other admins; owner-only for
  role-of-admins and delete.
- **Quota gaming**: founding gated on sybil bucket (a farmed account can't found);
  member badges grant no sybil score, so groups can't bootstrap sybil score.
- **Audit**: found/delete/rename, add/remove/role-change, and badge issue/revoke
  all audit-logged.

## Implementation plan (phased)

1. **Badge type + data model.** `group-membership` in `packages/shared` (+ zod
   claim schema, sybilWeight 0) and its mirror in `@minister/client`; `Group` /
   `GroupMembership` Prisma models + migration; `groupFoundingMinBucket` config.
2. **Server actions / RBAC core.** found/delete/rename group; add/remove/role
   member; the permission checks; the founding gate (bucket + quota); audit.
3. **Badge issuance + revocation wiring.** issue on add, short-TTL, re-mint live
   check on disclosure, disclose-nothing on removed. Tests for the full
   add→disclose→remove→disclose-nothing cycle.
4. **UI.** group list / create / manage (members, roles), the founding-quota +
   sybil-gate states, the "unverified" affordance.
5. **Deep-link provisioning.** Ministry group-page quick-create buttons; Deforum
   - Discreetly create flows accept a pre-filled group gate via query param.
6. **(v2) public directory** — separate, after the correlation review.

## Open questions (taken as recommended unless Tyler redirects)

1. Revocation: **short-TTL re-issue** (chosen) vs status list. — taken.
2. Public directory: **deferred to v2** (private groups + gating first). — taken.
3. Provisioning: **loose deep-link, RP owns the surface** (chosen) vs Ministry
   drives creation. — taken.
4. Ownership transfer in v1 or fast-follow? — proposed fast-follow.
5. Founding min bucket = 2? — proposed default, config-tunable.
