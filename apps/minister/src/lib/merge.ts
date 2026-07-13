import { Prisma } from "@/generated/prisma";
import { MERGE_REVERSAL_DAYS } from "@/lib/assurance";
import { ensureDedupHandle, nullifierService, runPostCommit } from "@/lib/nullifier";
import { derivePairwiseSubForPersistence } from "@/lib/pairwise-backend";
import { prisma } from "@/lib/prisma";

// Both merge transactions run at RepeatableRead (not the Postgres default READ
// COMMITTED). Under READ COMMITTED every statement takes a fresh snapshot, so a
// donor OidcAccessToken minted for a NEW clientId AFTER the finding-7 drift
// check but before the by-userId re-point (a /token redemption racing the merge)
// would be silently re-pointed to the survivor with no SubjectOverride and no
// precomputed sub — the exact un-preserved-sub outcome the drift check exists to
// abort on. Under RR the drift check and the updateMany share ONE snapshot, so a
// token committed mid-tx is invisible to both and stays on the tombstoned donor
// (the already-known, bounded post-commit class). A write-write conflict
// surfaces as a serialization failure (P2034) the caller retries — consistent
// with the drift check's own "safe to retry" contract. Passed as a short
// identifier so the transaction callback keeps its formatting.
const REPEATABLE_READ: { isolationLevel: Prisma.TransactionIsolationLevel } = {
  isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead,
};

// Both merge transactions read-then-write the same rows under RepeatableRead, so
// a concurrent writer can make Postgres abort the whole transaction with a
// serialization failure — Prisma surfaces it as P2034 and explicitly advises a
// retry. The transaction is fully rolled back on that error (no partial writes),
// and the callback re-reads everything from a fresh snapshot on the next
// attempt, so retrying is safe and idempotent. Bounded so a pathological
// hot-spot can't spin forever: after MAX_TX_ATTEMPTS we rethrow the last P2034
// and let the caller fail the ceremony. Any OTHER error propagates immediately —
// never swallowed, never retried.
const MAX_TX_ATTEMPTS = 5;
const TX_RETRY_BASE_MS = 25;

function isWriteConflict(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2034";
}

// Stable, deduplicated union of two string sets — used to accumulate the
// monotone OidcGrant badgeTypes / badgeIds when a donor grant merges into the
// survivor's grant for a shared RP. Mirrors oidc-grants.ts:unionTypes; kept
// local so the merge core stays independent of the grant module.
function unionStrings(a: readonly string[], b: readonly string[]): string[] {
  return [...new Set([...a, ...b])];
}

async function runWithWriteConflictRetry<T>(run: () => Promise<T>, label: string): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= MAX_TX_ATTEMPTS; attempt++) {
    try {
      return await run();
    } catch (err) {
      if (!isWriteConflict(err)) throw err;
      lastErr = err;
      if (attempt < MAX_TX_ATTEMPTS) {
        // Exponential backoff with jitter (full-jitter over the growing window)
        // so racing retries de-correlate instead of colliding on the same beat.
        const window = TX_RETRY_BASE_MS * 2 ** (attempt - 1);
        const delay = Math.floor(Math.random() * (window + 1));
        console.warn(
          `[merge] ${label} write-conflict (P2034), retry ${attempt}/${MAX_TX_ATTEMPTS}`,
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }
  throw lastErr;
}

// Account merge (slice 5) — the data-reconciliation core. The SECURITY
// dual-control (survivor at AAL2 + a single-use donor-proof) lives one layer up
// in src/server/merge-actions.ts; by the time mergeAccounts runs, the caller has
// already proven control of BOTH accounts. This module does the irreversible-
// looking-but-actually-reversible data surgery in one transaction and records a
// snapshot rich enough to undo it within the reversal window.
//
// Invariants this enforces (DESIGNDECISIONS #11–#13, the spec's slice 5):
//   * Survivor keeps its userId. Donor is tombstoned, never hard-deleted here.
//   * Every userId-FK row the donor owned is re-pointed to the survivor, with
//     explicit collision rules on the two tables that carry a per-user unique.
//   * The pairwise-sub seam (SubjectOverride) is populated so the survivor keeps
//     presenting the donor's historical identity to every RP only the donor
//     used. RPs both accounts used are irreducible: one login → one sub; the
//     donor's sub there is recorded as `stranded`, not silently dropped.
//   * isBanned is sticky-OR; isAdmin is NEVER escalated from the donor.
//   * sessionGeneration is bumped on both (survivor: its credential set changed;
//     donor: kill its live sessions). Donor sessions are deleted.

// ---------------------------------------------------------------------------
// Snapshot shape — the reverse() input
// ---------------------------------------------------------------------------

// Every userId-FK model re-pointed by a plain updateMany. The snapshot records,
// per model, the list of PK selectors of the rows that moved, so reversal can
// move exactly those rows back (and only those — not rows the survivor already
// owned). PK selectors are stored as the field(s) Prisma needs in a `where` to
// re-target a single row.
export interface MovedRows {
  // Models keyed by a single `id` PK.
  badge: string[];
  shareLink: string[];
  oidcAccessToken: string[]; // keyed by jti
  wizardSession: string[];
  recoveryCode: string[];
  recoveryAttempt: string[];
  userEmail: string[];
  // AuditLog.userId is nullable (no relation) but we still re-point the donor's
  // rows so the survivor inherits the donor's history.
  auditLog: string[];
  // Composite-PK models.
  account: Array<{ provider: string; providerAccountId: string }>;
  session: string[]; // keyed by sessionToken
  authenticator: Array<{ userId: string; credentialID: string }>; // userId here is the DONOR's (pre-move)
  subjectOverride: Array<{ clientId: string }>; // donor's own SubjectOverride rows, re-pointed
  inviteRedemption: string[];
  eligibility: string[];
  // OidcClient.ownerUserId — re-pointed (nullable owner FK).
  oidcClientOwned: string[];
  // OidcGrant rows re-pointed wholesale (donor-only clients: the survivor had
  // no grant for that clientId). Keyed by clientId — reversal moves the
  // (survivorUserId, clientId) row back to the donor. Optional so a snapshot
  // written before OidcGrant merge handling existed reverses without it.
  oidcGrant?: string[];
}

// The union-mergeable fields of an OidcGrant, captured for reversible merges.
interface OidcGrantFields {
  badgeTypes: string[];
  badgeIds: string[];
  profileName: boolean;
  profileAvatar: boolean;
  sybilScore: boolean;
}

export interface MergeSnapshot {
  version: 1;
  survivorUserId: string;
  donorUserId: string;
  movedAt: string;
  moved: MovedRows;
  // Collision losers we DELETED (so reversal can recreate them). Full row data,
  // because the row no longer exists to copy from.
  eligibilityDeleted: Array<{
    id: string;
    userId: string;
    badgeType: string;
    eligibleAt: string;
    fuzzDays: number;
    source: string;
  }>;
  inviteRedemptionDeleted: Array<{
    id: string;
    inviteCodeId: string;
    userId: string;
    redeemedAt: string;
  }>;
  // SubjectOverride rows CREATED on the survivor for donor-only clients. Reversal
  // deletes exactly these (and not any the survivor already had).
  overridesCreated: Array<{ clientId: string; sub: string }>;
  // OidcGrant collisions: BOTH accounts held a grant for the clientId, so the
  // donor's was union-OR'd into the survivor's and the donor row deleted.
  // Reversal restores the survivor's pre-merge grant state and recreates the
  // donor's deleted row (with its original id). Optional for pre-change snapshots.
  oidcGrantMerged?: Array<{
    clientId: string;
    survivorPrev: OidcGrantFields;
    donorDeleted: OidcGrantFields & { id: string };
  }>;
  // Clients BOTH accounts used: the donor's sub there is stranded (one login,
  // one sub). Carried for the UI + audit; nothing to undo.
  strandedClients: Array<{ clientId: string; donorSub: string }>;
  // Flag + cache state to restore on reversal.
  survivorPrev: {
    isBanned: boolean;
    sessionGeneration: number;
    email: string | null;
  };
  donorPrev: {
    sessionGeneration: number;
  };
  // UserEmails demoted from primary on the donor so the survivor keeps exactly
  // one primary. Reversal re-promotes them (they're re-pointed back to the donor
  // on un-merge, but restoring isPrimary makes the donor whole).
  demotedPrimaryEmailIds: string[];
  // Sybil-dedup ledger entry refs the donor held, re-tagged to the survivor's
  // owner handle POST-COMMIT. reverseMerge re-tags EXACTLY these back to the
  // donor. Optional for backward compatibility with pre-Phase-1 snapshots.
  dedupReassigned?: string[];
}

export interface MergeSummary {
  mergeRecordId: string;
  moved: Record<string, number>;
  overridesCreated: number;
  strandedClients: string[];
}

// ---------------------------------------------------------------------------
// mergeAccounts
// ---------------------------------------------------------------------------

// Reconcile `donorUserId` INTO `survivorUserId` in one transaction and tombstone
// the donor. Returns a summary including the stranded-RP list for the caller to
// surface. Throws if either user is missing, if they're the same, or if the
// donor is already tombstoned (a second merge of an already-merged donor is a
// caller bug, not a recoverable state).
export async function mergeAccounts(
  survivorUserId: string,
  donorUserId: string,
): Promise<MergeSummary> {
  if (survivorUserId === donorUserId) {
    throw new Error("Cannot merge an account into itself");
  }

  const now = new Date();

  // §2.6: the donor-sub derivations route through the Phase 7 pairwise seam,
  // which is a Signet mTLS round-trip under the shadow/signet-fallback/signet
  // backends. They are PRE-COMPUTED here, BEFORE the transaction opens — no
  // PRF/pairwise network call may run inside an open prisma.$transaction.
  // Collect the donor's token clientIds, resolve their subs (awaiting the seam),
  // then transact. (Finding 7 below re-reads the client set inside the tx and
  // aborts on any drift in this gap.)
  //
  // `derivePairwiseSubForPersistence` (not the plain seam) because these subs
  // are FROZEN into SubjectOverride: resolveSub's override short-circuit means a
  // wrong value could never later self-heal. While the local secret is present
  // it byte-crosschecks the served sub against the golden truth and throws on
  // divergence (merge aborts fail-closed, safe to retry) rather than permanently
  // re-keying the donor's identity at an RP on a transient/compromised Signet.
  const donorTokenClients = await prisma.oidcAccessToken.findMany({
    where: { userId: donorUserId },
    select: { clientId: true },
    distinct: ["clientId"],
  });
  const donorSubByClient = new Map<string, string>(
    await Promise.all(
      donorTokenClients.map(
        async (r) =>
          [r.clientId, await derivePairwiseSubForPersistence(donorUserId, r.clientId)] as const,
      ),
    ),
  );

  // RepeatableRead (see REPEATABLE_READ above) closes the in-tx token-drift
  // window between the finding-7 check and the by-userId re-point. A concurrent
  // writer that trips a P2034 serialization failure is retried with bounded
  // backoff (runWithWriteConflictRetry) — the whole tx rolls back and re-runs
  // from a fresh snapshot, which is exactly the "safe to retry" contract the
  // drift check and Finding 7 already assume.
  const runMergeTx = async (tx: Prisma.TransactionClient) => {
    const survivor = await tx.user.findUnique({
      where: { id: survivorUserId },
      select: {
        id: true,
        isBanned: true,
        isAdmin: true,
        sessionGeneration: true,
        email: true,
        dedupHandle: true,
      },
    });
    const donor = await tx.user.findUnique({
      where: { id: donorUserId },
      select: {
        id: true,
        isBanned: true,
        isAdmin: true,
        sessionGeneration: true,
        mergedIntoUserId: true,
        dedupHandle: true,
      },
    });
    if (!survivor) throw new Error(`Survivor account ${survivorUserId} not found`);
    if (!donor) throw new Error(`Donor account ${donorUserId} not found`);
    if (donor.mergedIntoUserId !== null) {
      throw new Error(`Donor account ${donorUserId} is already merged (tombstoned)`);
    }

    // Finding 7 — donor-sub precompute drift. `donorSubByClient` was resolved
    // BEFORE the transaction (§2.6: no PRF/nullifier network call inside an open
    // tx). A donor token minted for a NEW clientId in that gap would be
    // re-pointed to the survivor below with NO SubjectOverride / stranded record
    // and no precomputed sub — the survivor would silently present an
    // un-preserved sub to that RP. Re-read the donor's distinct token clients
    // inside the tx and abort on ANY drift; the merge is safe to retry.
    const donorTokenClientsInTx = await tx.oidcAccessToken.findMany({
      where: { userId: donorUserId },
      select: { clientId: true },
      distinct: ["clientId"],
    });
    const precomputedClientIds = new Set(donorTokenClients.map((r) => r.clientId));
    const currentClientIds = donorTokenClientsInTx.map((r) => r.clientId);
    if (
      currentClientIds.length !== precomputedClientIds.size ||
      currentClientIds.some((c) => !precomputedClientIds.has(c))
    ) {
      throw new Error(
        "merge: donor OIDC token clients changed between sub precompute and transaction — aborting (safe to retry)",
      );
    }

    // -----------------------------------------------------------------------
    // (b-pre) Capture the subject-override seam inputs BEFORE re-pointing the
    // OidcAccessToken rows — re-pointing fuses the donor's and survivor's token
    // history and would erase the donor-only/shared distinction. The donor
    // clientIds + their subs were resolved BEFORE the transaction (§2.6).
    // -----------------------------------------------------------------------
    const survivorTokenClients = await tx.oidcAccessToken.findMany({
      where: { userId: survivorUserId },
      select: { clientId: true },
      distinct: ["clientId"],
    });
    // The survivor's existing SubjectOverride clients count as "the survivor
    // already presents a sub there" — a prior merge could have populated them.
    const survivorExistingOverrides = await tx.subjectOverride.findMany({
      where: { userId: survivorUserId },
      select: { clientId: true },
    });
    const survivorUsedClients = new Set<string>([
      ...survivorTokenClients.map((r) => r.clientId),
      ...survivorExistingOverrides.map((r) => r.clientId),
    ]);

    const overridesCreated: MergeSnapshot["overridesCreated"] = [];
    const strandedClients: MergeSnapshot["strandedClients"] = [];
    for (const { clientId } of donorTokenClients) {
      // Pre-computed before the transaction (§2.6) — never derived in-tx.
      const donorSub = donorSubByClient.get(clientId)!;
      if (survivorUsedClients.has(clientId)) {
        // Shared RP: the survivor already presents a sub here; the donor's is
        // irreducibly stranded (one login → one sub).
        strandedClients.push({ clientId, donorSub });
      } else {
        // Donor-only RP: write an override so the survivor keeps presenting the
        // donor's historical pairwise identity to this RP.
        overridesCreated.push({ clientId, sub: donorSub });
      }
    }

    // -----------------------------------------------------------------------
    // (snapshot pre-reads) Capture the donor row PKs we're about to move, and
    // the collision losers we're about to delete, so the merge is reversible.
    // -----------------------------------------------------------------------
    const [
      donorBadges,
      donorShareLinks,
      donorTokens,
      donorWizards,
      donorRecoveryCodes,
      donorRecoveryAttempts,
      donorEmails,
      donorAuditLogs,
      donorAccounts,
      donorSessions,
      donorAuthenticators,
      donorOwnOverrides,
      donorOwnedClients,
    ] = await Promise.all([
      tx.badge.findMany({
        where: { userId: donorUserId },
        select: { id: true, nullifierRef: true },
      }),
      tx.shareLink.findMany({ where: { userId: donorUserId }, select: { id: true } }),
      tx.oidcAccessToken.findMany({ where: { userId: donorUserId }, select: { jti: true } }),
      tx.wizardSession.findMany({ where: { userId: donorUserId }, select: { id: true } }),
      tx.recoveryCode.findMany({ where: { userId: donorUserId }, select: { id: true } }),
      tx.recoveryAttempt.findMany({ where: { userId: donorUserId }, select: { id: true } }),
      tx.userEmail.findMany({
        where: { userId: donorUserId },
        select: { id: true, isPrimary: true },
      }),
      tx.auditLog.findMany({ where: { userId: donorUserId }, select: { id: true } }),
      tx.account.findMany({
        where: { userId: donorUserId },
        select: { provider: true, providerAccountId: true },
      }),
      tx.session.findMany({ where: { userId: donorUserId }, select: { sessionToken: true } }),
      tx.authenticator.findMany({
        where: { userId: donorUserId },
        select: { credentialID: true },
      }),
      tx.subjectOverride.findMany({
        where: { userId: donorUserId },
        select: { clientId: true },
      }),
      tx.oidcClient.findMany({ where: { ownerUserId: donorUserId }, select: { id: true } }),
    ]);

    // -----------------------------------------------------------------------
    // (a) Re-point the simple userId-FK models donor → survivor.
    //
    // NOTE on Eligibility / InviteRedemption: these carry a per-user unique
    // (@@unique([userId, badgeType]) / @@unique([inviteCodeId, userId])), so a
    // blind updateMany would throw on a collision. We resolve collisions FIRST
    // (delete the loser per the spec rules), then move the survivors.
    // -----------------------------------------------------------------------

    // Eligibility collision: keep the row with the EARLIER eligibleAt; delete the
    // loser. For each badgeType the donor holds that the survivor ALSO holds, one
    // of the two is deleted before the move so the move can't collide.
    const donorEligibilities = await tx.eligibility.findMany({
      where: { userId: donorUserId },
      select: { id: true, badgeType: true, eligibleAt: true, fuzzDays: true, source: true },
    });
    const survivorEligibilities = await tx.eligibility.findMany({
      where: { userId: survivorUserId },
      select: { id: true, badgeType: true, eligibleAt: true },
    });
    const survivorEligByType = new Map(survivorEligibilities.map((e) => [e.badgeType, e]));
    const eligibilityDeleted: MergeSnapshot["eligibilityDeleted"] = [];
    const eligibilityToMove: string[] = [];
    for (const d of donorEligibilities) {
      const s = survivorEligByType.get(d.badgeType);
      if (!s) {
        // No collision — this one moves.
        eligibilityToMove.push(d.id);
        continue;
      }
      // Collision: keep the earlier eligibleAt.
      if (d.eligibleAt.getTime() < s.eligibleAt.getTime()) {
        // Donor's is earlier → it wins. Delete the survivor's, then move donor's.
        eligibilityDeleted.push({
          id: s.id,
          userId: survivorUserId,
          badgeType: d.badgeType,
          // Re-read survivor's full row for a faithful restore.
          eligibleAt: "", // filled below
          fuzzDays: 0,
          source: "",
        });
        eligibilityToMove.push(d.id);
      } else {
        // Survivor's is earlier-or-equal → keep it. Delete the donor's.
        eligibilityDeleted.push({
          id: d.id,
          userId: donorUserId,
          badgeType: d.badgeType,
          eligibleAt: d.eligibleAt.toISOString(),
          fuzzDays: d.fuzzDays,
          source: d.source,
        });
      }
    }
    // For survivor-row deletes we need their full data for restore; re-read them.
    const survivorEligDeleteIds = eligibilityDeleted
      .filter((e) => e.userId === survivorUserId)
      .map((e) => e.id);
    if (survivorEligDeleteIds.length > 0) {
      const fullSurvivorRows = await tx.eligibility.findMany({
        where: { id: { in: survivorEligDeleteIds } },
        select: { id: true, eligibleAt: true, fuzzDays: true, source: true },
      });
      const byId = new Map(fullSurvivorRows.map((r) => [r.id, r]));
      for (const e of eligibilityDeleted) {
        if (e.userId !== survivorUserId) continue;
        const full = byId.get(e.id);
        if (full) {
          e.eligibleAt = full.eligibleAt.toISOString();
          e.fuzzDays = full.fuzzDays;
          e.source = full.source;
        }
      }
    }
    // Apply the eligibility deletes, then move the donor survivors.
    if (eligibilityDeleted.length > 0) {
      await tx.eligibility.deleteMany({
        where: { id: { in: eligibilityDeleted.map((e) => e.id) } },
      });
    }
    if (eligibilityToMove.length > 0) {
      await tx.eligibility.updateMany({
        where: { id: { in: eligibilityToMove } },
        data: { userId: survivorUserId },
      });
    }

    // InviteRedemption collision: keep one (the code is already spent), delete the
    // duplicate. Unique is (inviteCodeId, userId): a collision is the donor and
    // survivor having redeemed the SAME inviteCodeId. Keep the survivor's, delete
    // the donor's; move the donor's non-colliding ones.
    const donorRedemptions = await tx.inviteRedemption.findMany({
      where: { userId: donorUserId },
      select: { id: true, inviteCodeId: true, redeemedAt: true },
    });
    const survivorRedemptions = await tx.inviteRedemption.findMany({
      where: { userId: survivorUserId },
      select: { inviteCodeId: true },
    });
    const survivorCodeIds = new Set(survivorRedemptions.map((r) => r.inviteCodeId));
    const inviteRedemptionDeleted: MergeSnapshot["inviteRedemptionDeleted"] = [];
    const inviteRedemptionToMove: string[] = [];
    for (const d of donorRedemptions) {
      if (survivorCodeIds.has(d.inviteCodeId)) {
        // Collision — survivor already redeemed this code; drop the donor's dup.
        inviteRedemptionDeleted.push({
          id: d.id,
          inviteCodeId: d.inviteCodeId,
          userId: donorUserId,
          redeemedAt: d.redeemedAt.toISOString(),
        });
      } else {
        inviteRedemptionToMove.push(d.id);
      }
    }
    if (inviteRedemptionDeleted.length > 0) {
      await tx.inviteRedemption.deleteMany({
        where: { id: { in: inviteRedemptionDeleted.map((r) => r.id) } },
      });
    }
    if (inviteRedemptionToMove.length > 0) {
      await tx.inviteRedemption.updateMany({
        where: { id: { in: inviteRedemptionToMove } },
        data: { userId: survivorUserId },
      });
    }

    // The collision-free re-points. Badge has no per-user unique, so all move.
    await tx.account.updateMany({
      where: { userId: donorUserId },
      data: { userId: survivorUserId },
    });
    await tx.session.updateMany({
      where: { userId: donorUserId },
      data: { userId: survivorUserId },
    });
    await tx.authenticator.updateMany({
      where: { userId: donorUserId },
      data: { userId: survivorUserId },
    });
    await tx.badge.updateMany({ where: { userId: donorUserId }, data: { userId: survivorUserId } });
    await tx.shareLink.updateMany({
      where: { userId: donorUserId },
      data: { userId: survivorUserId },
    });
    await tx.oidcAccessToken.updateMany({
      where: { userId: donorUserId },
      data: { userId: survivorUserId },
    });
    await tx.wizardSession.updateMany({
      where: { userId: donorUserId },
      data: { userId: survivorUserId },
    });
    await tx.auditLog.updateMany({
      where: { userId: donorUserId },
      data: { userId: survivorUserId },
    });
    await tx.userEmail.updateMany({
      where: { userId: donorUserId },
      data: { userId: survivorUserId },
    });
    await tx.recoveryCode.updateMany({
      where: { userId: donorUserId },
      data: { userId: survivorUserId },
    });
    await tx.recoveryAttempt.updateMany({
      where: { userId: donorUserId },
      data: { userId: survivorUserId },
    });
    // The donor's OWN SubjectOverride rows (from a prior merge into the donor)
    // re-point to the survivor too. A collision on the composite PK (survivor
    // already has an override for the same clientId) keeps the survivor's: skip
    // the donor's for those clients (they'd be stranded — already captured above
    // when the donor's token clients overlap, but an override-only overlap is
    // handled here).
    for (const ov of donorOwnOverrides) {
      const collides = survivorExistingOverrides.some((s) => s.clientId === ov.clientId);
      if (collides) continue;
      await tx.subjectOverride.update({
        where: { userId_clientId: { userId: donorUserId, clientId: ov.clientId } },
        data: { userId: survivorUserId },
      });
    }
    // OidcClient ownership.
    await tx.oidcClient.updateMany({
      where: { ownerUserId: donorUserId },
      data: { ownerUserId: survivorUserId },
    });

    // -----------------------------------------------------------------------
    // (a2) OidcGrant — the durable per-(userId, clientId) "already proven these
    // badge types / profile claims to this RP" consent-transparency record. The
    // merge core predates this model, so without this block the donor's grants
    // stay orphaned on the tombstoned donor and are lost. For a client the
    // survivor never used, re-point the whole donor grant. For a SHARED client,
    // union-OR the donor's grant into the survivor's (@@unique([userId,clientId])
    // forbids a blind re-point) and delete the donor's row — snapshotting both
    // sides so reverseMerge can split them back apart.
    // -----------------------------------------------------------------------
    const donorGrants = await tx.oidcGrant.findMany({
      where: { userId: donorUserId },
      select: {
        id: true,
        clientId: true,
        badgeTypes: true,
        badgeIds: true,
        profileName: true,
        profileAvatar: true,
        sybilScore: true,
      },
    });
    const survivorGrants = await tx.oidcGrant.findMany({
      where: { userId: survivorUserId },
      select: {
        clientId: true,
        badgeTypes: true,
        badgeIds: true,
        profileName: true,
        profileAvatar: true,
        sybilScore: true,
      },
    });
    const survivorGrantByClient = new Map(survivorGrants.map((g) => [g.clientId, g]));
    const oidcGrantMoved: string[] = [];
    const oidcGrantMerged: NonNullable<MergeSnapshot["oidcGrantMerged"]> = [];
    for (const dg of donorGrants) {
      const sg = survivorGrantByClient.get(dg.clientId);
      if (!sg) {
        // Donor-only client: re-point the whole grant to the survivor.
        await tx.oidcGrant.update({
          where: { userId_clientId: { userId: donorUserId, clientId: dg.clientId } },
          data: { userId: survivorUserId },
        });
        oidcGrantMoved.push(dg.clientId);
      } else {
        // Shared client: union-OR the donor's grant into the survivor's, then
        // drop the donor's row. Snapshot the survivor's PRE-merge state + the
        // donor's full deleted row so reverse restores the exact split.
        oidcGrantMerged.push({
          clientId: dg.clientId,
          survivorPrev: {
            badgeTypes: sg.badgeTypes,
            badgeIds: sg.badgeIds,
            profileName: sg.profileName,
            profileAvatar: sg.profileAvatar,
            sybilScore: sg.sybilScore,
          },
          donorDeleted: {
            id: dg.id,
            badgeTypes: dg.badgeTypes,
            badgeIds: dg.badgeIds,
            profileName: dg.profileName,
            profileAvatar: dg.profileAvatar,
            sybilScore: dg.sybilScore,
          },
        });
        await tx.oidcGrant.update({
          where: { userId_clientId: { userId: survivorUserId, clientId: dg.clientId } },
          data: {
            badgeTypes: { set: unionStrings(sg.badgeTypes, dg.badgeTypes) },
            badgeIds: { set: unionStrings(sg.badgeIds, dg.badgeIds) },
            profileName: sg.profileName || dg.profileName,
            profileAvatar: sg.profileAvatar || dg.profileAvatar,
            sybilScore: sg.sybilScore || dg.sybilScore,
          },
        });
        await tx.oidcGrant.deleteMany({
          where: { userId: donorUserId, clientId: dg.clientId },
        });
      }
    }

    // -----------------------------------------------------------------------
    // (a3) Donor OIDC authorization codes — DELETE, never re-point. A donor
    // auth code minted seconds before the merge would otherwise still redeem at
    // /token AFTER the donor is tombstoned, minting a live token on a dead
    // account (the /token tombstone check is the second closure of this gap).
    // Codes are single-use, 60s-TTL, and worthless by the reversal window, so
    // deletion is correct and needs no reverse-side restore.
    // -----------------------------------------------------------------------
    const deletedAuthCodes = await tx.oidcAuthorizationCode.deleteMany({
      where: { userId: donorUserId },
    });

    // -----------------------------------------------------------------------
    // (b) Write the SubjectOverride rows for donor-only clients.
    // -----------------------------------------------------------------------
    for (const ov of overridesCreated) {
      await tx.subjectOverride.create({
        data: { userId: survivorUserId, clientId: ov.clientId, sub: ov.sub },
      });
    }

    // -----------------------------------------------------------------------
    // (c) Flags + the single-primary-email invariant.
    // -----------------------------------------------------------------------
    // Exactly one isPrimary UserEmail on the survivor: keep the survivor's
    // primary, demote every email that just moved over from the donor that was
    // primary on the donor side.
    const demotedPrimaryEmailIds = donorEmails.filter((e) => e.isPrimary).map((e) => e.id);
    if (demotedPrimaryEmailIds.length > 0) {
      await tx.userEmail.updateMany({
        where: { id: { in: demotedPrimaryEmailIds } },
        data: { isPrimary: false },
      });
    }

    await tx.user.update({
      where: { id: survivorUserId },
      data: {
        // Sticky-OR ban; isAdmin untouched (never escalated from donor).
        isBanned: survivor.isBanned || donor.isBanned,
        // Bump so the survivor's other sessions re-load the new credential set.
        sessionGeneration: { increment: 1 },
        // email cache: keep the survivor's existing primary cache. (The survivor
        // keeps its own isPrimary email; nothing to change.)
      },
    });

    // -----------------------------------------------------------------------
    // (d) Tombstone the donor.
    // -----------------------------------------------------------------------
    // Delete the donor's sessions: they were re-pointed to the survivor above,
    // so "donor sessions" no longer exist as donor rows — but kill any that the
    // re-point left (none) and bump the donor gen so any cached JWT for the donor
    // is rejected. The donor's Session rows moved to the survivor by design (the
    // human is the same); deleting them instead would log the survivor out of
    // the donor's still-open tabs. We keep them (re-pointed) and rely on the
    // tombstone for "the donor can't be signed into" — getCurrentSession rejects
    // a session whose user is tombstoned only by mergedIntoUserId on the USER,
    // and the user is now the survivor, so those tabs stay valid as the survivor.
    await tx.user.update({
      where: { id: donorUserId },
      data: {
        mergedIntoUserId: survivorUserId,
        mergedAt: now,
        sessionGeneration: { increment: 1 },
      },
    });

    // -----------------------------------------------------------------------
    // (e) MergeRecord with the reversal snapshot.
    // -----------------------------------------------------------------------
    const moved: MovedRows = {
      badge: donorBadges.map((r) => r.id),
      shareLink: donorShareLinks.map((r) => r.id),
      oidcAccessToken: donorTokens.map((r) => r.jti),
      wizardSession: donorWizards.map((r) => r.id),
      recoveryCode: donorRecoveryCodes.map((r) => r.id),
      recoveryAttempt: donorRecoveryAttempts.map((r) => r.id),
      userEmail: donorEmails.map((r) => r.id),
      auditLog: donorAuditLogs.map((r) => r.id),
      account: donorAccounts.map((r) => ({
        provider: r.provider,
        providerAccountId: r.providerAccountId,
      })),
      session: donorSessions.map((r) => r.sessionToken),
      authenticator: donorAuthenticators.map((r) => ({
        userId: donorUserId,
        credentialID: r.credentialID,
      })),
      subjectOverride: donorOwnOverrides
        .filter((ov) => !survivorExistingOverrides.some((s) => s.clientId === ov.clientId))
        .map((ov) => ({ clientId: ov.clientId })),
      inviteRedemption: inviteRedemptionToMove,
      eligibility: eligibilityToMove,
      oidcClientOwned: donorOwnedClients.map((r) => r.id),
      oidcGrant: oidcGrantMoved,
    };

    // Sybil-dedup refs the donor holds — re-tagged to the survivor POST-COMMIT
    // (§2.6), recorded so reverseMerge can re-tag exactly these back.
    const dedupReassigned = donorBadges
      .map((b) => b.nullifierRef)
      .filter((r): r is string => typeof r === "string");

    const snapshot: MergeSnapshot = {
      version: 1,
      survivorUserId,
      donorUserId,
      movedAt: now.toISOString(),
      moved,
      eligibilityDeleted,
      inviteRedemptionDeleted,
      overridesCreated,
      oidcGrantMerged,
      strandedClients,
      survivorPrev: {
        isBanned: survivor.isBanned,
        sessionGeneration: survivor.sessionGeneration,
        email: survivor.email,
      },
      donorPrev: {
        sessionGeneration: donor.sessionGeneration,
      },
      demotedPrimaryEmailIds,
      dedupReassigned,
    };

    const record = await tx.mergeRecord.create({
      data: {
        survivorUserId,
        donorUserId,
        snapshot: snapshot as unknown as Prisma.InputJsonValue,
        reversibleUntil: new Date(now.getTime() + MERGE_REVERSAL_DAYS * 24 * 60 * 60 * 1000),
      },
      select: { id: true },
    });

    const movedCounts: Record<string, number> = {
      account: moved.account.length,
      session: moved.session.length,
      authenticator: moved.authenticator.length,
      badge: moved.badge.length,
      shareLink: moved.shareLink.length,
      oidcAccessToken: moved.oidcAccessToken.length,
      wizardSession: moved.wizardSession.length,
      auditLog: moved.auditLog.length,
      userEmail: moved.userEmail.length,
      recoveryCode: moved.recoveryCode.length,
      recoveryAttempt: moved.recoveryAttempt.length,
      subjectOverride: moved.subjectOverride.length,
      inviteRedemption: moved.inviteRedemption.length,
      eligibility: moved.eligibility.length,
      oidcClientOwned: moved.oidcClientOwned.length,
      oidcGrant: oidcGrantMoved.length,
      oidcGrantMerged: oidcGrantMerged.length,
      oidcAuthorizationCodeDeleted: deletedAuthCodes.count,
      eligibilityDeleted: eligibilityDeleted.length,
      inviteRedemptionDeleted: inviteRedemptionDeleted.length,
    };

    return {
      summary: {
        mergeRecordId: record.id,
        moved: movedCounts,
        overridesCreated: overridesCreated.length,
        strandedClients: strandedClients.map((c) => c.clientId),
      },
      // Post-commit reassign inputs. donorHandle is non-null whenever the donor
      // registered any of these refs; survivorHandle may be null (minted below).
      reassign: {
        entryRefs: dedupReassigned,
        donorHandle: donor.dedupHandle,
      },
    };
  };
  const txResult = await runWithWriteConflictRetry(
    () => prisma.$transaction(runMergeTx, REPEATABLE_READ),
    "mergeAccounts",
  );

  // §2.6 post-commit: re-tag the donor's dedup ledger entries to the survivor.
  // Runs AFTER the transaction commits, with idempotent retry; a failure leaves
  // entries under the donor handle (conservative — never a dedup bypass) for
  // admin reconcile, and never fails the merge.
  const { entryRefs, donorHandle } = txResult.reassign;
  if (entryRefs.length > 0 && donorHandle) {
    await runPostCommit(async () => {
      // Mint the survivor's receiving handle INSIDE the post-commit op: the
      // merge transaction has already committed, so a mint failure here must be
      // retried/swallowed like the reassign itself — never allowed to reject a
      // completed merge (which would tell the caller a committed merge failed).
      const survivorHandle = await ensureDedupHandle(survivorUserId);
      await nullifierService.reassignOwner({
        entryRefs,
        fromOwnerHandle: donorHandle,
        toOwnerHandle: survivorHandle,
      });
    }, "reassign-on-merge");
  }

  return txResult.summary;
}

// ---------------------------------------------------------------------------
// reverseMerge
// ---------------------------------------------------------------------------

export interface ReverseResult {
  ok: boolean;
  // What was restored, for the caller/audit. `restoredRows` is the count of
  // moved-row models pushed back to the donor; `recreatedDeleted` counts
  // collision losers recreated.
  restoredRows?: number;
  recreatedDeleted?: number;
  error?: string;
}

// Undo a merge from its snapshot, while still inside the reversal window.
//
// WHAT THIS RESTORES (fully):
//   * Un-tombstones the donor (clears mergedIntoUserId/mergedAt) and bumps both
//     users' sessionGeneration again (the credential sets are changing back).
//   * Restores the survivor's prior isBanned flag (the sticky-OR is undone).
//   * Removes the SubjectOverride rows this merge CREATED for donor-only clients
//     (so the survivor stops presenting the donor's identity). Overrides the
//     survivor already had are untouched.
//   * Moves every re-pointed row back to the donor: Account, Session,
//     Authenticator, Badge, ShareLink, OidcAccessToken, WizardSession, AuditLog,
//     UserEmail, RecoveryCode, RecoveryAttempt, the donor's own SubjectOverrides,
//     re-pointed InviteRedemptions and Eligibilities, OidcClient ownership, and
//     donor-only OidcGrants — identified by the exact PK list captured in the
//     snapshot, so only rows that actually moved are moved back (survivor-native
//     rows are never touched).
//   * Re-promotes the donor's demoted primary email(s).
//   * Recreates the collision LOSERS that were deleted (Eligibility /
//     InviteRedemption) with their original data, so the donor (or survivor) gets
//     its row back. For a shared-client OidcGrant that was union-merged, restores
//     the survivor's pre-merge grant and recreates the donor's deleted grant.
//
// WHAT THIS INTENTIONALLY DOES NOT RESTORE:
//   * The donor's deleted OidcAuthorizationCodes: single-use, 60s-TTL codes are
//     long dead by the reversal window, so there is nothing worth recreating.
//
// WHAT THIS DOES NOT (and CANNOT) RESTORE — called out, not faked:
//   * STRANDED-CLIENT subs are not "restored" because nothing about them was
//     changed at merge time: for an RP both accounts used, the donor's sub there
//     was never written anywhere (it's derivable from the donor's userId via
//     pairwiseSub). Un-tombstoning the donor makes that sub derivable again, so
//     reversal does restore the donor's access to shared RPs implicitly — there
//     is no stored state to undo.
//   * Authenticator PRIMARY-KEY identity: an Authenticator's PK is
//     (userId, credentialID). The merge changed userId from donor→survivor. We
//     captured (donorUserId, credentialID) and move it back to the donor by
//     credentialID, which is itself @unique — so the move-back is exact.
//   * Rows the donor created AFTER the merge as the survivor are NOT separated
//     back out (there is no donor session post-merge, so in practice none exist),
//     and any survivor-side mutation to a moved row's CONTENT (not its owner) is
//     preserved as-is on the row when it moves back. Reversal restores OWNERSHIP
//     and the deleted losers; it does not snapshot-and-restore row CONTENTS.
//
// Returns ok:false (no throw) when the record is missing, already reversed, or
// past its window — the caller surfaces a friendly message.
export async function reverseMerge(mergeRecordId: string): Promise<ReverseResult> {
  const record = await prisma.mergeRecord.findUnique({
    where: { id: mergeRecordId },
    select: { id: true, snapshot: true, reversedAt: true, reversibleUntil: true },
  });
  if (!record) return { ok: false, error: "Merge record not found" };
  // `!= null` covers both a real reversedAt timestamp and any non-null marker;
  // a not-yet-reversed record has reversedAt === null.
  if (record.reversedAt != null) return { ok: false, error: "This merge was already reversed" };
  if (record.reversibleUntil.getTime() <= Date.now()) {
    return { ok: false, error: "The reversal window for this merge has passed" };
  }

  const snap = record.snapshot as unknown as MergeSnapshot;
  if (!snap || snap.version !== 1) {
    return { ok: false, error: "Merge snapshot is missing or unsupported" };
  }

  const { survivorUserId, donorUserId } = snap;
  const dedupReassigned = snap.dedupReassigned ?? [];

  // RepeatableRead to match mergeAccounts (see REPEATABLE_READ above): reversal
  // re-points rows back to the donor by the exact snapshot PK lists under one
  // snapshot; a serialization failure is a retryable P2034 (runWithWriteConflictRetry)
  // and reversal is idempotent-guarded above (the reversedAt check + the exact
  // PK lists make a re-run a no-op once it has committed).
  const runReverseTx = async (tx: Prisma.TransactionClient) => {
    // Guard: the donor must still be tombstoned INTO this survivor. If something
    // else changed the donor in the meantime, refuse rather than corrupt state.
    const donor = await tx.user.findUnique({
      where: { id: donorUserId },
      select: { mergedIntoUserId: true, dedupHandle: true },
    });
    if (!donor || donor.mergedIntoUserId !== survivorUserId) {
      return {
        result: {
          ok: false as const,
          error: "Donor account is no longer in the merged state this record describes",
        },
        reassign: null,
      };
    }
    const survivor = await tx.user.findUnique({
      where: { id: survivorUserId },
      select: { dedupHandle: true },
    });

    let restoredRows = 0;
    const m = snap.moved;

    // Move ownership back to the donor, per the exact captured PK lists.
    if (m.badge.length) {
      restoredRows += (
        await tx.badge.updateMany({
          where: { id: { in: m.badge } },
          data: { userId: donorUserId },
        })
      ).count;
    }
    if (m.shareLink.length) {
      restoredRows += (
        await tx.shareLink.updateMany({
          where: { id: { in: m.shareLink } },
          data: { userId: donorUserId },
        })
      ).count;
    }
    if (m.oidcAccessToken.length) {
      restoredRows += (
        await tx.oidcAccessToken.updateMany({
          where: { jti: { in: m.oidcAccessToken } },
          data: { userId: donorUserId },
        })
      ).count;
    }
    if (m.wizardSession.length) {
      restoredRows += (
        await tx.wizardSession.updateMany({
          where: { id: { in: m.wizardSession } },
          data: { userId: donorUserId },
        })
      ).count;
    }
    if (m.recoveryCode.length) {
      restoredRows += (
        await tx.recoveryCode.updateMany({
          where: { id: { in: m.recoveryCode } },
          data: { userId: donorUserId },
        })
      ).count;
    }
    if (m.recoveryAttempt.length) {
      restoredRows += (
        await tx.recoveryAttempt.updateMany({
          where: { id: { in: m.recoveryAttempt } },
          data: { userId: donorUserId },
        })
      ).count;
    }
    if (m.userEmail.length) {
      restoredRows += (
        await tx.userEmail.updateMany({
          where: { id: { in: m.userEmail } },
          data: { userId: donorUserId },
        })
      ).count;
    }
    if (m.auditLog.length) {
      restoredRows += (
        await tx.auditLog.updateMany({
          where: { id: { in: m.auditLog } },
          data: { userId: donorUserId },
        })
      ).count;
    }
    if (m.account.length) {
      restoredRows += (
        await tx.account.updateMany({
          where: {
            OR: m.account.map((a) => ({
              provider: a.provider,
              providerAccountId: a.providerAccountId,
            })),
          },
          data: { userId: donorUserId },
        })
      ).count;
    }
    if (m.session.length) {
      restoredRows += (
        await tx.session.updateMany({
          where: { sessionToken: { in: m.session } },
          data: { userId: donorUserId },
        })
      ).count;
    }
    // Authenticator: keyed on the @unique credentialID; move each back.
    for (const a of m.authenticator) {
      const res = await tx.authenticator.updateMany({
        where: { credentialID: a.credentialID, userId: survivorUserId },
        data: { userId: donorUserId },
      });
      restoredRows += res.count;
    }
    if (m.inviteRedemption.length) {
      restoredRows += (
        await tx.inviteRedemption.updateMany({
          where: { id: { in: m.inviteRedemption } },
          data: { userId: donorUserId },
        })
      ).count;
    }
    if (m.eligibility.length) {
      restoredRows += (
        await tx.eligibility.updateMany({
          where: { id: { in: m.eligibility } },
          data: { userId: donorUserId },
        })
      ).count;
    }
    // Donor's own SubjectOverride rows (re-pointed at merge) move back.
    for (const ov of m.subjectOverride) {
      const res = await tx.subjectOverride.updateMany({
        where: { userId: survivorUserId, clientId: ov.clientId },
        data: { userId: donorUserId },
      });
      restoredRows += res.count;
    }
    if (m.oidcClientOwned.length) {
      restoredRows += (
        await tx.oidcClient.updateMany({
          where: { id: { in: m.oidcClientOwned } },
          data: { ownerUserId: donorUserId },
        })
      ).count;
    }
    // OidcGrant: re-pointed donor-only grants move back to the donor (keyed by
    // clientId, guarded on the survivor as the current owner). `?? []` tolerates
    // a snapshot written before OidcGrant merge handling existed.
    for (const clientId of m.oidcGrant ?? []) {
      const res = await tx.oidcGrant.updateMany({
        where: { userId: survivorUserId, clientId },
        data: { userId: donorUserId },
      });
      restoredRows += res.count;
    }

    // Remove the overrides the merge CREATED for donor-only clients.
    for (const ov of snap.overridesCreated) {
      await tx.subjectOverride.deleteMany({
        where: { userId: survivorUserId, clientId: ov.clientId, sub: ov.sub },
      });
    }

    // Recreate the collision losers we deleted.
    let recreatedDeleted = 0;
    for (const e of snap.eligibilityDeleted) {
      await tx.eligibility.create({
        data: {
          id: e.id,
          userId: e.userId,
          badgeType: e.badgeType,
          eligibleAt: new Date(e.eligibleAt),
          fuzzDays: e.fuzzDays,
          source: e.source,
        },
      });
      recreatedDeleted++;
    }
    for (const r of snap.inviteRedemptionDeleted) {
      await tx.inviteRedemption.create({
        data: {
          id: r.id,
          inviteCodeId: r.inviteCodeId,
          userId: r.userId,
          redeemedAt: new Date(r.redeemedAt),
        },
      });
      recreatedDeleted++;
    }

    // OidcGrant collisions: restore the survivor's PRE-merge grant state and
    // recreate the donor's deleted grant (with its original id), splitting the
    // union back apart. `?? []` tolerates pre-change snapshots.
    for (const mg of snap.oidcGrantMerged ?? []) {
      await tx.oidcGrant.updateMany({
        where: { userId: survivorUserId, clientId: mg.clientId },
        data: {
          badgeTypes: { set: mg.survivorPrev.badgeTypes },
          badgeIds: { set: mg.survivorPrev.badgeIds },
          profileName: mg.survivorPrev.profileName,
          profileAvatar: mg.survivorPrev.profileAvatar,
          sybilScore: mg.survivorPrev.sybilScore,
        },
      });
      await tx.oidcGrant.create({
        data: {
          id: mg.donorDeleted.id,
          userId: donorUserId,
          clientId: mg.clientId,
          badgeTypes: mg.donorDeleted.badgeTypes,
          badgeIds: mg.donorDeleted.badgeIds,
          profileName: mg.donorDeleted.profileName,
          profileAvatar: mg.donorDeleted.profileAvatar,
          sybilScore: mg.donorDeleted.sybilScore,
        },
      });
      recreatedDeleted++;
    }

    // Re-promote the donor's demoted primary email(s).
    if (snap.demotedPrimaryEmailIds.length) {
      await tx.userEmail.updateMany({
        where: { id: { in: snap.demotedPrimaryEmailIds } },
        data: { isPrimary: true },
      });
    }

    // Restore the survivor's prior ban flag and bump its gen (credential set
    // changed back). isAdmin was never touched, so nothing to restore there.
    await tx.user.update({
      where: { id: survivorUserId },
      data: {
        isBanned: snap.survivorPrev.isBanned,
        sessionGeneration: { increment: 1 },
      },
    });

    // Un-tombstone the donor and bump its gen so any pre-merge JWT stays invalid
    // (the human must sign in fresh to the un-merged donor).
    await tx.user.update({
      where: { id: donorUserId },
      data: {
        mergedIntoUserId: null,
        mergedAt: null,
        sessionGeneration: { increment: 1 },
      },
    });

    await tx.mergeRecord.update({
      where: { id: mergeRecordId },
      data: { reversedAt: new Date() },
    });

    return {
      result: { ok: true as const, restoredRows, recreatedDeleted },
      reassign: {
        entryRefs: dedupReassigned,
        fromHandle: survivor?.dedupHandle ?? null,
        toHandle: donor.dedupHandle,
      },
    };
  };
  const txResult = await runWithWriteConflictRetry(
    () => prisma.$transaction(runReverseTx, REPEATABLE_READ),
    "reverseMerge",
  );

  // §2.6 post-commit: re-tag EXACTLY the merge's reassigned refs back to the
  // donor handle. Idempotent retry; conservative on failure (entries stay under
  // the survivor handle for admin reconcile), never fails the reversal.
  const r = txResult.reassign;
  if (r && r.entryRefs.length > 0 && r.fromHandle && r.toHandle) {
    const { entryRefs, fromHandle, toHandle } = r;
    await runPostCommit(
      () =>
        nullifierService.reassignOwner({
          entryRefs,
          fromOwnerHandle: fromHandle,
          toOwnerHandle: toHandle,
        }),
      "reassign-on-reverse-merge",
    );
  }

  return txResult.result;
}
