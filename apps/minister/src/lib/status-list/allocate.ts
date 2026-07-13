import { randomInt } from "node:crypto";

import { Prisma } from "@/generated/prisma";
import { prisma } from "@/lib/prisma";

import { SHARD_FILL_THRESHOLD, SHARD_SIZE_BITS } from "./constants";
import { newBitstring } from "./bitstring";

// Lazy per-RP allocation of a revocation handle (§5.2). Called at FIRST
// disclosure of a revocable badge to a given RP, from loadApprovedBadgeJwts.
// Idempotent on (statusAnchor, clientId); assigns a crypto-random free index in
// the RP's current shard; NEVER touches a published bitstring (allocation
// invisibility, auditor #1) — bits flip only on revocation.

export interface AllocatedStatus {
  listId: string;
  bitIndex: number;
}

// Attempts before giving up on the current shard and rolling to a fresh (empty)
// one. On a shard kept under SHARD_FILL_THRESHOLD, per-attempt collision
// probability is < 0.75, so exhausting this many is ~1% and only near the
// threshold; the roll-to-empty fallback then succeeds without a deterministic
// scan (a scan would bias toward low indices under contention — auditor #3).
const MAX_RANDOM_ATTEMPTS = 24;

type ConstraintKind = "anchor" | "index" | "shard" | "other";

function uniqueViolationKind(err: unknown): ConstraintKind | null {
  if (!(err instanceof Prisma.PrismaClientKnownRequestError) || err.code !== "P2002") {
    return null;
  }
  const target = err.meta?.target;
  const fields = Array.isArray(target) ? target.map(String) : [String(target ?? "")];
  if (fields.some((f) => f.includes("statusAnchor"))) return "anchor";
  if (fields.some((f) => f.includes("bitIndex"))) return "index";
  if (fields.some((f) => f.includes("shardNo"))) return "shard";
  return "other";
}

async function findExisting(
  statusAnchor: string,
  clientId: string,
): Promise<AllocatedStatus | null> {
  return prisma.badgeStatusEntry.findUnique({
    where: { statusAnchor_clientId: { statusAnchor, clientId } },
    select: { listId: true, bitIndex: true },
  });
}

interface ShardRow {
  id: string;
  shardNo: number;
}

async function getOrCreateShard(clientId: string, shardNo: number): Promise<ShardRow> {
  try {
    const created = await prisma.statusList.create({
      data: {
        clientId,
        shardNo,
        sizeBits: SHARD_SIZE_BITS,
        // All-zero at birth, published at full size (§5.3) so growth never leaks
        // allocation. signedJwt starts "" until the publisher first signs it.
        bits: Buffer.from(newBitstring()),
      },
      select: { id: true, shardNo: true },
    });
    return created;
  } catch (err) {
    // A concurrent first-disclosure for this RP created the same shard first.
    if (uniqueViolationKind(err) === "shard") {
      const existing = await prisma.statusList.findUnique({
        where: { clientId_shardNo: { clientId, shardNo } },
        select: { id: true, shardNo: true },
      });
      if (existing) return existing;
    }
    throw err;
  }
}

// The shard new indices should land in: the highest-numbered shard, unless it has
// passed the fill threshold, in which case a fresh shard is opened.
async function currentWritableShard(clientId: string): Promise<ShardRow> {
  const top = await prisma.statusList.findFirst({
    where: { clientId },
    orderBy: { shardNo: "desc" },
    select: { id: true, shardNo: true },
  });
  if (!top) return getOrCreateShard(clientId, 0);
  const count = await prisma.badgeStatusEntry.count({ where: { listId: top.id } });
  if (count >= SHARD_FILL_THRESHOLD * SHARD_SIZE_BITS) {
    return getOrCreateShard(clientId, top.shardNo + 1);
  }
  return top;
}

// Try random free indices in one shard. Returns the allocation, or null if every
// random attempt collided (shard too full — caller rolls to a fresh shard). A
// concurrent same-fact allocation short-circuits to the winner's handle. When
// `revokedAt` is non-null the anchor is ALREADY revoked (W1): the entry is born
// revoked (revokedAt = revealAfter = revokedAt) so the publisher sets its bit — a
// late allocation can never mint an un-revocable handle.
async function allocateInShard(
  list: ShardRow,
  statusAnchor: string,
  clientId: string,
  revokedAt: Date | null,
): Promise<AllocatedStatus | null> {
  for (let attempt = 0; attempt < MAX_RANDOM_ATTEMPTS; attempt++) {
    const bitIndex = randomInt(0, SHARD_SIZE_BITS);
    try {
      await prisma.badgeStatusEntry.create({
        data: {
          statusAnchor,
          clientId,
          listId: list.id,
          bitIndex,
          // Born revoked with an immediate reveal (no jitter): the fact is already
          // public via the sibling entries' kick, and prompt enforcement outweighs
          // decorrelation for a straggler re-allocation.
          ...(revokedAt ? { revokedAt, revealAfter: revokedAt } : {}),
        },
      });
      return { listId: list.id, bitIndex };
    } catch (err) {
      const kind = uniqueViolationKind(err);
      if (kind === "anchor") {
        const raced = await findExisting(statusAnchor, clientId);
        if (raced) return raced;
        // The racing writer rolled back; keep trying our own index.
        continue;
      }
      if (kind === "index") continue; // index taken — draw another
      throw err;
    }
  }
  return null;
}

// Has this anchor been durably revoked (W1 tombstone)? A returned Date is the
// revocation instant; null means "not revoked (yet)".
async function anchorRevokedAt(statusAnchor: string): Promise<Date | null> {
  const row = await prisma.statusAnchorRevocation.findUnique({
    where: { statusAnchor },
    select: { revokedAt: true },
  });
  return row?.revokedAt ?? null;
}

// Mark a just-allocated (or pre-existing) entry revoked, immediately reveal-able.
// Idempotent and race-safe: only touches a still-clear row.
async function forceRevokeEntry(statusAnchor: string, clientId: string): Promise<void> {
  const now = new Date();
  await prisma.badgeStatusEntry.updateMany({
    where: { statusAnchor, clientId, revokedAt: null },
    data: { revokedAt: now, revealAfter: now },
  });
}

export async function allocateStatusEntry(args: {
  statusAnchor: string;
  clientId: string;
}): Promise<AllocatedStatus> {
  const { statusAnchor, clientId } = args;

  // W1: if the anchor is already revoked, any entry we hand back MUST be revoked,
  // or the disclosure re-mints a credentialStatus whose bit nobody ever sets.
  const revokedAt = await anchorRevokedAt(statusAnchor);

  const existing = await findExisting(statusAnchor, clientId);
  if (existing) {
    // Defense for the tight race where a prior allocation created a CLEAR entry
    // and the kick landed between its create and its own reconcile: fix it now.
    if (revokedAt) await forceRevokeEntry(statusAnchor, clientId);
    return existing;
  }

  const shard = await currentWritableShard(clientId);
  const alloc =
    (await allocateInShard(shard, statusAnchor, clientId, revokedAt)) ??
    // The chosen shard filled up under us — open the next and allocate there
    // (empty shard: a random index cannot collide, so this succeeds).
    (await allocateInShard(
      await getOrCreateShard(clientId, shard.shardNo + 1),
      statusAnchor,
      clientId,
      revokedAt,
    ));

  if (!alloc) {
    throw new Error(
      `status-list: could not allocate a bit index for (${statusAnchor}, ${clientId}) after shard roll`,
    );
  }

  // Reconcile the post-revoke race. If the anchor was already revoked at our read
  // (revokedAt), OR its tombstone COMMITTED while we were mid-allocation (re-check
  // below), ensure the handle we hand back is revoked. Idempotent — forceRevokeEntry
  // only touches a still-clear row, so a born-revoked entry is a no-op, but a CLEAR
  // entry we raced into (e.g. a concurrent first-disclosure that read the anchor
  // pre-kick and won the create) gets fixed. Only on the create path.
  if (revokedAt || (await anchorRevokedAt(statusAnchor))) {
    await forceRevokeEntry(statusAnchor, clientId);
  }

  return alloc;
}
