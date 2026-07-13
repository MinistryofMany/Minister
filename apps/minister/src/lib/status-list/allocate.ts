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
// concurrent same-fact allocation short-circuits to the winner's handle.
async function allocateInShard(
  list: ShardRow,
  statusAnchor: string,
  clientId: string,
): Promise<AllocatedStatus | null> {
  for (let attempt = 0; attempt < MAX_RANDOM_ATTEMPTS; attempt++) {
    const bitIndex = randomInt(0, SHARD_SIZE_BITS);
    try {
      await prisma.badgeStatusEntry.create({
        data: { statusAnchor, clientId, listId: list.id, bitIndex },
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

export async function allocateStatusEntry(args: {
  statusAnchor: string;
  clientId: string;
}): Promise<AllocatedStatus> {
  const { statusAnchor, clientId } = args;

  const existing = await findExisting(statusAnchor, clientId);
  if (existing) return existing;

  const shard = await currentWritableShard(clientId);
  const first = await allocateInShard(shard, statusAnchor, clientId);
  if (first) return first;

  // The chosen shard filled up under us — open the next and allocate there
  // (empty shard: a random index cannot collide, so this succeeds).
  const nextShard = await getOrCreateShard(clientId, shard.shardNo + 1);
  const second = await allocateInShard(nextShard, statusAnchor, clientId);
  if (second) return second;

  throw new Error(
    `status-list: could not allocate a bit index for (${statusAnchor}, ${clientId}) after shard roll`,
  );
}
