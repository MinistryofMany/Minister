import { randomInt } from "node:crypto";

import type { Prisma } from "@/generated/prisma";
import { audit } from "@/lib/audit";
import { prisma } from "@/lib/prisma";

import { JITTER_MAX_MS } from "./constants";

// The revocation chokepoint (§5.2) — ONE primitive every kick/delete/recall
// routes through. Marks every per-RP handle for a fact revoked and stamps an
// INDEPENDENT jitter floor per row (auditor #2), then audits. The publisher folds
// the bits in on its next epoch once each row's `revealAfter` has passed.
//
// A revoke landing mid-publication is never lost: the publisher re-reads eligible
// entries each pass, so a bit set here appears in that epoch or the next (auditor
// #13). Idempotent: an already-revoked row (revokedAt set) is skipped, so its
// original jitter floor and reveal instant are preserved on a repeat call.

const AUDIT_ACTION = "status.anchor_revoked";

// Accepts the caller's transaction client so the revoke + its durable tombstone +
// its audit commit atomically with the membership mutation that triggered it.
type RevokeClient = Pick<
  Prisma.TransactionClient,
  "badgeStatusEntry" | "statusAnchorRevocation" | "auditLog"
>;

export async function revokeStatusAnchor(args: {
  anchor: string;
  reason: string;
  actorUserId?: string | null;
  client?: RevokeClient;
}): Promise<number> {
  const { anchor, reason, actorUserId = null } = args;
  const client = args.client ?? prisma;

  const nowMs = Date.now();

  // W1: write the durable per-anchor tombstone FIRST, so a disclosure that
  // allocates a fresh entry for this anchor AFTER this transaction commits sees it
  // and is born revoked. Written even when there are ZERO existing entries (a
  // member kicked before ever disclosing) — that is the case a per-entry-only
  // revoke could never cover. Idempotent: a repeat revoke keeps the first
  // revokedAt/reason.
  await client.statusAnchorRevocation.upsert({
    where: { statusAnchor: anchor },
    create: { statusAnchor: anchor, revokedAt: new Date(nowMs), reason },
    update: {},
  });

  const entries = await client.badgeStatusEntry.findMany({
    where: { statusAnchor: anchor, revokedAt: null },
    select: { id: true },
  });

  for (const entry of entries) {
    // Independent per-(event, list) jitter from a CSPRNG (§5.7). Enforced by the
    // publisher, not advisory — an entry is folded in only once revealAfter <= now.
    const revealAfter = new Date(nowMs + randomInt(0, JITTER_MAX_MS + 1));
    await client.badgeStatusEntry.update({
      where: { id: entry.id },
      data: { revokedAt: new Date(nowMs), revealAfter },
    });
  }

  await audit(actorUserId, AUDIT_ACTION, { anchor, reason, entries: entries.length }, client);
  return entries.length;
}
