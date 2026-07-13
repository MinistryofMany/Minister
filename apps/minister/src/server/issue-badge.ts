import { BADGE_TYPES } from "@minister/shared";
import { buildUserDid, issueVc } from "@minister/vc";

import type { Prisma } from "@/generated/prisma";
import { getIssuer } from "@/lib/issuer";
import { prisma } from "@/lib/prisma";
import { genericBadgeAnchor } from "@/lib/status-list";

export interface BadgeToIssue {
  type: string;
  attributes: Record<string, unknown>; // denormalized display → Badge.attributes
  claims: Record<string, unknown>; // → VC credentialSubject; must pass the type's Zod schema
  expiresAt?: Date | null;
  eligibilities?: Array<{ badgeType: string; eligibleAt: Date; fuzzDays: number }>;
}

// Mint a single native badge for `userId`.
//
// Extracted from the wizard runtime so every code path that issues a native
// badge — the plugin wizard AND the sign-in auto-issue path — produces the
// IDENTICAL VC shape (same claim validation, same subject DID, same jti/exp,
// same audit event). Do not hand-roll a VC elsewhere; call this.
//
// The insert, sign, and write-back happen in one interactive transaction so a
// Badge row is never observable with an empty vcJwt: a signing failure rolls
// back the insert instead of leaving an empty credential behind. issueVc is
// pure in-process Ed25519 signing (no network/IO), so wrapping it is safe.
export async function issueBadge(args: {
  userId: string;
  pluginId: string | null;
  badge: BadgeToIssue;
  // Optional idempotency key (Badge.dedupeKey, unique). When set, a concurrent
  // duplicate insert fails with P2002 instead of minting a second badge; the
  // caller decides whether that is benign (see auto-issue-email-domain).
  dedupeKey?: string | null;
  // Opaque handle into the Sybil-dedup nullifier ledger, set by the wizard
  // runtime AFTER it has registered the anchor and DISCARDED it. null for
  // badges with no nullifier. Persisted on Badge.nullifierRef.
  nullifierRef?: string | null;
  // Optional caller-provided transaction client. When set, the insert/sign/
  // write-back run INSIDE the caller's transaction instead of opening a new one,
  // so a badge can be minted atomically alongside other writes (e.g. group
  // creation: Group + owner GroupMembership + owner badge in one transaction).
  // Prisma has no nested interactive transactions, so we must reuse it rather
  // than open our own. Omitted = self-contained (the historical behavior).
  tx?: Prisma.TransactionClient;
  // Revocation status anchor (docs/groups-revocation-design.md §5.1). Set for a
  // revocable badge whose anchor is a FACT known to the caller before the badge
  // row exists — e.g. a group-membership badge, anchored on its GroupMembership
  // row ("gm:<membershipId>"). Omitted for a revocable type whose anchor is the
  // badge itself: this path then derives "badge:<badgeId>" after insert. null/
  // omitted on a non-revocable type => no anchor (the common case).
  statusAnchor?: string | null;
}): Promise<string> {
  const { userId, pluginId, badge, dedupeKey, nullifierRef, tx: externalTx } = args;

  const meta = BADGE_TYPES[badge.type];
  if (!meta) {
    throw new Error(`Unknown badge type: ${badge.type}`);
  }
  const claims = meta.schema.parse(badge.claims);
  const revocable = meta.revocable ?? false;

  const issuer = await getIssuer();
  const subjectDid = buildUserDid(issuer.domain, userId);

  // For a revocable type, resolve the anchor: an explicit caller anchor (the
  // group-membership "gm:<membershipId>" case) wins; otherwise the badge id is
  // the fact ("badge:<badgeId>"), stamped after insert once the id exists. A
  // non-revocable type never gets an anchor.
  const explicitAnchor = revocable ? (args.statusAnchor ?? null) : null;

  const run = async (tx: Prisma.TransactionClient): Promise<string> => {
    const created = await tx.badge.create({
      data: {
        userId,
        type: badge.type,
        attributes: badge.attributes as Prisma.InputJsonValue,
        vcJwt: "",
        issuer: issuer.did,
        issuedAt: new Date(),
        expiresAt: badge.expiresAt ?? null,
        pluginId,
        dedupeKey: dedupeKey ?? null,
        nullifierRef: nullifierRef ?? null,
        statusAnchor: explicitAnchor,
      },
    });

    const statusAnchor = revocable ? (explicitAnchor ?? genericBadgeAnchor(created.id)) : null;

    const vcJwt = await issueVc(issuer, badge.type, subjectDid, claims as Record<string, unknown>, {
      jti: created.id,
      expiresIn: "1y",
    });

    await tx.badge.update({
      where: { id: created.id },
      data: {
        vcJwt,
        // Backfill the derived generic anchor when no explicit one was supplied.
        ...(statusAnchor !== explicitAnchor ? { statusAnchor } : {}),
      },
    });

    if (badge.eligibilities && badge.eligibilities.length > 0) {
      for (const e of badge.eligibilities) {
        await tx.eligibility.upsert({
          where: { userId_badgeType: { userId, badgeType: e.badgeType } },
          create: {
            userId,
            badgeType: e.badgeType,
            eligibleAt: e.eligibleAt,
            fuzzDays: e.fuzzDays,
            source: pluginId ?? badge.type,
          },
          update: {
            eligibleAt: e.eligibleAt,
            fuzzDays: e.fuzzDays,
            source: pluginId ?? badge.type,
          },
        });
      }
    }

    await tx.auditLog.create({
      data: {
        userId,
        action: "badge.issued",
        metadata: { badgeId: created.id, type: badge.type, pluginId } as Prisma.InputJsonValue,
      },
    });

    return created.id;
  };

  return externalTx ? run(externalTx) : prisma.$transaction(run);
}
