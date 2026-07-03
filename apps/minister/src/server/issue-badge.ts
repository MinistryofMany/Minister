import { BADGE_TYPES } from "@minister/shared";
import { buildUserDid, issueVc } from "@minister/vc";

import type { Prisma } from "@/generated/prisma";
import { getIssuer } from "@/lib/issuer";
import { prisma } from "@/lib/prisma";

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
}): Promise<string> {
  const { userId, pluginId, badge, dedupeKey } = args;

  const meta = BADGE_TYPES[badge.type];
  if (!meta) {
    throw new Error(`Unknown badge type: ${badge.type}`);
  }
  const claims = meta.schema.parse(badge.claims);

  const issuer = await getIssuer();
  const subjectDid = buildUserDid(issuer.domain, userId);

  return prisma.$transaction(async (tx) => {
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
      },
    });

    const vcJwt = await issueVc(issuer, badge.type, subjectDid, claims as Record<string, unknown>, {
      jti: created.id,
      expiresIn: "1y",
    });

    await tx.badge.update({ where: { id: created.id }, data: { vcJwt } });

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
  });
}
