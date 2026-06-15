import { randomBytes } from "node:crypto";

import { BADGE_TYPES } from "@minister/shared";

import { prisma } from "@/lib/prisma";

// Bytes of entropy for share-link tokens. CLAUDE.md asks for ≥128
// bits; 32 bytes = 256 bits → 43 base64url characters.
const SHARE_TOKEN_BYTES = 32;

export const DEFAULT_SHARE_TTL_DAYS = 7;
export const MAX_SHARE_TTL_DAYS = 90;

export function generateShareToken(): string {
  return randomBytes(SHARE_TOKEN_BYTES).toString("base64url");
}

// Resolve a share token to the rendered shape: the share link's
// metadata + the badges it covers (with display meta attached). null
// if the token doesn't exist, is revoked, or has expired.
//
// Does NOT enforce `requiresAccount` — that's a UI/route concern; this
// helper is shared by both the public landing and any future API.
export async function loadShareLinkByToken(token: string): Promise<{
  id: string;
  ownerUserId: string;
  requiresAccount: boolean;
  expiresAt: Date;
  createdAt: Date;
  badges: Array<{
    id: string;
    type: string;
    label: string;
    description: string;
    iconKey: string;
    attributes: Record<string, unknown>;
    vcJwt: string;
  }>;
} | null> {
  const row = await prisma.shareLink.findUnique({
    where: { token },
    select: {
      id: true,
      userId: true,
      requiresAccount: true,
      expiresAt: true,
      createdAt: true,
      revokedAt: true,
      badgeIds: true,
    },
  });
  if (!row) return null;
  if (row.revokedAt) return null;
  if (row.expiresAt < new Date()) return null;

  const badges = await prisma.badge.findMany({
    where: { userId: row.userId, id: { in: row.badgeIds } },
    select: {
      id: true,
      type: true,
      attributes: true,
      vcJwt: true,
    },
  });

  // Preserve the user's chosen badge order from the ShareLink.
  const badgeOrder = new Map(row.badgeIds.map((id, i) => [id, i]));
  badges.sort((a, b) => (badgeOrder.get(a.id) ?? 0) - (badgeOrder.get(b.id) ?? 0));

  return {
    id: row.id,
    ownerUserId: row.userId,
    requiresAccount: row.requiresAccount,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    badges: badges
      .map((b) => {
        const meta = BADGE_TYPES[b.type];
        if (!meta) return null;
        return {
          id: b.id,
          type: b.type,
          label: meta.label,
          description: meta.description,
          iconKey: meta.iconKey,
          attributes: b.attributes as Record<string, unknown>,
          vcJwt: b.vcJwt,
        };
      })
      .filter((b): b is NonNullable<typeof b> => b !== null),
  };
}

// User-facing listing on /shares — every link this user has ever
// created, with derived "active" / "expired" / "revoked" status.
export interface ShareLinkSummary {
  id: string;
  token: string;
  badgeCount: number;
  requiresAccount: boolean;
  createdAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
  viewCount: number;
  status: "active" | "expired" | "revoked";
}

export async function loadUserShareLinks(userId: string): Promise<ShareLinkSummary[]> {
  const rows = await prisma.shareLink.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      token: true,
      badgeIds: true,
      requiresAccount: true,
      createdAt: true,
      expiresAt: true,
      revokedAt: true,
      _count: { select: { views: true } },
    },
  });
  const now = new Date();
  return rows.map((r) => ({
    id: r.id,
    token: r.token,
    badgeCount: r.badgeIds.length,
    requiresAccount: r.requiresAccount,
    createdAt: r.createdAt,
    expiresAt: r.expiresAt,
    revokedAt: r.revokedAt,
    viewCount: r._count.views,
    status: r.revokedAt ? "revoked" : r.expiresAt < now ? "expired" : "active",
  }));
}
