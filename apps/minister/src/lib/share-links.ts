import { randomBytes } from "node:crypto";

import { BADGE_TYPES } from "@minister/shared";
import { buildPairwiseUserDid, reMintVc } from "@minister/vc";

import { audit } from "@/lib/audit";
import { sanitizeDisclosedClaims } from "@/lib/disclosure-claims";
import { getIssuer } from "@/lib/issuer";
import {
  deriveLocalPairwise,
  deriveShareLinkPairwiseJti,
  deriveShareLinkPairwiseSub,
  shareLinkPairwiseJtiInput,
  shareLinkPairwiseSubInput,
} from "@/lib/pairwise-backend";
import { prisma } from "@/lib/prisma";

// Bytes of entropy for share-link tokens. CLAUDE.md asks for ≥128
// bits; 32 bytes = 256 bits → 43 base64url characters.
const SHARE_TOKEN_BYTES = 32;

export const DEFAULT_SHARE_TTL_DAYS = 7;
export const MAX_SHARE_TTL_DAYS = 90;

export function generateShareToken(): string {
  return randomBytes(SHARE_TOKEN_BYTES).toString("base64url");
}

// PER-SHARE-LINK pairwise subject pseudonym for VCs disclosed via a share
// link. A share link has no relying-party clientId, so the OIDC pairwise sub
// doesn't apply; the link itself is the disclosure context, so the LINK plays
// the audience role: every viewer (and re-fetch) of one link sees the same
// holder subject, while two different links from the same user — and any OIDC
// disclosure to any RP — carry unrelated subjects. Keying per-link (not
// per-user) is what makes viewers of two links unable to tell they came from
// the same holder.
//
// Domain separation: the OIDC spaces hash `${userId}:${clientId}` (sub) and
// `jti:${badgeId}:${clientId}` (jti) under the same secret. The `sharelink:`
// prefix keeps this input disjoint from both — userIds/badgeIds are cuids and
// clientIds are `mc_`-prefixed base64url (no colons), so no OIDC input can
// ever alias a share-link input or vice versa.
// Synchronous local byte truth (golden-vector-pinned). Runtime share-link
// rendering routes through `deriveShareLinkPairwiseSub` (async) so it can be
// staged into Signet; this stays for the cross-repo golden fixtures.
export function shareLinkPairwiseSub(userId: string, shareLinkId: string): string {
  return deriveLocalPairwise(shareLinkPairwiseSubInput(userId, shareLinkId));
}

// Per-(badge, share-link) `jti` for a disclosed VC — never the raw badge id
// (a stable cross-context correlator), and unlinkable from the same badge's
// `pairwiseJti` at any OIDC relying party. Deterministic, so it can still
// serve as a revocation handle for everything served through one link.
export function shareLinkPairwiseJti(badgeId: string, shareLinkId: string): string {
  return deriveLocalPairwise(shareLinkPairwiseJtiInput(badgeId, shareLinkId));
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

  const issuer = await getIssuer();
  const badges = await prisma.badge.findMany({
    // `issuer` scoping, same posture as the OIDC disclosure path: only
    // Minister's own badges are disclosable via re-mint. A foreign-issuer row
    // (badge import is a future feature) is silently not disclosed rather
    // than 500ing the page — reMintVc would refuse to re-sign it anyway.
    where: { userId: row.userId, id: { in: row.badgeIds }, issuer: issuer.did },
    select: {
      id: true,
      type: true,
      attributes: true,
      vcJwt: true,
      expiresAt: true,
    },
  });

  // Preserve the user's chosen badge order from the ShareLink.
  const badgeOrder = new Map(row.badgeIds.map((id, i) => [id, i]));
  badges.sort((a, b) => (badgeOrder.get(a.id) ?? 0) - (badgeOrder.get(b.id) ?? 0));

  // Re-mint every disclosed VC at view time, exactly like the OIDC token /
  // userinfo paths: the stored VC carries the STABLE `:users:<userId>` subject
  // and `jti = badge.id` — cross-context correlators that would link this
  // link's viewers to each other's OIDC disclosures and to every other share
  // link. The disclosed copy instead gets the per-LINK pairwise subject and
  // jti, disclosure-time iat/nbf, a presentation-shaped exp (never past the
  // badge's real lifetime NOR the link's own expiry — an artifact served by a
  // link should die with the link), and the coarse issuanceMonth bucket.
  // Route through the Phase 7 seam (async) so share-link pseudonyms can be
  // staged into Signet; in the default `local` mode these are byte-identical to
  // the synchronous shareLinkPairwise* helpers. §2.6: no open prisma.$transaction
  // is held here.
  const subjectId = buildPairwiseUserDid(
    issuer.domain,
    await deriveShareLinkPairwiseSub(row.userId, row.id),
  );

  const disclosed = await Promise.all(
    badges.map(async (b) => {
      const meta = BADGE_TYPES[b.type];
      // Unknown badge type: nothing to render — skip BEFORE signing; we
      // never re-sign an artifact we won't serve.
      if (!meta) return null;
      // Per-badge FAIL-CLOSED OMIT (ADR M5), same posture as the OIDC disclosure
      // path: a per-badge throw omits only THAT badge from the share page — it
      // must never 500 the whole page and kill every other badge on the link.
      // The per-link jti derivation lives INSIDE this try (not before it): once
      // the pairwise seam is on Signet, a transient per-badge jti-derivation
      // error must omit just that badge (matching oidc-claims.ts, which derives
      // the jti inside its own per-badge try), not reject the whole Promise.all
      // and drop every badge — and it must produce the audit record below.
      // Audit-logged so a systematic drift stays visible.
      let vcJwt: string;
      let jti: string;
      try {
        // One per-link jti per badge, reused for the re-mint and the render key.
        jti = await deriveShareLinkPairwiseJti(b.id, row.id);
        vcJwt = await reMintVc(issuer, b.vcJwt, {
          subjectId,
          jti,
          maxExpiresAt:
            b.expiresAt !== null && b.expiresAt < row.expiresAt ? b.expiresAt : row.expiresAt,
          // Strip any legacy claim the current schema has since removed (e.g. the
          // pre-Phase-1 oauth-account Sybil anchor) before re-signing.
          sanitizeClaims: sanitizeDisclosedClaims,
        });
      } catch (err) {
        await audit(row.userId, "sharelink.badge_disclosure_omitted", {
          badgeId: b.id,
          shareLinkId: row.id,
          reason: err instanceof Error ? err.message : String(err),
        });
        return null;
      }
      return {
        // The per-link jti, not the raw badge id: this shape is a disclosure
        // payload ("any future API"), and the stored id is the correlator the
        // re-mint just removed. The page only needs a per-link-unique key.
        id: jti,
        type: b.type,
        label: meta.label,
        description: meta.description,
        iconKey: meta.iconKey,
        attributes: b.attributes as Record<string, unknown>,
        vcJwt,
      };
    }),
  );

  return {
    id: row.id,
    ownerUserId: row.userId,
    requiresAccount: row.requiresAccount,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    badges: disclosed.filter((b): b is NonNullable<typeof b> => b !== null),
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

// "Shared with you" — links the viewer received from someone else.
export interface IncomingShareLinkSummary {
  token: string;
  badgeCount: number;
  requiresAccount: boolean;
  expiresAt: Date;
  lastViewedAt: Date;
  status: "active" | "expired" | "revoked";
}

// Links this user has legitimately opened, authored by someone else.
//
// AUTHZ: the ONLY key is a `ShareLinkView` row whose `viewerUserId` is this
// user. That row is written exclusively by the `/share/[token]` route, and
// only AFTER it has passed the very gate that governs viewing: the caller
// possessed the ≥128-bit bearer token, the link was neither revoked nor
// expired, and — for `requiresAccount` links — the caller was signed in (the
// row then records THAT signed-in user's id). So a `viewerUserId == me` row
// can exist only if I already viewed the link under the exact rule
// `/share/[token]` enforces. Deriving this list from my own recorded views is
// therefore a strict consequence of that gate, never looser — it cannot
// surface a link I was never given, and a different user (no matching view
// row) can never see it. We also exclude links I own; those are the outgoing
// list. Owner identity is deliberately NOT returned — the per-link pairwise
// subjects keep viewers from correlating a holder across links, and this list
// must not undo that.
export async function loadIncomingShareLinks(userId: string): Promise<IncomingShareLinkSummary[]> {
  const rows = await prisma.shareLink.findMany({
    where: {
      userId: { not: userId },
      views: { some: { viewerUserId: userId } },
    },
    orderBy: { createdAt: "desc" },
    select: {
      token: true,
      badgeIds: true,
      requiresAccount: true,
      expiresAt: true,
      revokedAt: true,
      views: {
        where: { viewerUserId: userId },
        orderBy: { viewedAt: "desc" },
        take: 1,
        select: { viewedAt: true },
      },
    },
  });
  const now = new Date();
  return rows.flatMap((r) => {
    // The `some` filter guarantees a matching view; the guard just satisfies
    // the compiler (noUncheckedIndexedAccess) and drops any impossible row.
    const lastViewedAt = r.views[0]?.viewedAt;
    if (!lastViewedAt) return [];
    return [
      {
        token: r.token,
        badgeCount: r.badgeIds.length,
        requiresAccount: r.requiresAccount,
        expiresAt: r.expiresAt,
        lastViewedAt,
        status: (r.revokedAt
          ? "revoked"
          : r.expiresAt < now
            ? "expired"
            : "active") as IncomingShareLinkSummary["status"],
      },
    ];
  });
}
