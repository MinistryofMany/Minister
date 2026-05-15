import { BADGE_TYPES } from "@tessera/shared";

import { prisma } from "@/lib/prisma";

export interface BadgeRow {
  id: string;
  type: string;
  attributes: Record<string, unknown>;
  issuer: string;
  issuedAt: Date;
  expiresAt: Date | null;
  isPublic: boolean;
  sortOrder: number;
  importedFrom: string | null;
  pluginId: string | null;
}

// Client-safe view of badge type metadata. Strips the Zod schema —
// schemas are class instances and can't cross the RSC boundary.
export interface BadgeMetaView {
  type: string;
  label: string;
  description: string;
  iconKey: string;
}

export interface DisplayBadge extends BadgeRow {
  meta: BadgeMetaView;
}

function attach(row: BadgeRow): DisplayBadge | undefined {
  const meta = BADGE_TYPES[row.type];
  if (!meta) return undefined;
  return {
    ...row,
    meta: {
      type: meta.type,
      label: meta.label,
      description: meta.description,
      iconKey: meta.iconKey,
    },
  };
}

export async function loadUserBadges(userId: string): Promise<DisplayBadge[]> {
  const rows = await prisma.badge.findMany({
    where: { userId },
    orderBy: [{ sortOrder: "asc" }, { issuedAt: "asc" }],
    select: {
      id: true,
      type: true,
      attributes: true,
      issuer: true,
      issuedAt: true,
      expiresAt: true,
      isPublic: true,
      sortOrder: true,
      importedFrom: true,
      pluginId: true,
    },
  });

  return rows
    .map((row) =>
      attach({
        ...row,
        attributes: row.attributes as Record<string, unknown>,
      }),
    )
    .filter((b): b is DisplayBadge => b !== undefined);
}

export async function loadPublicBadges(
  userId: string,
): Promise<DisplayBadge[]> {
  const rows = await prisma.badge.findMany({
    where: { userId, isPublic: true },
    orderBy: [{ sortOrder: "asc" }, { issuedAt: "asc" }],
    select: {
      id: true,
      type: true,
      attributes: true,
      issuer: true,
      issuedAt: true,
      expiresAt: true,
      isPublic: true,
      sortOrder: true,
      importedFrom: true,
      pluginId: true,
    },
  });

  return rows
    .map((row) =>
      attach({
        ...row,
        attributes: row.attributes as Record<string, unknown>,
      }),
    )
    .filter((b): b is DisplayBadge => b !== undefined);
}

export function summarizeAttributes(
  type: string,
  attributes: Record<string, unknown>,
): string {
  switch (type) {
    case "email-domain":
      return typeof attributes.domain === "string" ? attributes.domain : "";
    case "email-exact":
      return typeof attributes.email === "string" ? attributes.email : "";
    case "oauth-account": {
      const p =
        typeof attributes.provider === "string" ? attributes.provider : "";
      const h = typeof attributes.handle === "string" ? attributes.handle : "";
      return h ? `${p} · @${h}` : p;
    }
    case "residency-country":
      return typeof attributes.country === "string" ? attributes.country : "";
    case "residency-state":
      return [attributes.state, attributes.country].filter(Boolean).join(", ");
    case "residency-city":
      return [attributes.city, attributes.state, attributes.country]
        .filter(Boolean)
        .join(", ");
    default:
      if (type.startsWith("age-over-")) {
        const t = type.slice("age-over-".length);
        return `Over ${t}`;
      }
      return "";
  }
}
