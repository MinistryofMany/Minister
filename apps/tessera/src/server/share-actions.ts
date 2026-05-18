"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { audit } from "@/lib/audit";
import { sendMail } from "@/lib/mailer";
import { prisma } from "@/lib/prisma";
import { requireSession } from "@/lib/session";
import {
  DEFAULT_SHARE_TTL_DAYS,
  MAX_SHARE_TTL_DAYS,
  generateShareToken,
} from "@/lib/share-links";

const CreateInput = z.object({
  badgeIds: z.array(z.string().cuid()).min(1, "Pick at least one badge"),
  ttlDays: z.coerce
    .number()
    .int()
    .min(1)
    .max(MAX_SHARE_TTL_DAYS)
    .default(DEFAULT_SHARE_TTL_DAYS),
  requiresAccount: z.boolean().default(false),
  // Optional recipient — if provided, we email them the URL. Empty
  // string is treated as "don't email."
  sendToEmail: z
    .string()
    .email()
    .optional()
    .or(z.literal("").transform(() => undefined)),
});

export type CreateShareLinkResult =
  | { ok: true; token: string; url: string }
  | { ok: false; error: string };

// Build the absolute /share/<token> URL. We can't reach Next.js's
// `headers()` from a non-async-action call site, so callers pass the
// origin in (typically from a header read in the page).
function buildShareUrl(origin: string, token: string): string {
  return `${origin.replace(/\/$/, "")}/share/${token}`;
}

export async function createShareLink(
  input: z.infer<typeof CreateInput>,
  origin: string,
): Promise<CreateShareLinkResult> {
  const session = await requireSession();

  const parsed = CreateInput.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      error: parsed.error.issues[0]?.message ?? "Invalid input",
    };
  }
  const { badgeIds, ttlDays, requiresAccount, sendToEmail } = parsed.data;

  // Confirm every badge belongs to the user. Don't allow disclosing
  // somebody else's badge through one of your own share links.
  const owned = await prisma.badge.findMany({
    where: { userId: session.user.id, id: { in: badgeIds } },
    select: { id: true },
  });
  if (owned.length !== badgeIds.length) {
    return { ok: false, error: "Some badges are not yours" };
  }

  const token = generateShareToken();
  const expiresAt = new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000);
  const row = await prisma.shareLink.create({
    data: {
      userId: session.user.id,
      token,
      badgeIds,
      expiresAt,
      requiresAccount,
    },
    select: { id: true },
  });

  const url = buildShareUrl(origin, token);

  await audit(session.user.id, "share_link.created", {
    shareLinkId: row.id,
    badgeCount: badgeIds.length,
    ttlDays,
    requiresAccount,
    emailed: Boolean(sendToEmail),
  });

  if (sendToEmail) {
    await sendMail({
      to: sendToEmail,
      subject: "Someone shared their Tessera badges with you",
      text: [
        `You've been sent a Tessera share link. It carries ${badgeIds.length} verifiable credential${badgeIds.length === 1 ? "" : "s"}.`,
        "",
        url,
        "",
        `Link is valid for ${ttlDays} day${ttlDays === 1 ? "" : "s"}; the sender can revoke it at any time.${
          requiresAccount ? " Opening it requires a Tessera account." : ""
        }`,
      ].join("\n"),
    });
  }

  revalidatePath("/shares");
  return { ok: true, token, url };
}

const RevokeInput = z.object({
  shareLinkId: z.string().cuid(),
});

export async function revokeShareLink(input: z.infer<typeof RevokeInput>) {
  const session = await requireSession();
  const parsed = RevokeInput.safeParse(input);
  if (!parsed.success) return { ok: false as const, error: "Invalid input" };

  // updateMany scopes the where clause; we'd rather a no-op than throw
  // if somebody tries to revoke a link they don't own.
  const result = await prisma.shareLink.updateMany({
    where: {
      id: parsed.data.shareLinkId,
      userId: session.user.id,
      revokedAt: null,
    },
    data: { revokedAt: new Date() },
  });
  if (result.count === 0) {
    return { ok: false as const, error: "Share link not found or already revoked" };
  }

  await audit(session.user.id, "share_link.revoked", {
    shareLinkId: parsed.data.shareLinkId,
  });

  revalidatePath("/shares");
  return { ok: true as const };
}
