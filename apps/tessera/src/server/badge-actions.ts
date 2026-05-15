"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { audit } from "@/lib/audit";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";

class UnauthorizedError extends Error {
  constructor() {
    super("Not signed in");
    this.name = "UnauthorizedError";
  }
}

async function requireUserId(): Promise<string> {
  const session = await getCurrentSession();
  if (!session?.user?.id) throw new UnauthorizedError();
  return session.user.id;
}

const TogglePublicInput = z.object({
  badgeId: z.string().cuid(),
  isPublic: z.boolean(),
});

export async function toggleBadgePublic(input: z.infer<typeof TogglePublicInput>) {
  const { badgeId, isPublic } = TogglePublicInput.parse(input);
  const userId = await requireUserId();

  const result = await prisma.badge.updateMany({
    where: { id: badgeId, userId },
    data: { isPublic },
  });

  if (result.count === 0) {
    return { ok: false as const, error: "Badge not found" };
  }

  await audit(userId, "badge.visibility_changed", { badgeId, isPublic });
  revalidatePath("/profile");
  return { ok: true as const };
}

const ReorderInput = z.object({
  orderedIds: z.array(z.string().cuid()).min(1),
});

export async function reorderBadges(input: z.infer<typeof ReorderInput>) {
  const { orderedIds } = ReorderInput.parse(input);
  const userId = await requireUserId();

  // Validate the user owns every id in the request before persisting.
  const owned = await prisma.badge.findMany({
    where: { userId, id: { in: orderedIds } },
    select: { id: true },
  });
  if (owned.length !== orderedIds.length) {
    return { ok: false as const, error: "Some badges are not yours" };
  }

  await prisma.$transaction(
    orderedIds.map((id, index) =>
      prisma.badge.update({
        where: { id },
        data: { sortOrder: index },
      }),
    ),
  );

  await audit(userId, "badge.reordered", { count: orderedIds.length });
  revalidatePath("/profile");
  return { ok: true as const };
}

const DeleteInput = z.object({
  badgeId: z.string().cuid(),
});

export async function deleteBadge(input: z.infer<typeof DeleteInput>) {
  const { badgeId } = DeleteInput.parse(input);
  const userId = await requireUserId();

  const result = await prisma.badge.deleteMany({
    where: { id: badgeId, userId },
  });

  if (result.count === 0) {
    return { ok: false as const, error: "Badge not found" };
  }

  await audit(userId, "badge.deleted", { badgeId });
  revalidatePath("/profile");
  return { ok: true as const };
}
