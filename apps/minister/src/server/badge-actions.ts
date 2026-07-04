"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { audit } from "@/lib/audit";
import { nullifierService, runPostCommit } from "@/lib/nullifier";
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

  // Capture the nullifier ref + owner handle BEFORE the delete so the ledger
  // entry can be released post-delete (a revoked credential must be free to be
  // re-registered from another account — otherwise it is permanently burned).
  const badge = await prisma.badge.findFirst({
    where: { id: badgeId, userId },
    select: { nullifierRef: true },
  });
  if (!badge) {
    return { ok: false as const, error: "Badge not found" };
  }
  const owner = badge.nullifierRef
    ? await prisma.user.findUnique({ where: { id: userId }, select: { dedupHandle: true } })
    : null;

  const result = await prisma.badge.deleteMany({
    where: { id: badgeId, userId },
  });

  if (result.count === 0) {
    return { ok: false as const, error: "Badge not found" };
  }

  // Post-commit release (§2.6): the badge is gone; release with retry. A
  // release failure strands the credential (conservative), never bypasses dedup.
  //
  // Sibling-ref guard: re-issuing a credential from the same account yields a
  // SECOND Badge row pointing at the SAME nullifierRef (registerDedup →
  // `already_yours`). Releasing the ledger entry while a sibling badge still
  // references it would be a dedup bypass — the freed entry lets a DIFFERENT
  // account register the same credential while this user still holds a live,
  // signed sibling badge.
  //
  // Correctness does NOT rest on the count below — it is a fast path that
  // skips a pointless release round trip (a network call in the Phase 3
  // backend) when siblings obviously remain. A one-shot count cannot guard a
  // release that fires LATER: a concurrent re-issue's badge INSERT can commit
  // between this count and the release, and the mint-side probe can run
  // before the release fires — both one-shot reads miss it (the proven Case-A
  // bypass). The authoritative guard is the release itself: the interim
  // backend deletes the entry ATOMICALLY only when no Badge row references it
  // (one conditional statement, see lib/nullifier/interim.ts). That composes
  // with the mint-side re-validation in issueBadgesAndComplete
  // (server/wizard.ts): release-after-badge-commit no-ops on the sibling;
  // release-before-badge-commit is seen by the probe and self-healed.
  if (badge.nullifierRef && owner?.dedupHandle) {
    const ref = badge.nullifierRef;
    const ownerHandle = owner.dedupHandle;
    const siblingsSharingRef = await prisma.badge.count({ where: { nullifierRef: ref } });
    if (siblingsSharingRef === 0) {
      await runPostCommit(
        () => nullifierService.release({ entryRef: ref, ownerHandle }),
        "release-on-badge-delete",
      );
    }
  }

  await audit(userId, "badge.deleted", { badgeId });
  revalidatePath("/profile");
  return { ok: true as const };
}
