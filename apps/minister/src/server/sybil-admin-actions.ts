"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { audit } from "@/lib/audit";
import { prisma } from "@/lib/prisma";
import { adminAction } from "@/server/admin-action";
import type { AdminActionResult } from "@/server/admin-actions";

// ---------------------------------------------------------------------------
// /admin/sybil-score editor actions: sybilWeight rows, categories + caps, and
// bucket cutoffs. These feed ONLY the RP-facing anti-sybil score (never the
// recovery threshold — that surface lives at /admin/recovery-config behind AAL2
// + auth-recency). So they apply IMMEDIATELY and ride the low-friction
// `adminAction` wrapper (admin gate + zod parse + uniform error), which is
// exactly why the recovery column is READ-ONLY here.
// ---------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Weights (+ per-row category)
// -----------------------------------------------------------------------------

// Per-row save, matching /admin/recovery-config's weight-row action (rather
// than the previous bulk "save everything" — the two same-shaped tables now
// share one save granularity, so a partial edit elsewhere on the page can never
// be swept up into an unrelated row's save, and the client can show an
// unsaved-changes marker per row instead of only per whole table).
const UpdateSybilWeightInput = z.object({
  badgeType: z.string().min(1),
  qualifier: z.string().min(1),
  sybilWeight: z.number(),
  category: z.string().min(1),
});

export const updateSybilWeight = adminAction(
  UpdateSybilWeightInput,
  async ({ session, input }): Promise<AdminActionResult> => {
    const [existing, categoryRow] = await Promise.all([
      prisma.badgeWeight.findUnique({
        where: {
          badgeType_qualifier: { badgeType: input.badgeType, qualifier: input.qualifier },
        },
        select: { sybilWeight: true, category: true },
      }),
      prisma.sybilCategory.findUnique({ where: { name: input.category } }),
    ]);
    if (!existing) {
      return { ok: false, error: `Unknown weight row: ${input.badgeType} / ${input.qualifier}` };
    }
    if (!categoryRow) {
      return { ok: false, error: `Unknown category: ${input.category}` };
    }

    // Clamp: sybilWeight is a non-negative integer.
    const toWeight = Math.max(0, Math.floor(input.sybilWeight));
    if (toWeight === existing.sybilWeight && input.category === existing.category) {
      return { ok: true };
    }

    await prisma.badgeWeight.update({
      where: { badgeType_qualifier: { badgeType: input.badgeType, qualifier: input.qualifier } },
      data: { sybilWeight: toWeight, category: input.category },
    });

    await audit(session.user.id, "admin.sybil_weights.updated", {
      row: `${input.badgeType}:${input.qualifier}`,
      sybilWeight: { before: existing.sybilWeight, after: toWeight },
      category: { before: existing.category, after: input.category },
    });

    revalidatePath("/admin/sybil-score");
    return { ok: true };
  },
);

// -----------------------------------------------------------------------------
// Categories + caps
//
// Categories are CODE-OWNED (seeded from sybil-config.ts). Only their cap is
// editable here; adding/renaming a category from the UI was removed as dead
// weight — a category's identity lives in code.
// -----------------------------------------------------------------------------

const UpdateCategoryCapInput = z.object({
  name: z.string().min(1),
  cap: z.number(),
});

export const updateSybilCategoryCap = adminAction(
  UpdateCategoryCapInput,
  async ({ session, input }): Promise<AdminActionResult> => {
    const cap = Math.max(0, Math.floor(input.cap));
    const existing = await prisma.sybilCategory.findUnique({ where: { name: input.name } });
    if (!existing) return { ok: false, error: `No category "${input.name}"` };
    if (existing.cap === cap) return { ok: true };

    await prisma.sybilCategory.update({ where: { name: input.name }, data: { cap } });

    await audit(session.user.id, "admin.sybil_category.cap_updated", {
      name: input.name,
      before: existing.cap,
      after: cap,
    });
    revalidatePath("/admin/sybil-score");
    return { ok: true };
  },
);

// -----------------------------------------------------------------------------
// Bucket cutoffs (singleton)
// -----------------------------------------------------------------------------

const SaveBucketCutoffsInput = z.object({
  bucket1Raw: z.number(),
  bucket2Raw: z.number(),
  bucket3Raw: z.number(),
  bucket4Raw: z.number(),
  bucket3MinCats: z.number(),
  bucket4MinCats: z.number(),
});

export const saveBucketCutoffs = adminAction(
  SaveBucketCutoffsInput,
  async ({ session, input }): Promise<AdminActionResult> => {
    const b1 = Math.max(0, Math.floor(input.bucket1Raw));
    const b2 = Math.max(0, Math.floor(input.bucket2Raw));
    const b3 = Math.max(0, Math.floor(input.bucket3Raw));
    const b4 = Math.max(0, Math.floor(input.bucket4Raw));
    const b3Cats = Math.max(0, Math.floor(input.bucket3MinCats));
    const b4Cats = Math.max(0, Math.floor(input.bucket4MinCats));

    // The bucket ladder must be monotonic non-decreasing, or a higher bucket
    // would be unreachable / a lower one would shadow it.
    if (!(b1 <= b2 && b2 <= b3 && b3 <= b4)) {
      return { ok: false, error: "Raw cutoffs must be non-decreasing: b1 ≤ b2 ≤ b3 ≤ b4." };
    }
    if (!(b3Cats <= b4Cats)) {
      return { ok: false, error: "Breadth floors must be non-decreasing: b3 cats ≤ b4 cats." };
    }

    const before = await prisma.sybilBucketConfig.findUnique({ where: { id: "singleton" } });

    await prisma.sybilBucketConfig.upsert({
      where: { id: "singleton" },
      create: {
        id: "singleton",
        bucket1Raw: b1,
        bucket2Raw: b2,
        bucket3Raw: b3,
        bucket4Raw: b4,
        bucket3MinCats: b3Cats,
        bucket4MinCats: b4Cats,
      },
      update: {
        bucket1Raw: b1,
        bucket2Raw: b2,
        bucket3Raw: b3,
        bucket4Raw: b4,
        bucket3MinCats: b3Cats,
        bucket4MinCats: b4Cats,
      },
    });

    await audit(session.user.id, "admin.sybil_buckets.updated", {
      before: before
        ? {
            bucket1Raw: before.bucket1Raw,
            bucket2Raw: before.bucket2Raw,
            bucket3Raw: before.bucket3Raw,
            bucket4Raw: before.bucket4Raw,
            bucket3MinCats: before.bucket3MinCats,
            bucket4MinCats: before.bucket4MinCats,
          }
        : null,
      after: {
        bucket1Raw: b1,
        bucket2Raw: b2,
        bucket3Raw: b3,
        bucket4Raw: b4,
        bucket3MinCats: b3Cats,
        bucket4MinCats: b4Cats,
      },
    });

    revalidatePath("/admin/sybil-score");
    return { ok: true };
  },
);
