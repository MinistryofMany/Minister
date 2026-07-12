"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { audit } from "@/lib/audit";
import { cohortFilterSchema } from "@/lib/cohort-filter";
import { Prisma } from "@/generated/prisma";
import { prisma } from "@/lib/prisma";
import { recomputeAllStats } from "@/lib/stats-recompute";
import { adminAction } from "@/server/admin-action";

// The admin "Recompute now" action (phase-2 impl brief §4). The escape hatch +
// test surface for the in-process interval: it recomputes the materialized badge
// statistics synchronously (no advisory lock — an operator-triggered run always
// executes). adminAction gates it on a fresh, non-banned admin session.
export const recomputeStatsNow = adminAction(
  // No input; adminAction still parses it, so accept an empty/absent object.
  z.object({}).optional(),
  async ({ session }): Promise<{ ok: true; durationMs: number } | { ok: false; error: string }> => {
    const { durationMs } = await recomputeAllStats();
    await audit(session.user.id, "stats.recompute", { durationMs, trigger: "admin" });
    return { ok: true, durationMs };
  },
);

// ---------------------------------------------------------------------------
// Cohort defs (admin stats view, /admin/stats)
// ---------------------------------------------------------------------------

// The numerator/denominator arrive as untrusted JSON built by the admin add-
// cohort form. Deliberately typed `z.unknown()` here rather than nested inside
// `cohortFilterSchema` directly, so each side is validated SEPARATELY below and
// the resulting error names which side (numerator vs denominator) failed and
// why — reusing cohort-filter.ts's own schema (its `superRefine` already
// enforces the allowlist + known-type checks; this action never reimplements
// that logic).
const CreateCohortDefInput = z.object({
  label: z.string().trim().min(1, "Label is required").max(200),
  numeratorFilter: z.unknown(),
  denominatorFilter: z.unknown(),
});

export type CreateCohortDefResult = { ok: true; id: string } | { ok: false; error: string };

export const createCohortDef = adminAction(
  CreateCohortDefInput,
  async ({ session, input }): Promise<CreateCohortDefResult> => {
    const numerator = cohortFilterSchema.safeParse(input.numeratorFilter);
    if (!numerator.success) {
      return {
        ok: false,
        error: `Numerator: ${numerator.error.issues[0]?.message ?? "invalid filter"}`,
      };
    }
    const denominator = cohortFilterSchema.safeParse(input.denominatorFilter);
    if (!denominator.success) {
      return {
        ok: false,
        error: `Denominator: ${denominator.error.issues[0]?.message ?? "invalid filter"}`,
      };
    }

    const row = await prisma.cohortStatDef.create({
      data: {
        label: input.label,
        numeratorFilter: numerator.data as unknown as Prisma.InputJsonValue,
        denominatorFilter: denominator.data as unknown as Prisma.InputJsonValue,
      },
      select: { id: true },
    });

    // No CohortStat row exists yet — the admin page renders "pending next
    // recompute" for a def with no matching stat until the next run fills it in.
    await audit(session.user.id, "admin.stats.cohort_def_created", {
      cohortStatDefId: row.id,
      label: input.label,
    });

    revalidatePath("/admin/stats");
    return { ok: true, id: row.id };
  },
);

export type SetCohortDefPublishedResult = { ok: true } | { ok: false; error: string };

// Publish / unpublish a cohort def. A def is created UNPUBLISHED (see
// `createCohortDef`); only this action flips its visibility on the public
// /transparency page. Both surfaces are revalidated so the change is reflected
// immediately on the admin view AND the world-readable page.
export const setCohortDefPublished = adminAction(
  z.object({ id: z.string().min(1), published: z.boolean() }),
  async ({ session, input }): Promise<SetCohortDefPublishedResult> => {
    await prisma.cohortStatDef.update({
      where: { id: input.id },
      data: { published: input.published },
      select: { id: true },
    });

    await audit(session.user.id, "admin.stats.cohort_def_published", {
      cohortStatDefId: input.id,
      published: input.published,
    });

    revalidatePath("/admin/stats");
    revalidatePath("/transparency");
    return { ok: true };
  },
);
