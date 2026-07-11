"use server";

import { z } from "zod";

import { audit } from "@/lib/audit";
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
