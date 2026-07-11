"use server";

import { revalidatePath } from "next/cache";
import type { Session } from "next-auth";
import { z } from "zod";

import { audit } from "@/lib/audit";
import { RECOVERY_ELIGIBLE_TYPES } from "@/lib/assurance";
import { sendMail } from "@/lib/mailer";
import { prisma } from "@/lib/prisma";
import {
  planRecoveryWeightWrite,
  planThresholdWrite,
  soloBlockError,
  validateRecoveryWeightBounds,
  validateThresholdBounds,
} from "@/lib/recovery-config-guardrails";
import { requireAal, requireAdmin, requireAuthRecency, StepUpRequiredError } from "@/lib/session";
import type { ActionResult } from "@/server/credential-actions";

// ---------------------------------------------------------------------------
// Recovery-config editor server actions (SECURITY-CRITICAL — the account
// takeover control surface). These deliberately do NOT use the `adminAction`
// wrapper: that wrapper catches every throw (including StepUpRequiredError) and
// collapses it to "Not authorized", which would hide the step-up path. Instead
// each action runs its body through `run()`, which maps a StepUpRequiredError
// into the `{ ok:false, stepUp:true, requiredAal }` contract the client's
// `withStepUp` handler drives (run a passkey ceremony → retry). Every action, in
// order: requireAdmin → requireAal(2) → reject recovered → requireAuthRecency →
// guardrail validation → mutate → audit + admin-email broadcast.
// ---------------------------------------------------------------------------

// Recovery-config recency window: an AAL2 session can be up to 24h old, so a
// captured cookie stays dangerous. Recovery-config edits demand a real
// authentication within the last 10 minutes (design spec §5.4).
const RECOVERY_CONFIG_MAX_AUTH_AGE_SECS = 600;

// Fixed 64-bit key for the Postgres transaction-level advisory lock all three
// recovery-config mutations take as their FIRST statement, so they serialize
// against each other. The solo-block invariant ("no non-solo type reaches the
// threshold alone", spec §5.4) is a CROSS-ROW predicate: updateRecoveryWeight
// reads RecoveryConfig then writes a BadgeWeight; updateRecoveryThreshold reads
// BadgeWeight rows then writes RecoveryConfig. Under Read-Committed, two
// concurrent admin requests each validate against the OTHER's pre-change state
// and can jointly defeat the invariant. A shared advisory lock forces them to
// run one-at-a-time so each validates and commits against a stable world.
// Any fixed constant works; it just has to be identical across all three.
const RECOVERY_CONFIG_ADVISORY_LOCK_KEY = 4823710192837n;

// Local mirror of credential-actions' run(): translate a thrown
// StepUpRequiredError into the tagged step-up result (a thrown Server Action
// error does not cross the RSC boundary with its class intact), everything else
// into a presentable error.
async function run<T>(fn: () => Promise<T>): Promise<ActionResult<T>> {
  try {
    return { ok: true, data: await fn() };
  } catch (err) {
    if (err instanceof StepUpRequiredError) {
      return { ok: false, stepUp: true, requiredAal: err.requiredAal };
    }
    const error = err instanceof Error ? err.message : "Something went wrong.";
    return { ok: false, error };
  }
}

// The full recovery-config gate. Throws StepUpRequiredError (→ step-up) when the
// AAL floor or auth-recency check fails; throws a plain Error (→ presentable
// failure) for a non-admin or a recovered session.
async function gateRecoveryConfig(): Promise<Session> {
  const session = await requireAdmin();
  requireAal(session, 2);
  if (session.recovered) {
    throw new Error(
      "A recovered session can't edit the recovery config. Re-authenticate with a passkey first.",
    );
  }
  requireAuthRecency(session, RECOVERY_CONFIG_MAX_AUTH_AGE_SECS);
  return session;
}

// The lowest threshold that could be live in the near future: honor a scheduled
// (pending) threshold DECREASE even before it lands, so a guardrail can't be
// dodged by scheduling the weakening separately. Fail-closed.
function worstThreshold(cfg: { threshold: number; pendingThreshold: number | null }): number {
  return cfg.pendingThreshold != null
    ? Math.min(cfg.threshold, cfg.pendingThreshold)
    : cfg.threshold;
}

// The highest weight a row could carry in the near future: honor a scheduled
// (pending) weight INCREASE even before it lands. Fail-closed.
function worstWeight(row: {
  recoveryWeight: number;
  pendingRecoveryWeight: number | null;
}): number {
  return row.pendingRecoveryWeight != null
    ? Math.max(row.recoveryWeight, row.pendingRecoveryWeight)
    : row.recoveryWeight;
}

// Email every admin about a recovery-config change. Guarded: the config change
// is already committed, so a mail failure must NOT roll it back — it is logged
// server-side (never to a user) and swallowed per-recipient so one bad address
// doesn't drop the rest of the broadcast.
async function broadcastRecoveryConfigChange(subject: string, body: string): Promise<void> {
  const admins = await prisma.user.findMany({
    where: { isAdmin: true },
    select: { email: true },
  });
  for (const admin of admins) {
    if (!admin.email) continue;
    try {
      await sendMail({ to: admin.email, subject, text: body });
    } catch (err) {
      // Do not rethrow — the config change stands; just record the delivery miss.
      console.error(
        `[recovery-config] admin broadcast to ${admin.email} failed:`,
        err instanceof Error ? err.message : err,
      );
    }
  }
}

function effectiveAtCopy(effectiveAt: Date | null): string {
  return effectiveAt
    ? `This is a weakening change and takes effect in 72h at ${effectiveAt.toISOString()}.`
    : "This is a defensive change and takes effect immediately.";
}

// ---------------------------------------------------------------------------
// recoveryWeight (per BadgeWeight row)
// ---------------------------------------------------------------------------

const UpdateRecoveryWeightInput = z.object({
  badgeType: z.string().min(1),
  qualifier: z.string().min(1),
  recoveryWeight: z.number(),
});

export async function updateRecoveryWeight(
  input: z.infer<typeof UpdateRecoveryWeightInput>,
): Promise<ActionResult<{ effectiveAt: string | null }>> {
  return run(async () => {
    const session = await gateRecoveryConfig();

    const parsed = UpdateRecoveryWeightInput.safeParse(input);
    if (!parsed.success) {
      throw new Error(parsed.error.issues[0]?.message ?? "Invalid input");
    }
    const { badgeType, qualifier, recoveryWeight } = parsed.data;

    // recovery-eligibility is a CODE property (a plugin can nonce-bind a live
    // re-proof), never a DB toggle. The engine only reads eligible types, so an
    // edit to an ineligible type's recovery weight is inert — reject it outright
    // rather than record a misleading change (defense in depth behind the greyed
    // UI control).
    if (!RECOVERY_ELIGIBLE_TYPES.has(badgeType)) {
      throw new Error(
        `${badgeType} is not recovery-eligible; its recovery weight is never read by the recovery engine and cannot be edited.`,
      );
    }

    // Serialize the WHOLE read → guardrail-validate → write → audit against the
    // other two recovery-config actions (advisory lock, taken FIRST), and commit
    // the mutation together with its audit row so a change can never land
    // unlogged. Everything the solo-block invariant depends on — bounds, the
    // BadgeWeight row, the RecoveryConfig threshold, the pending-aware worst-case
    // check — is read and validated inside this locked transaction.
    const { effectiveAt, before } = await prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(${RECOVERY_CONFIG_ADVISORY_LOCK_KEY})`;

      const boundsError = validateRecoveryWeightBounds(recoveryWeight);
      if (boundsError) throw new Error(boundsError);

      const row = await tx.badgeWeight.findUnique({
        where: { badgeType_qualifier: { badgeType, qualifier } },
        select: {
          recoveryWeight: true,
          pendingRecoveryWeight: true,
          recoveryEffectiveAt: true,
          allowSoloRecovery: true,
        },
      });
      if (!row) {
        throw new Error(`No badge-weight row for ${badgeType} / ${qualifier}.`);
      }

      const cfg = await tx.recoveryConfig.findUnique({
        where: { id: "singleton" },
        select: { threshold: true, pendingThreshold: true },
      });
      if (!cfg) throw new Error("Recovery config is not seeded.");

      // Solo-block: the requested weight is the value that will become effective
      // (immediately on a decrease, in 72h on an increase) — guard it regardless
      // of timing, against the lowest threshold that could apply. tlsn (solo=true)
      // stays valid.
      const soloError = soloBlockError(recoveryWeight, worstThreshold(cfg), row.allowSoloRecovery);
      if (soloError) throw new Error(soloError);

      const now = Date.now();
      const plan = planRecoveryWeightWrite(row.recoveryWeight, recoveryWeight, now);

      const data =
        plan.kind === "immediate"
          ? {
              recoveryWeight: plan.recoveryWeight,
              pendingRecoveryWeight: plan.pendingRecoveryWeight,
              recoveryEffectiveAt: plan.recoveryEffectiveAt,
            }
          : {
              pendingRecoveryWeight: plan.pendingRecoveryWeight,
              recoveryEffectiveAt: plan.recoveryEffectiveAt,
            };

      await tx.badgeWeight.update({
        where: { badgeType_qualifier: { badgeType, qualifier } },
        data,
      });

      const scheduledAt = plan.kind === "scheduled" ? plan.recoveryEffectiveAt : null;

      await audit(
        session.user.id,
        "admin.recovery_config.updated",
        {
          field: `recoveryWeight:${badgeType}:${qualifier}`,
          before: row.recoveryWeight,
          after: recoveryWeight,
          effectiveAt: scheduledAt ? scheduledAt.toISOString() : null,
        },
        tx,
      );

      return { effectiveAt: scheduledAt, before: row.recoveryWeight };
    });

    // Best-effort AFTER the transaction commits: a mail failure must NOT roll
    // back the (already committed + audited) change.
    await broadcastRecoveryConfigChange(
      "Minister recovery config changed",
      `Recovery weight for ${badgeType} / ${qualifier} changed from ${before} to ${recoveryWeight}.\n` +
        `${effectiveAtCopy(effectiveAt)}\n\n` +
        `If you did not make this change, treat the admin account as compromised.`,
    );

    revalidatePath("/admin/recovery-config");
    return { effectiveAt: effectiveAt ? effectiveAt.toISOString() : null };
  });
}

// ---------------------------------------------------------------------------
// allowSoloRecovery (per BadgeWeight row) — no pending column exists, so it
// applies immediately. It is still a recovery-config change (full gate +
// broadcast). The dangerous case (pairing solo=true with a HIGH weight) is
// itself delayed by the weight rule above, so an immediate solo toggle cannot by
// itself open a solo path faster than 72h.
// ---------------------------------------------------------------------------

const SetAllowSoloInput = z.object({
  badgeType: z.string().min(1),
  qualifier: z.string().min(1),
  allowSoloRecovery: z.boolean(),
});

export async function setAllowSoloRecovery(
  input: z.infer<typeof SetAllowSoloInput>,
): Promise<ActionResult<void>> {
  return run(async () => {
    const session = await gateRecoveryConfig();

    const parsed = SetAllowSoloInput.safeParse(input);
    if (!parsed.success) {
      throw new Error(parsed.error.issues[0]?.message ?? "Invalid input");
    }
    const { badgeType, qualifier, allowSoloRecovery } = parsed.data;

    // Same fixed advisory lock as the weight/threshold actions (taken FIRST) so a
    // solo toggle serializes against them, and the mutation + its audit commit
    // atomically. Returns whether anything actually changed (a no-op skips the
    // post-commit broadcast/revalidate).
    const changed = await prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(${RECOVERY_CONFIG_ADVISORY_LOCK_KEY})`;

      const row = await tx.badgeWeight.findUnique({
        where: { badgeType_qualifier: { badgeType, qualifier } },
        select: { allowSoloRecovery: true, recoveryWeight: true, pendingRecoveryWeight: true },
      });
      if (!row) {
        throw new Error(`No badge-weight row for ${badgeType} / ${qualifier}.`);
      }

      if (row.allowSoloRecovery === allowSoloRecovery) {
        // No-op: nothing to change, broadcast, or audit.
        return false;
      }

      // Turning solo OFF must not strand this row above the threshold (which would
      // violate the solo-block invariant from the other side). Check the row's
      // worst-case weight against the worst-case threshold.
      if (!allowSoloRecovery) {
        const cfg = await tx.recoveryConfig.findUnique({
          where: { id: "singleton" },
          select: { threshold: true, pendingThreshold: true },
        });
        if (!cfg) throw new Error("Recovery config is not seeded.");
        const soloError = soloBlockError(worstWeight(row), worstThreshold(cfg), false);
        if (soloError) {
          throw new Error(
            `Can't disable solo recovery here: ${soloError} Lower this row's weight first.`,
          );
        }
      }

      await tx.badgeWeight.update({
        where: { badgeType_qualifier: { badgeType, qualifier } },
        data: { allowSoloRecovery },
      });

      await audit(
        session.user.id,
        "admin.recovery_config.updated",
        {
          field: `allowSoloRecovery:${badgeType}:${qualifier}`,
          before: row.allowSoloRecovery,
          after: allowSoloRecovery,
          effectiveAt: null,
        },
        tx,
      );

      return true;
    });

    if (!changed) return;

    // Best-effort AFTER commit: a mail failure must NOT roll back the change.
    await broadcastRecoveryConfigChange(
      "Minister recovery config changed",
      `Solo recovery for ${badgeType} / ${qualifier} was turned ${allowSoloRecovery ? "ON" : "OFF"}.\n` +
        "This takes effect immediately.\n\n" +
        "If you did not make this change, treat the admin account as compromised.",
    );

    revalidatePath("/admin/recovery-config");
  });
}

// ---------------------------------------------------------------------------
// threshold (RecoveryConfig singleton)
// ---------------------------------------------------------------------------

const UpdateThresholdInput = z.object({
  threshold: z.number(),
});

export async function updateRecoveryThreshold(
  input: z.infer<typeof UpdateThresholdInput>,
): Promise<ActionResult<{ effectiveAt: string | null }>> {
  return run(async () => {
    const session = await gateRecoveryConfig();

    const parsed = UpdateThresholdInput.safeParse(input);
    if (!parsed.success) {
      throw new Error(parsed.error.issues[0]?.message ?? "Invalid input");
    }
    const { threshold } = parsed.data;

    // Serialize the whole read → validate → write → audit against the other two
    // recovery-config actions (advisory lock FIRST), and commit the mutation with
    // its audit row atomically. bounds, the current threshold, and every non-solo
    // row's pending-aware worst-case weight are read and checked inside the lock.
    const { effectiveAt, before } = await prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(${RECOVERY_CONFIG_ADVISORY_LOCK_KEY})`;

      const boundsError = validateThresholdBounds(threshold);
      if (boundsError) throw new Error(boundsError);

      const cfg = await tx.recoveryConfig.findUnique({
        where: { id: "singleton" },
        select: { threshold: true, pendingThreshold: true },
      });
      if (!cfg) throw new Error("Recovery config is not seeded.");

      // Uphold the solo-block invariant from the THRESHOLD side: lowering the
      // threshold must not let any existing non-solo row solo-recover. Check the
      // requested threshold against every non-solo row's worst-case weight.
      const nonSoloRows = await tx.badgeWeight.findMany({
        where: { allowSoloRecovery: false },
        select: {
          badgeType: true,
          qualifier: true,
          recoveryWeight: true,
          pendingRecoveryWeight: true,
        },
      });
      for (const row of nonSoloRows) {
        if (worstWeight(row) >= threshold) {
          throw new Error(
            `Can't lower the threshold to ${threshold}: ${row.badgeType} / ${row.qualifier} ` +
              `(recovery weight ${worstWeight(row)}) would then solo-recover an account. ` +
              "Lower that row's weight or enable solo recovery for it first.",
          );
        }
      }

      const now = Date.now();
      const plan = planThresholdWrite(cfg.threshold, threshold, now);

      const data =
        plan.kind === "immediate"
          ? {
              threshold: plan.threshold,
              pendingThreshold: plan.pendingThreshold,
              thresholdEffectiveAt: plan.thresholdEffectiveAt,
            }
          : {
              pendingThreshold: plan.pendingThreshold,
              thresholdEffectiveAt: plan.thresholdEffectiveAt,
            };

      await tx.recoveryConfig.update({ where: { id: "singleton" }, data });

      const scheduledAt = plan.kind === "scheduled" ? plan.thresholdEffectiveAt : null;

      await audit(
        session.user.id,
        "admin.recovery_config.updated",
        {
          field: "threshold",
          before: cfg.threshold,
          after: threshold,
          effectiveAt: scheduledAt ? scheduledAt.toISOString() : null,
        },
        tx,
      );

      return { effectiveAt: scheduledAt, before: cfg.threshold };
    });

    // Best-effort AFTER commit: a mail failure must NOT roll back the change.
    await broadcastRecoveryConfigChange(
      "Minister recovery config changed",
      `Recovery threshold changed from ${before} to ${threshold}.\n` +
        `${effectiveAtCopy(effectiveAt)}\n\n` +
        `If you did not make this change, treat the admin account as compromised.`,
    );

    revalidatePath("/admin/recovery-config");
    return { effectiveAt: effectiveAt ? effectiveAt.toISOString() : null };
  });
}
