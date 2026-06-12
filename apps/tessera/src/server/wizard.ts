import { BADGE_TYPES } from "@tessera/shared";
import type {
  IssuedBadge,
  PluginContext,
  WizardState,
} from "@tessera/plugin-sdk";
import { buildUserDid, issueVc } from "@tessera/vc";

import type { Prisma } from "@/generated/prisma";
import { audit } from "@/lib/audit";
import { getIssuer } from "@/lib/issuer";
import { sendMail } from "@/lib/mailer";
import { prisma } from "@/lib/prisma";
import { getPlugin } from "@/plugins/registry";
import { pendingTokenFor } from "@/server/wizard-helpers";

const SESSION_TTL_MINUTES = 60;

function nowPlusMinutes(min: number): Date {
  return new Date(Date.now() + min * 60_000);
}

// Wizard-state is persisted as JSON, but only the `currentStep` and
// `data` fields need to survive — userId and pluginId are stored as
// dedicated columns. Strip back to the minimum for round-trips.
function serializeState(state: WizardState): Prisma.InputJsonValue {
  return {
    currentStep: state.currentStep,
    data: state.data,
  } as unknown as Prisma.InputJsonValue;
}

function hydrate(
  row: {
    id: string;
    userId: string;
    pluginId: string;
    state: unknown;
  },
): WizardState {
  const s = row.state as {
    currentStep: WizardState["currentStep"];
    data: WizardState["data"];
  };
  return {
    pluginId: row.pluginId,
    userId: row.userId,
    currentStep: s.currentStep,
    data: s.data,
  };
}

function buildPluginContext(userId: string, origin: string): PluginContext {
  return {
    userId,
    origin,
    audit: {
      log: (action, metadata) => audit(userId, action, metadata),
    },
    sendMail,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function startWizard(
  pluginId: string,
  userId: string,
  origin: string,
): Promise<{ sessionId: string; state: WizardState }> {
  const plugin = getPlugin(pluginId);
  if (!plugin) throw new Error(`Unknown plugin: ${pluginId}`);

  const ctx = buildPluginContext(userId, origin);
  const state = await plugin.startWizard(ctx);

  // Drop any stale unfinished session for this user+plugin before
  // creating a new one — prevents pendingToken collisions on retries.
  await prisma.wizardSession.deleteMany({
    where: { userId, pluginId, completedAt: null },
  });

  // Lift pendingToken on the initial step too — plugins like github
  // open with a redirect step whose state must be addressable by the
  // callback route. The submitStep path below does the same for
  // subsequent continue steps.
  const row = await prisma.wizardSession.create({
    data: {
      userId,
      pluginId,
      state: serializeState(state),
      pendingToken: pendingTokenFor(state),
      expiresAt: nowPlusMinutes(SESSION_TTL_MINUTES),
    },
  });

  return { sessionId: row.id, state };
}

export async function loadWizard(
  sessionId: string,
  userId: string,
): Promise<WizardState | null> {
  const row = await prisma.wizardSession.findFirst({
    where: { id: sessionId, userId, completedAt: null },
  });
  if (!row) return null;
  if (row.expiresAt < new Date()) return null;
  return hydrate(row);
}

export async function submitStep(
  sessionId: string,
  userId: string,
  origin: string,
  input: unknown,
): Promise<
  | { kind: "continue"; state: WizardState }
  | { kind: "complete"; badgeIds: string[] }
  | { kind: "error"; message: string }
> {
  const row = await prisma.wizardSession.findFirst({
    where: { id: sessionId, userId, completedAt: null },
  });
  if (!row) return { kind: "error", message: "Wizard session not found" };
  if (row.expiresAt < new Date()) {
    return { kind: "error", message: "Wizard session expired" };
  }

  const plugin = getPlugin(row.pluginId);
  if (!plugin) return { kind: "error", message: "Plugin no longer registered" };

  const state = hydrate(row);
  const ctx = buildPluginContext(userId, origin);
  const result = await plugin.handleStep(state, input, ctx);

  switch (result.kind) {
    case "continue": {
      // If the new step is a magic-link, lift expectedToken onto the
      // session's indexed `pendingToken` column so the verify route can
      // look the session up without a JSON query.
      const pendingToken = pendingTokenFor(result.state);
      await prisma.wizardSession.update({
        where: { id: sessionId },
        data: {
          state: serializeState(result.state),
          pendingToken,
          expiresAt: nowPlusMinutes(SESSION_TTL_MINUTES),
        },
      });
      return { kind: "continue", state: result.state };
    }
    case "complete": {
      const badgeIds = await issueBadgesAndComplete({
        sessionId,
        userId,
        pluginId: row.pluginId,
        issued: result.badges,
      });
      return { kind: "complete", badgeIds };
    }
    case "error":
      return { kind: "error", message: result.message };
  }
}

// Generic callback path: resolve a wizard session by its pendingToken
// (set by the runtime from magic-link's expectedToken or redirect's
// expectedState), then submit the caller-supplied input to the plugin.
//
// Caller is whatever endpoint received the round trip: magic-link
// verify page → input = { token }; OAuth callback → input = { code }.
// The plugin decides what to do with the input shape.
export async function resumeViaPendingToken(args: {
  token: string;
  userId: string;
  origin: string;
  input: Record<string, unknown>;
}): Promise<
  | { kind: "complete"; badgeIds: string[]; pluginId: string }
  | { kind: "continue"; pluginId: string; sessionId: string }
  | { kind: "error"; message: string }
> {
  const row = await prisma.wizardSession.findUnique({
    where: { pendingToken: args.token },
  });
  if (!row) return { kind: "error", message: "Link is invalid or already used" };
  if (row.userId !== args.userId) {
    return {
      kind: "error",
      message: "Link belongs to a different account. Sign in as that user and click the link again.",
    };
  }
  if (row.expiresAt < new Date()) {
    return { kind: "error", message: "Link has expired" };
  }
  if (row.completedAt) {
    return { kind: "error", message: "Link is already used" };
  }

  const result = await submitStep(row.id, args.userId, args.origin, args.input);
  if (result.kind === "complete") {
    return { kind: "complete", badgeIds: result.badgeIds, pluginId: row.pluginId };
  }
  if (result.kind === "continue") {
    return { kind: "continue", pluginId: row.pluginId, sessionId: row.id };
  }
  return result;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function issueBadgesAndComplete(args: {
  sessionId: string;
  userId: string;
  pluginId: string;
  issued: IssuedBadge[];
}): Promise<string[]> {
  const { sessionId, userId, pluginId, issued } = args;
  const issuer = await getIssuer();
  const subjectDid = buildUserDid(issuer.domain, userId);

  const createdIds: string[] = [];

  for (const badge of issued) {
    const meta = BADGE_TYPES[badge.type];
    if (!meta) {
      throw new Error(
        `Plugin ${pluginId} produced an unknown badge type: ${badge.type}`,
      );
    }
    const claims = meta.schema.parse(badge.claims);

    // Insert Badge row first so we have an id to use as jti, then
    // update with the signed VC. Two-step avoids a Prisma round-trip
    // dance with a generated cuid.
    const created = await prisma.badge.create({
      data: {
        userId,
        type: badge.type,
        attributes: badge.attributes as Prisma.InputJsonValue,
        vcJwt: "",
        issuer: issuer.did,
        issuedAt: new Date(),
        expiresAt: badge.expiresAt ?? null,
        pluginId,
      },
    });

    const vcJwt = await issueVc(
      issuer,
      badge.type,
      subjectDid,
      claims as Record<string, unknown>,
      { jti: created.id, expiresIn: "1y" },
    );

    await prisma.badge.update({
      where: { id: created.id },
      data: { vcJwt },
    });

    createdIds.push(created.id);

    if (badge.eligibilities && badge.eligibilities.length > 0) {
      for (const e of badge.eligibilities) {
        await prisma.eligibility.upsert({
          where: {
            userId_badgeType: { userId, badgeType: e.badgeType },
          },
          create: {
            userId,
            badgeType: e.badgeType,
            eligibleAt: e.eligibleAt,
            fuzzDays: e.fuzzDays,
            source: pluginId,
          },
          update: {
            eligibleAt: e.eligibleAt,
            fuzzDays: e.fuzzDays,
            source: pluginId,
          },
        });
      }
    }

    await audit(userId, "badge.issued", {
      badgeId: created.id,
      type: badge.type,
      pluginId,
    });
  }

  await prisma.wizardSession.update({
    where: { id: sessionId },
    data: { completedAt: new Date(), pendingToken: null },
  });

  return createdIds;
}
