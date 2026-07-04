import type { IssuedBadge, PluginContext, WizardState } from "@minister/plugin-sdk";

import type { Prisma } from "@/generated/prisma";
import { audit } from "@/lib/audit";
import { sendMail } from "@/lib/mailer";
import { ensureDedupHandle, nullifierService, runPostCommit } from "@/lib/nullifier";
import { prisma } from "@/lib/prisma";
import { getPlugin } from "@/plugins/registry";
import { issueBadge } from "@/server/issue-badge";
import { pendingTokenFor } from "@/server/wizard-helpers";

// Thrown when a Sybil-anchored badge's credential is already linked to another
// account (registerDedup → `taken`). Surfaced to the wizard UI as an error, not
// a 500.
export class SybilTakenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SybilTakenError";
  }
}

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

function hydrate(row: {
  id: string;
  userId: string;
  pluginId: string;
  state: unknown;
}): WizardState {
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

export async function loadWizard(sessionId: string, userId: string): Promise<WizardState | null> {
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
      try {
        const badgeIds = await issueBadgesAndComplete({
          sessionId,
          userId,
          pluginId: row.pluginId,
          issued: result.badges,
        });
        return { kind: "complete", badgeIds };
      } catch (err) {
        // A Sybil-dedup collision is a user-facing outcome (this credential is
        // already linked elsewhere), not a server fault — surface its message.
        if (err instanceof SybilTakenError) {
          return { kind: "error", message: err.message };
        }
        throw err;
      }
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
      message:
        "Link belongs to a different account. Sign in as that user and click the link again.",
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

// THE central Sybil-anchor discard point. Any plugin that emits an
// `IssuedBadge.sybilAnchor` gets the SAME treatment here — nowhere else:
//   1. nullify the anchor (registerDedup) BEFORE minting, refusing a `taken`
//      credential;
//   2. persist only the opaque Badge.nullifierRef;
//   3. DISCARD the raw anchor (it is never passed to issueBadge, so it never
//      reaches Badge.attributes/claims or the VC);
//   4. SCRUB the wizard-session state on completion so no anchor a plugin
//      stashed in `state.data` across a round trip survives at rest.
//
// ⚠ registerDedup performs network I/O in the Phase 3 backend: it runs here,
// OUTSIDE any transaction (issueBadge opens its own per-badge tx). A fresh
// `registered` entry is released if the subsequent mint fails, so a signing
// error never strands the credential.
async function issueBadgesAndComplete(args: {
  sessionId: string;
  userId: string;
  pluginId: string;
  issued: IssuedBadge[];
}): Promise<string[]> {
  const { sessionId, userId, pluginId, issued } = args;

  const anchorSeen = issued.some((b) => typeof b.sybilAnchor === "string");
  // Minted once, lazily, only if this batch actually nullifies something.
  let ownerHandle: string | null = null;

  const createdIds: string[] = [];
  for (const badge of issued) {
    let nullifierRef: string | null = null;
    let freshlyRegistered = false;

    if (typeof badge.sybilAnchor === "string") {
      if (!ownerHandle) ownerHandle = await ensureDedupHandle(userId);
      const reg = await nullifierService.registerDedup({
        anchor: badge.sybilAnchor,
        badgeType: badge.type,
        ownerHandle,
      });
      if (reg.status === "taken") {
        // One-credential-one-account. Message is intentionally concrete for the
        // only anchor-emitting plugin today (github); generic wiring, specific copy.
        throw new SybilTakenError(
          "This GitHub account is already linked to another Minister account.",
        );
      }
      nullifierRef = reg.entryRef;
      freshlyRegistered = reg.status === "registered";
    }

    // Shared mint path — see src/server/issue-badge.ts. `badge` is an
    // IssuedBadge; issueBadge reads only BadgeToIssue fields, so `sybilAnchor`
    // is structurally dropped and never persisted.
    try {
      createdIds.push(await issueBadge({ userId, pluginId, badge, nullifierRef }));
    } catch (err) {
      // Compensate: a just-created ledger entry with no badge would strand the
      // credential. Release ONLY a fresh registration (never an `already_yours`
      // entry that predates this issuance).
      if (freshlyRegistered && nullifierRef && ownerHandle) {
        const handle = ownerHandle;
        const ref = nullifierRef;
        await runPostCommit(
          () => nullifierService.release({ entryRef: ref, ownerHandle: handle }),
          "release-after-mint-failure",
        );
      }
      if (err instanceof Error && err.message.startsWith("Unknown badge type:")) {
        throw new Error(`Plugin ${pluginId} produced an ${err.message.toLowerCase()}`);
      }
      throw err;
    }
  }

  await prisma.wizardSession.update({
    where: { id: sessionId },
    data: {
      completedAt: new Date(),
      pendingToken: null,
      // Scrub-on-completion: once an anchor has been nullified, overwrite the
      // persisted state so nothing a plugin stashed across the round trip
      // (github: none; email-domain in Phase 5: the address) survives at rest.
      ...(anchorSeen ? { state: { scrubbed: true } as Prisma.InputJsonValue } : {}),
    },
  });

  return createdIds;
}
