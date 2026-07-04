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

// Does the raw Sybil anchor appear as a VALUE anywhere in `node`? Walk the
// object/array tree and compare STRING-typed leaves for equality to the anchor,
// rather than substring-scanning JSON.stringify (Finding 5). The anchor is
// always a string (`sybilAnchor: String(facts.id)`), so a genuine leak copies
// it as a string leaf; a substring scan false-refused a legit user whose
// numeric claim merely shared digits with the id (github id "60" is a substring
// of the serialized `"olderThanMonths":60`). Numbers are DELIBERATELY not
// stringified for the compare: a numeric claim (olderThanMonths, followersAtLeast)
// can legitimately equal the id's digits, and flagging it would refuse a real
// credential — the badge types that carry numbers are exactly the ones that
// collide. Fail-closed on a real string match.
function anchorAppearsAsValue(node: unknown, anchor: string): boolean {
  if (typeof node === "string") return node === anchor;
  if (Array.isArray(node)) return node.some((v) => anchorAppearsAsValue(v, anchor));
  if (node !== null && typeof node === "object") {
    return Object.values(node).some((v) => anchorAppearsAsValue(v, anchor));
  }
  return false;
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
  // Fresh (first-sighting) ledger registrations from THIS batch, for
  // compensating release on a mid-batch abort. Never includes an
  // `already_yours` entry that predates the batch. Within a batch every badge
  // has a distinct type, so registerDedup keys (anchor, type) never collide —
  // no two refs here are shared, and releasing them can free no live sibling.
  const freshRegs: Array<{ ref: string; handle: string }> = [];

  // Undo a partially-applied batch on abort: delete the badges already minted
  // in this call and release only this batch's fresh registrations, leaving the
  // account exactly as before the attempt (no orphan badge, no stranded entry).
  // Scrubs the session state too when the batch carried an anchor, so a
  // plugin-stashed anchor never rides the dead session's TTL at rest.
  const compensateBatch = async (): Promise<void> => {
    if (createdIds.length > 0) {
      await prisma.badge.deleteMany({ where: { id: { in: createdIds }, userId } });
    }
    for (const { ref, handle } of freshRegs) {
      await runPostCommit(
        () => nullifierService.release({ entryRef: ref, ownerHandle: handle }),
        "release-on-batch-abort",
      );
    }
    if (anchorSeen) {
      await prisma.wizardSession.update({
        where: { id: sessionId },
        data: { state: { scrubbed: true } as Prisma.InputJsonValue },
      });
    }
  };

  // The one-credential-one-account error, raised from two places (the initial
  // registerDedup and the mint-side re-validation re-register). Concrete copy
  // for the only anchor-emitting plugin today (github); generic wiring.
  const takenError = () =>
    new SybilTakenError("This GitHub account is already linked to another Minister account.");

  for (const badge of issued) {
    let nullifierRef: string | null = null;
    const anchor = typeof badge.sybilAnchor === "string" ? badge.sybilAnchor : null;

    if (anchor !== null) {
      // Value-based discard discipline (not just field-based): issueBadge signs
      // schema-parsed claims and persists `attributes` VERBATIM, so a future
      // anchor-emitting plugin that copied the raw anchor into either would leak
      // it at rest despite this central discard point stripping the `sybilAnchor`
      // FIELD. Refuse issuance outright if the anchor VALUE appears in the badge
      // it is meant to have been discarded from — fail closed (Finding 5).
      if (
        anchorAppearsAsValue(badge.attributes, anchor) ||
        anchorAppearsAsValue(badge.claims, anchor)
      ) {
        await compensateBatch();
        throw new Error(
          `Plugin ${pluginId} leaked a Sybil anchor into badge attributes/claims — refusing to issue`,
        );
      }

      if (!ownerHandle) ownerHandle = await ensureDedupHandle(userId);
      const reg = await nullifierService.registerDedup({
        anchor,
        badgeType: badge.type,
        ownerHandle,
      });
      if (reg.status === "taken") {
        await compensateBatch();
        throw takenError();
      }
      nullifierRef = reg.entryRef;
      if (reg.status === "registered") freshRegs.push({ ref: reg.entryRef, handle: ownerHandle });
    }

    // Shared mint path — see src/server/issue-badge.ts. `badge` is an
    // IssuedBadge; issueBadge reads only BadgeToIssue fields, so `sybilAnchor`
    // is structurally dropped and never persisted.
    let createdId: string;
    try {
      createdId = await issueBadge({ userId, pluginId, badge, nullifierRef });
    } catch (err) {
      // A mid-batch mint failure strands the just-registered entry AND leaves any
      // earlier badges in this batch minted (partial success presented as an
      // error). Roll the whole batch back before surfacing the fault.
      await compensateBatch();
      if (err instanceof Error && err.message.startsWith("Unknown badge type:")) {
        throw new Error(`Plugin ${pluginId} produced an ${err.message.toLowerCase()}`);
      }
      throw err;
    }
    createdIds.push(createdId);

    // MINT-SIDE RE-VALIDATION (Finding 1 — the delete-vs-reissue TOCTOU).
    //
    // registerDedup above may return `already_yours` (ref E already exists),
    // but this badge's INSERT lags behind the Ed25519 signing step inside
    // issueBadge. A concurrent deleteBadge of the LAST sibling can, in that
    // window, see a sibling count of 0 and release E — leaving this just-minted,
    // signed badge pointing at a dangling ref while the credential is free for a
    // DIFFERENT account to register: two live signed VCs for one credential, a
    // dedup bypass. The count→release guard in deleteBadge alone does NOT close
    // this (its count runs before this INSERT is visible).
    //
    // Close it here: now that the badge row exists, re-check the ledger entry
    // survived and is still ours. If it is GONE (a concurrent release won the
    // race), the raw anchor is still in memory — re-register it (self-heal) and
    // re-point the badge. A fresh `registered` re-anchors the credential to this
    // account; `already_yours` means a concurrent re-issue of ours already
    // re-created it; `taken` means another account grabbed the freed credential
    // in the gap, so compensate and fail closed. This makes the race
    // self-correct instead of silently bypassing dedup.
    if (anchor !== null && nullifierRef !== null && ownerHandle) {
      const present = await nullifierService.entryExistsForOwner({
        entryRef: nullifierRef,
        ownerHandle,
      });
      if (!present) {
        const reReg = await nullifierService.registerDedup({
          anchor,
          badgeType: badge.type,
          ownerHandle,
        });
        if (reReg.status === "taken") {
          await compensateBatch();
          throw takenError();
        }
        await prisma.badge.update({
          where: { id: createdId },
          data: { nullifierRef: reReg.entryRef },
        });
        nullifierRef = reReg.entryRef;
        if (reReg.status === "registered") {
          freshRegs.push({ ref: reReg.entryRef, handle: ownerHandle });
        }
      }
    }
  }

  await prisma.wizardSession.update({
    where: { id: sessionId },
    data: {
      completedAt: new Date(),
      pendingToken: null,
      // Scrub-on-completion (unconditional): nothing reads a completed session's
      // state again, so overwrite it so no anchor a plugin stashed across a round
      // trip (github: none; email-domain in Phase 5: the address) survives at
      // rest — independent of whether THIS batch carried an anchor.
      state: { scrubbed: true } as Prisma.InputJsonValue,
    },
  });

  return createdIds;
}
