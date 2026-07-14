import type { IssuedBadge, PluginContext, WizardState } from "@minister/plugin-sdk";
import { OAUTH_PROVIDERS } from "@minister/shared";

import type { Prisma } from "@/generated/prisma";
import { audit } from "@/lib/audit";
import { sendMail } from "@/lib/mailer";
import {
  ensureDedupHandle,
  nullifierService,
  runPostCommit,
  serializeMintWindow,
} from "@/lib/nullifier";
import { prisma } from "@/lib/prisma";
import { getPlugin, isPluginConfigured } from "@/plugins/registry";
import { issueBadge } from "@/server/issue-badge";
import { pendingTokenFor, toClientState } from "@/server/wizard-helpers";

// Thrown when a Sybil-anchored badge's credential is already linked to another
// account (registerDedup → `taken`). Surfaced to the wizard UI as an error, not
// a 500.
export class SybilTakenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SybilTakenError";
  }
}

// Thrown when startWizard is asked for a plugin that's registered but not
// deployment-configured (e.g. GitHub OAuth creds unset in prod). The
// add-a-badge menu already hides the entry (listAvailablePlugins) and the
// wizard page route already 404s before reaching here — this is the
// defense-in-depth backstop so ANY caller of startWizard, present or future,
// fails on a clean, named error instead of the plugin's own startWizard()
// throwing mid-flow.
export class PluginNotConfiguredError extends Error {
  constructor(pluginId: string) {
    super(`Plugin "${pluginId}" is not configured on this deployment.`);
    this.name = "PluginNotConfiguredError";
  }
}

// Thrown when startWizard is called while the user's Private Identity enrollment
// is PENDING_BACKUP (spec §6.4): no badge value may be built on a seed that
// hasn't been backed up. Carries the settings link the UI renders so the user
// can go finish the backup. Only raised when the flag is on and the user is
// mid-enrollment — `none` and ACTIVE users never see it.
export class AnonBackupPendingError extends Error {
  readonly href = "/settings/private-identity";
  constructor() {
    super("Finish backing up your Private Identity key before adding badges.");
    this.name = "AnonBackupPendingError";
  }
}

const SESSION_TTL_MINUTES = 60;

// Copy for a mint that failed on issuance INFRASTRUCTURE (Signet down/slow,
// lock contention, DB pool exhaustion) — retryable, nothing persisted.
// Exported so tests pin the exact user-facing copy.
export const ISSUANCE_UNAVAILABLE_MESSAGE =
  "Badge issuance is temporarily unavailable. Please try again in a moment.";

// Is this mint failure an issuance-infrastructure fault (retryable, expected
// once the nullifier backend is a network service) rather than a programmer
// error? Matched fail-open toward throwing: only the two shapes we KNOW are
// infrastructure — nullifier-backend errors (every error the backends raise
// is "nullifier:"-prefixed) and Prisma pool/transaction-lifetime faults
// (P2024 pool timeout, P2028 transaction closed/rolled back) — are mapped to
// the wizard's error UI; anything else still throws.
function isIssuanceInfraError(err: unknown): boolean {
  if (err instanceof Error && err.message.startsWith("nullifier:")) return true;
  const code =
    typeof err === "object" && err !== null ? (err as { code?: unknown }).code : undefined;
  return code === "P2024" || code === "P2028";
}

function nowPlusMinutes(min: number): Date {
  return new Date(Date.now() + min * 60_000);
}

// Best-effort at-rest cleanup: a raw address a plugin stashes in `state.data`
// across a magic-link round trip lives on the WizardSession row until the flow
// completes (scrub-on-completion) or is undone (compensateBatch scrub). The
// ABANDONED path — form submitted, link never clicked, user never returns — has
// no such trigger, so without an expiry sweep the lowercased address would sit
// at rest indefinitely, past the session TTL the plugin comments claim bounds
// it. Deleted-on-observe (below) covers a revisited-after-expiry session;
// sweepExpiredWizardSessions covers the never-revisited one, piggybacked on
// startWizard so any wizard use purges the backlog (there is no scheduler yet).
export async function sweepExpiredWizardSessions(): Promise<number> {
  const { count } = await prisma.wizardSession.deleteMany({
    where: { completedAt: null, expiresAt: { lt: new Date() } },
  });
  return count;
}

// Delete a single observed-expired, uncompleted session. Best-effort: a failed
// delete must not turn a user-facing "expired" response into a 500; the sweep
// is the backstop. deleteMany (not delete) so a concurrent purge is a no-op,
// not a P2025 throw.
async function deleteExpiredSession(id: string): Promise<void> {
  try {
    await prisma.wizardSession.deleteMany({ where: { id, completedAt: null } });
  } catch (err) {
    console.error("[wizard] failed to delete expired session:", err);
  }
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
const PROVIDER_SLUGS = new Set<string>(OAUTH_PROVIDERS);
function anchorAppearsAsValue(node: unknown, anchor: string): boolean {
  if (typeof node === "string") return node === anchor;
  if (Array.isArray(node)) return node.some((v) => anchorAppearsAsValue(v, anchor));
  if (node !== null && typeof node === "object") {
    // `provider` is a fixed, low-cardinality plugin CONSTANT (the slug: "steam",
    // "reddit", "hackernews", …), never derived from user input, so it can never
    // be an anchor-leak vector — exempt it so a user whose id/handle happens to
    // equal their provider slug (an HN account literally named "hackernews")
    // doesn't trip the guard on the account-age badge, which carries `provider`
    // but not the handle (and so, unlike oauth-account, has no revealsAnchor).
    // The exemption is narrowed to a value that really IS a registered slug, so a
    // field-swap bug that put a raw id under a `provider` key is still caught.
    return Object.entries(node).some(([key, v]) => {
      if (key === "provider" && typeof v === "string" && PROVIDER_SLUGS.has(v)) {
        return false;
      }
      return anchorAppearsAsValue(v, anchor);
    });
  }
  return false;
}

// Per-provider display noun for an oauth-account-family `taken` refusal. github
// keeps the exact wording pinned by the discard/signet-race tests; the other
// providers get their own noun so the copy is correct once the oauth-account
// type is no longer github-only. An unknown provider falls back to generic.
const OAUTH_PROVIDER_NOUNS: Record<string, string> = {
  github: "GitHub account",
  google: "Google account",
  discord: "Discord account",
  reddit: "Reddit account",
  steam: "Steam account",
  hackernews: "Hacker News account",
};

// The user-facing credential noun for a `taken` (one-credential-one-account)
// refusal, keyed on the badge type and (for the oauth family) the provider. The
// email types get their own noun (Phase 5, when email became the second
// anchor-emitting plugin). Fallback is generic.
function takenCredentialNoun(badgeType: string, provider?: string): string {
  if (badgeType === "email-domain" || badgeType === "email-exact") return "email address";
  if (
    badgeType === "oauth-account" ||
    badgeType === "account-age" ||
    badgeType === "social-following"
  ) {
    return (provider ? OAUTH_PROVIDER_NOUNS[provider] : undefined) ?? "connected account";
  }
  return "credential";
}

// The `provider` claim on an oauth-account-family badge, if present, so the
// `taken` copy can name the right service.
function providerOf(badge: IssuedBadge): string | undefined {
  const p = (badge.claims as { provider?: unknown }).provider;
  return typeof p === "string" ? p : undefined;
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

// A wizard session's persisted `state` is overwritten with `{ scrubbed: true }`
// once the batch is terminal (success OR compensated abort), so it carries no
// `currentStep`. Such a row must never be hydrated back into the client renderer
// or a plugin — both dereference `currentStep` and would 500. Detect it at the
// load boundary and treat the session as gone (belt-and-suspenders alongside the
// terminal-marking in issueBadgesAndComplete, which also keeps these rows off the
// `completedAt: null` queries in the first place).
function isScrubbedRow(row: { state: unknown }): boolean {
  const s = row.state;
  return (
    s === null || typeof s !== "object" || (s as { currentStep?: unknown }).currentStep == null
  );
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
  if (!isPluginConfigured(plugin)) throw new PluginNotConfiguredError(pluginId);

  // Badge gate (spec §6.4): refuse to start any badge wizard while the user's
  // Private Identity enrollment is PENDING_BACKUP, so nobody builds badge value
  // on an unbackuped seed. No-op when the flag is off or the user has no
  // in-progress enrollment (isAnonBackupPending returns false for none/active).
  // Imported lazily so the env-coupled gate module stays out of wizard.ts's
  // static graph — submitStep-only unit tests must not have to stub env just to
  // load this file.
  const { isAnonBackupPending } = await import("@/lib/anon-seed/backup-gate");
  if (await isAnonBackupPending(userId)) throw new AnonBackupPendingError();

  const ctx = buildPluginContext(userId, origin);
  const state = await plugin.startWizard(ctx);

  // Purge globally-expired abandoned sessions (their at-rest address is past
  // TTL). Best-effort: a sweep failure must not block a new wizard.
  try {
    await sweepExpiredWizardSessions();
  } catch (err) {
    console.error("[wizard] expired-session sweep failed:", err);
  }

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

  // Never return the pending-token secret (or the server-side `data`) to the
  // initiating browser — a server action serializes the whole value over the
  // wire. The DB row above holds the full state; the client gets a scrubbed copy.
  return { sessionId: row.id, state: toClientState(state) };
}

export async function loadWizard(sessionId: string, userId: string): Promise<WizardState | null> {
  const row = await prisma.wizardSession.findFirst({
    where: { id: sessionId, userId, completedAt: null },
  });
  if (!row) return null;
  if (row.expiresAt < new Date()) {
    // TTL-bound the at-rest address: delete on observation, don't just ignore.
    await deleteExpiredSession(row.id);
    return null;
  }
  // A terminal (scrubbed) session has no step to render — behave as if it's gone
  // so the page restarts the wizard instead of 500ing on an undefined step.
  if (isScrubbedRow(row)) return null;
  // The loaded state feeds the client-rendered wizard, so scrub its secrets/data.
  return toClientState(hydrate(row));
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
    // Delete the observed-expired row so its at-rest address is TTL-bounded.
    await deleteExpiredSession(row.id);
    return { kind: "error", message: "Wizard session expired" };
  }
  // A terminal (scrubbed) session can't be resumed — its step is gone. Surface a
  // restart-able error rather than handing an undefined step to the plugin.
  if (isScrubbedRow(row)) {
    return { kind: "error", message: "This verification was reset — start over." };
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
      // Persist the full state (above) but hand the browser a scrubbed copy:
      // the magic-link `expectedToken` (and the raw address in `data`) must
      // never cross the server-action wire (capture-at-verify, build-plan §2.3).
      return { kind: "continue", state: toClientState(result.state) };
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
        // An issuance-infrastructure fault (Signet outage/timeout, lock or
        // pool contention) is a RETRYABLE user-facing outcome: the batch was
        // compensated (no badge, no ledger entry, session not completed), so
        // surface the wizard's error UI, not a generic server-action 500.
        // The ops trail stays server-side: console alert + audit row (the
        // backends' messages carry statuses and opaque refs only).
        if (isIssuanceInfraError(err)) {
          const message = err instanceof Error ? err.message : String(err);
          console.error(
            `[wizard] issuance infrastructure failure (plugin ${row.pluginId}): ${message}`,
          );
          try {
            await audit(userId, "wizard.issuance_unavailable", {
              pluginId: row.pluginId,
              error: message,
            });
          } catch (auditErr) {
            // The audit trail must never turn a mapped, user-retryable
            // failure back into a 500 — the console line above stands.
            console.error("[wizard] failed to audit issuance failure:", auditErr);
          }
          return { kind: "error", message: ISSUANCE_UNAVAILABLE_MESSAGE };
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

  // In-flight-wizard backup gate (spec §6.4): the single completion choke point
  // every badge-issuance path routes through. startWizard already refuses to
  // START a wizard mid-enrollment, but a user can generate a seed (→
  // PENDING_BACKUP) AFTER a wizard began and then reach completion here — so
  // re-check at the terminal step, before anything is minted. No-op for
  // none/ACTIVE users and when the flag is off (isAnonBackupPending returns
  // false for all three), so it never bites a user without an in-progress
  // enrollment. Lazily imported to keep the env-coupled gate out of wizard.ts's
  // static graph (mirrors the startWizard gate).
  const { isAnonBackupPending } = await import("@/lib/anon-seed/backup-gate");
  if (await isAnonBackupPending(userId)) throw new AnonBackupPendingError();

  const anchorSeen = issued.some((b) => typeof b.sybilAnchor === "string");
  // Minted once, lazily, only if this batch actually nullifies something.
  let ownerHandle: string | null = null;

  const createdIds: string[] = [];
  // Fresh (first-sighting) ledger registrations from THIS batch, for
  // compensating release on a mid-batch abort. Never includes an
  // `already_yours` entry that predates the batch. Within a batch every badge
  // has a distinct type, so registerDedup keys (anchor, type) never collide —
  // but that guarantee is INTRA-BATCH ONLY: a concurrent same-user batch can
  // get `already_yours` against one of these fresh registrations and mint a
  // live badge pointing at it, so an unconditional release here could free an
  // entry that badge references (W-1). The releases in compensateBatch go
  // through nullifierService.release, whose interim implementation deletes
  // atomically only when NO Badge row references the entry — the sibling
  // guard lives in the release statement itself, not in this bookkeeping.
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
        data: {
          // Mirror the success-path scrub: an aborted batch is TERMINAL, so mark
          // the session completed and drop its pendingToken alongside scrubbing
          // the state. Scrubbing alone (without completedAt/pendingToken) left a
          // resumable session whose `state` no longer has a `currentStep`, so a
          // later loadWizard/resume would hydrate an undefined step and 500 in
          // toClientState/handleStep. Terminal-marking keeps it off both paths.
          completedAt: new Date(),
          pendingToken: null,
          state: { scrubbed: true } as Prisma.InputJsonValue,
        },
      });
    }
  };

  // The one-credential-one-account error, raised from two places (the initial
  // registerDedup and the mint-side re-validation re-register). The credential
  // noun is derived from the badge type so the copy is correct per anchor plugin
  // (github vs email); the oauth phrasing is unchanged from before Phase 5.
  const takenError = (badge: IssuedBadge) =>
    new SybilTakenError(
      `This ${takenCredentialNoun(badge.type, providerOf(badge))} is already linked to another Minister account.`,
    );

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
      //
      // EXCEPT a badge that reveals its anchor BY DESIGN (`revealsAnchor`, today
      // only email-exact): there the normalized address IS the disclosed claim,
      // so the value legitimately appears — the guard would else refuse every
      // such badge. The opt-out is explicit and per-badge; every anchor-hiding
      // badge keeps the guard.
      if (
        !badge.revealsAnchor &&
        (anchorAppearsAsValue(badge.attributes, anchor) ||
          anchorAppearsAsValue(badge.claims, anchor))
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
        throw takenError(badge);
      }
      nullifierRef = reg.entryRef;
      if (reg.status === "registered") freshRegs.push({ ref: reg.entryRef, handle: ownerHandle });
    }

    // Shared mint path — see src/server/issue-badge.ts. `badge` is an
    // IssuedBadge; issueBadge reads only BadgeToIssue fields, so `sybilAnchor`
    // is structurally dropped and never persisted.
    //
    // MINT-SIDE RE-VALIDATION (Finding 1 — the delete-vs-reissue TOCTOU).
    //
    // registerDedup above may return `already_yours` (ref E already exists),
    // but this badge's INSERT lags behind the Ed25519 signing step inside
    // issueBadge. A concurrent deleteBadge of the LAST sibling can, in that
    // window, decide to release E — leaving this just-minted, signed badge
    // pointing at a dangling ref while the credential is free for a DIFFERENT
    // account to register: two live signed VCs for one credential, a dedup
    // bypass.
    //
    // The probe covers exactly ONE ordering: a release that COMMITS BEFORE
    // this badge's INSERT commits is visible as a gone entry → self-heal
    // below. It cannot guard a release that fires AFTER it returns true (a
    // one-shot read has no forward reach — two prior fix attempts died on
    // that). That ordering is closed on the RELEASE side, per backend:
    //   * interim — release deletes the entry atomically only when no Badge
    //     row references it (lib/nullifier/interim.ts), and this badge's row
    //     is committed by the time the probe runs, so a later release no-ops.
    //   * signet — the ledger lives across the network, so the equivalent is
    //     SERIALIZATION: serializeMintWindow holds the per-entryRef advisory
    //     lock across [INSERT → probe], and the signet backend's release
    //     holds the same lock across [sibling check → /dedup/release]
    //     (lib/nullifier/signet-backend.ts). Interim: passthrough.
    // The mechanisms COMPOSE — keep both halves.
    //
    // The probe runs INSIDE the try: in the signet backend it is a network
    // round trip, and a transport failure must roll the whole batch back
    // (wizard error, retryable, no reservation leak) — compensateBatch runs
    // AFTER the lock window so its releases can take the same lock.
    let createdId: string;
    let entryPresent = true;
    try {
      if (nullifierRef !== null && ownerHandle !== null) {
        const ref = nullifierRef;
        const handle = ownerHandle;
        const minted = await serializeMintWindow(ref, async (assertLockLive) => {
          const id = await issueBadge({ userId, pluginId, badge, nullifierRef: ref });
          // Record immediately: if the probe below throws, compensateBatch
          // must still delete this badge.
          createdIds.push(id);
          const present = await nullifierService.entryExistsForOwner({
            entryRef: ref,
            ownerHandle: handle,
          });
          // The probe's answer is only trustworthy if the advisory lock was
          // held throughout: if the lock transaction died mid-window (e.g. a
          // stalled signing call ate the budget), a release may have run
          // unserialized after the probe read `present`. Throws in that case
          // → the whole batch compensates, fail-closed. Note the badge INSERT
          // committed BEFORE this point, so a release that takes the lock
          // after a liveness pass here always sees the sibling and no-ops.
          await assertLockLive();
          return { id, present };
        });
        createdId = minted.id;
        entryPresent = minted.present;
      } else {
        createdId = await issueBadge({ userId, pluginId, badge, nullifierRef });
        createdIds.push(createdId);
      }
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

    // Self-heal: if the entry is GONE, the raw anchor is still in memory —
    // re-register it and re-point the badge. A fresh `registered` re-anchors
    // the credential to this account; `already_yours` means a concurrent
    // re-issue of ours already re-created it; `taken` means another account
    // grabbed the freed credential in the gap, so compensate and fail closed.
    // This makes the race self-correct instead of silently bypassing dedup.
    //
    // The re-registration itself runs outside any lock (compensateBatch on
    // the `taken` path must be free to take the release lock), but the
    // REPOINT + verification run INSIDE serializeMintWindow on the NEW ref:
    // for `registered` the fresh entry is unreachable by any release until
    // our repoint commits (nobody else holds its ref), but for
    // `already_yours` the entry belongs to a CONCURRENT re-issue of ours
    // whose badge could be deleted — its release must be ordered against our
    // repoint, or it could free the entry between our re-register and our
    // update. Under the lock, a release either runs first (the in-window
    // probe sees the entry gone → loop and re-register again) or after our
    // committed repoint (its fresh sibling count sees our badge → no-op).
    //
    // Every failure here — re-register outage, repoint failure, probe
    // outage, attempts exhausted — compensates the WHOLE batch before
    // rethrowing: this block runs outside the mint-window try above, and an
    // uncompensated exit would strand a live signed badge with no ledger
    // entry (the Phase-1 dedup bypass, reopened). freshRegs records a fresh
    // re-registration BEFORE the repoint so a repoint failure releases it.
    if (anchor !== null && nullifierRef !== null && ownerHandle && !entryPresent) {
      const handle = ownerHandle;
      try {
        let healedRef: string | null = null;
        for (let attempt = 0; attempt < 3 && healedRef === null; attempt++) {
          const reReg = await nullifierService.registerDedup({
            anchor,
            badgeType: badge.type,
            ownerHandle: handle,
          });
          if (reReg.status === "taken") {
            throw takenError(badge);
          }
          if (reReg.status === "registered") {
            freshRegs.push({ ref: reReg.entryRef, handle });
          }
          const present = await serializeMintWindow(reReg.entryRef, async (assertLockLive) => {
            await prisma.badge.update({
              where: { id: createdId },
              data: { nullifierRef: reReg.entryRef },
            });
            const stillThere = await nullifierService.entryExistsForOwner({
              entryRef: reReg.entryRef,
              ownerHandle: handle,
            });
            await assertLockLive();
            return stillThere;
          });
          if (present) healedRef = reReg.entryRef;
        }
        if (healedRef === null) {
          // Interim backend residual (no lock): a hostile interleaving could
          // in principle keep winning the repoint race — bounded attempts,
          // then fail closed. Unreachable under the signet lock ordering.
          throw new Error("nullifier: mint self-heal could not re-anchor the credential");
        }
        nullifierRef = healedRef;
      } catch (err) {
        await compensateBatch();
        throw err;
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
