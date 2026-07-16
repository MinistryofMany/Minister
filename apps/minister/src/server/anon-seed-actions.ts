"use server";

import { z } from "zod";

import { WRAP_CIPHERTEXT_BYTES, WRAP_IV_BYTES } from "@minister/shared";

import { env } from "@/env";
import { audit } from "@/lib/audit";
import { gatePrivilegedAction } from "@/lib/credential-gate";
import type { QuarantineRefusal } from "@/lib/credential-lifecycle";
import { prisma } from "@/lib/prisma";
import { anonSeedActionLimiter } from "@/lib/rate-limit";
import { getCurrentSession, requireSession } from "@/lib/session";

// Server actions for the anonymous-identity daily-key stack (anon-identity
// master spec §6, §7.1, §11.2). GOVERNING INVARIANT (spec §2): no action here
// ever receives or returns a plaintext seed, per-app secret, KEK, or PRF
// output. `putSeedBlob` persists ONLY the PRF-wrapped ciphertext + IV; the
// server cannot decrypt it. Every action is inert unless ANON_IDENTITY_ENABLED
// is on, and every action gates on the owning session — a blob is readable
// only by the user who wrote it. Fail closed: a disabled flag, a missing
// session, or an invalid input yields an error and touches nothing.

// The 3-value enrollment state (spec §6.1). `none` = no row or seedGeneratedAt
// null; `pending_backup` = seed generated, backup not confirmed; `active` =
// backup confirmed, derivation allowed.
export type AnonSeedStatus = "none" | "pending_backup" | "active";

export interface AnonSeedState {
  status: AnonSeedStatus;
  // Monotonic epoch the client binds into the wrap AAD (spec §7.1). Present
  // even at `none` (the value a first wrap would carry) so the client always
  // has a definite epoch.
  enrollmentEpoch: number;
}

// One stored blob, returned to its owner (ciphertext only). `enrollmentEpoch`
// rides along so the client can rebuild the exact AAD tuple for unwrap.
export interface SeedBlobView {
  credentialId: string;
  ciphertext: string; // base64url of the 32-byte AES-256-GCM output
  iv: string; // base64url of the 12-byte IV
  wrapVersion: number;
  enrollmentEpoch: number;
}

type Ok<T> = { ok: true } & T;
type Err = { ok: false; error: string };
type Result<T> = Ok<T> | Err;

const DISABLED_ERROR = "Private Identity is not enabled.";

// Per-user rate-limit guard for the write actions (spec §13). Fail closed: on
// deny, return an error and the caller bails before any DB write. Keyed on the
// signed-in user id, since these are authenticated actions, not public routes.
function rateLimitGuard(userId: string): Err | null {
  const verdict = anonSeedActionLimiter.check(userId);
  if (verdict.allowed) return null;
  return {
    ok: false,
    error: `Too many requests. Wait ${verdict.retryAfterSeconds}s and try again.`,
  };
}

// At most 5 wrapped blobs per user (spec §7.1). One per (user, credential); a
// re-wrap of an existing credential updates in place and never counts against
// the cap.
const MAX_BLOBS_PER_USER = 5;

// Destructive-reset confirmation (spec §6.1). A reset while ACTIVE mints a new
// seed = a new identity in every app, unrecoverable; require the exact typed
// phrase so it can never be a one-click accident.
const RESET_CONFIRM_PHRASE = "reset my anonymous key";

// Re-key ("I lost my key"): its own typed phrase, distinct from the reset
// phrase so the two destructive surfaces can never be confused for one another.
const REKEY_CONFIRM_PHRASE = "re-key my identity";

// Re-key cooldown backstop (identity plan, O-6 / re-key section). Matches the
// merge-reversal horizon; the real bound on double-action is the sub-keying
// invariant, this only rate-limits the destructive mint. 7 days.
const REKEY_COOLDOWN_MS = 7 * 24 * 60 * 60 * 1000;

// Recent-auth window the re-key gate demands (identity plan): an AAL2 session
// can be hours old, so re-key additionally requires a real authentication in
// the last 5 minutes. Fail closed on a missing/NaN auth_time.
const REKEY_RECENCY_SECS = 5 * 60;

// The bump-epoch-and-purge transaction shared by reset and re-key: increment the
// epoch (anti-rollback, I12), null both timestamps (back to `none`), and delete
// every wrapped blob — atomically. Callers own the authorization; this is the
// mutation only.
async function bumpEpochAndPurge(userId: string) {
  const [row] = await prisma.$transaction([
    prisma.anonSeedEnrollment.update({
      where: { userId },
      data: {
        enrollmentEpoch: { increment: 1 },
        seedGeneratedAt: null,
        backupConfirmedAt: null,
      },
    }),
    prisma.anonSeedBlob.deleteMany({ where: { userId } }),
  ]);
  return row;
}

// A base64url WebAuthn credential id. Capped, charset-restricted; the base64url
// alphabet excludes ":", which the wrap AAD uses as its field separator (§7.1),
// so a valid credentialId can never corrupt that binding.
const CredentialId = z
  .string()
  .min(1)
  .max(512)
  .regex(/^[A-Za-z0-9_-]+$/, "credentialId must be base64url");

const PutBlobInput = z.object({
  credentialId: CredentialId,
  // base64url of the ciphertext / IV. Byte lengths are checked after decode.
  ciphertext: z.string().min(1).max(128),
  iv: z.string().min(1).max(64),
  // Only wrap format v1 exists today; reject anything else rather than store an
  // uninterpretable blob.
  wrapVersion: z.literal(1).default(1),
});

const DeleteBlobInput = z.object({ credentialId: CredentialId });

const ResetInput = z.object({ confirmPhrase: z.string().optional() });

function stateOf(
  row: {
    enrollmentEpoch: number;
    seedGeneratedAt: Date | null;
    backupConfirmedAt: Date | null;
  } | null,
): AnonSeedState {
  if (!row || row.seedGeneratedAt === null) {
    return { status: "none", enrollmentEpoch: row?.enrollmentEpoch ?? 1 };
  }
  return {
    status: row.backupConfirmedAt === null ? "pending_backup" : "active",
    enrollmentEpoch: row.enrollmentEpoch,
  };
}

// Decode base64url and assert an exact byte length. Buffer.from(base64url) is
// lenient (it ignores stray/misaligned chars), so we re-encode and compare to
// reject any non-canonical input rather than silently store a mangled blob.
function decodeExact(value: string, expected: number, field: string): Uint8Array<ArrayBuffer> {
  const buf = Buffer.from(value, "base64url");
  if (buf.length !== expected || buf.toString("base64url") !== value) {
    throw new Error(`${field} must be base64url of exactly ${expected} bytes`);
  }
  // Copy into a fresh ArrayBuffer-backed view (Prisma's Bytes field type).
  return new Uint8Array(buf);
}

// Read the current enrollment state (spec §11.2). Returns the epoch the client
// binds into wrap AADs. Owner-scoped: only the signed-in user's own row.
export async function getAnonSeedState(): Promise<Result<{ state: AnonSeedState }>> {
  if (!env.ANON_IDENTITY_ENABLED) return { ok: false, error: DISABLED_ERROR };
  const session = await requireSession();
  const row = await prisma.anonSeedEnrollment.findUnique({
    where: { userId: session.user.id },
  });
  return { ok: true, state: stateOf(row) };
}

// Record that a fresh seed was generated CLIENT-SIDE (spec §6.1, §6.3 step 1).
// Creates the enrollment row (epoch 1) or, on an existing `none`-state row,
// stamps seedGeneratedAt → PENDING_BACKUP. The server never sees the seed; this
// only records that generation happened. Valid only from `none`; regenerating a
// seed once PENDING/ACTIVE goes through resetAnonSeed (which bumps the epoch).
export async function beginAnonSeedEnrollment(): Promise<Result<{ state: AnonSeedState }>> {
  if (!env.ANON_IDENTITY_ENABLED) return { ok: false, error: DISABLED_ERROR };
  const session = await requireSession();
  const userId = session.user.id;

  const limited = rateLimitGuard(userId);
  if (limited) return limited;

  const existing = await prisma.anonSeedEnrollment.findUnique({ where: { userId } });
  if (existing && existing.seedGeneratedAt !== null) {
    return {
      ok: false,
      error: "Private Identity already enrolled. Reset it before generating a new one.",
    };
  }

  const now = new Date();
  const row = await prisma.anonSeedEnrollment.upsert({
    where: { userId },
    // A brand-new row starts at epoch 1 (schema default); an existing `none`
    // row (e.g. after a PENDING reset) keeps its already-bumped epoch.
    create: { userId, seedGeneratedAt: now },
    update: { seedGeneratedAt: now },
  });

  await audit(userId, "anon_seed.generated", { enrollmentEpoch: row.enrollmentEpoch });
  return { ok: true, state: stateOf(row) };
}

// Confirm the forced-backup quiz passed (spec §6.3 step 3): PENDING_BACKUP →
// ACTIVE. The quiz itself is verified CLIENT-SIDE (the server must never see the
// seed words, §2); this only flips the state. No security control may rest on
// backupConfirmedAt (§6.3 honesty note) — it gates the badge-wizard incentive
// only.
export async function confirmSeedBackup(): Promise<Result<{ state: AnonSeedState }>> {
  if (!env.ANON_IDENTITY_ENABLED) return { ok: false, error: DISABLED_ERROR };
  const session = await requireSession();
  const userId = session.user.id;

  const limited = rateLimitGuard(userId);
  if (limited) return limited;

  const existing = await prisma.anonSeedEnrollment.findUnique({ where: { userId } });
  if (!existing || existing.seedGeneratedAt === null) {
    return { ok: false, error: "Generate a Private Identity before confirming its backup." };
  }
  if (existing.backupConfirmedAt !== null) {
    return { ok: true, state: stateOf(existing) }; // idempotent: already ACTIVE
  }

  const row = await prisma.anonSeedEnrollment.update({
    where: { userId },
    data: { backupConfirmedAt: new Date() },
  });
  await audit(userId, "anon_seed.backup_confirmed", { enrollmentEpoch: row.enrollmentEpoch });
  return { ok: true, state: stateOf(row) };
}

// Store a PRF-wrapped seed blob (spec §7.1 step 6). Persists CIPHERTEXT ONLY —
// the server cannot decrypt it without the browser-only PRF output. Requires
// ACTIVE enrollment (no storage write before ACTIVE, invariant I3). Enforces the
// exact 32-byte ciphertext / 12-byte IV sizes and the 5-blob cap. One row per
// (user, credential): re-wrapping an existing credential updates in place.
export async function putSeedBlob(input: z.infer<typeof PutBlobInput>): Promise<Result<object>> {
  if (!env.ANON_IDENTITY_ENABLED) return { ok: false, error: DISABLED_ERROR };
  const session = await requireSession();
  const userId = session.user.id;

  const limited = rateLimitGuard(userId);
  if (limited) return limited;

  const parsed = PutBlobInput.safeParse(input);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid blob" };
  }

  let ciphertext: Uint8Array<ArrayBuffer>;
  let iv: Uint8Array<ArrayBuffer>;
  try {
    ciphertext = decodeExact(parsed.data.ciphertext, WRAP_CIPHERTEXT_BYTES, "ciphertext");
    iv = decodeExact(parsed.data.iv, WRAP_IV_BYTES, "iv");
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Invalid blob bytes" };
  }

  const enrollment = await prisma.anonSeedEnrollment.findUnique({ where: { userId } });
  if (!enrollment || enrollment.backupConfirmedAt === null) {
    // I3: no storage-layer write before ACTIVE.
    return { ok: false, error: "Finish backing up your Private Identity before storing it." };
  }

  const { credentialId, wrapVersion } = parsed.data;
  const existingForCred = await prisma.anonSeedBlob.findUnique({
    where: { userId_credentialId: { userId, credentialId } },
    select: { id: true },
  });
  if (!existingForCred) {
    const count = await prisma.anonSeedBlob.count({ where: { userId } });
    if (count >= MAX_BLOBS_PER_USER) {
      return {
        ok: false,
        error: `At most ${MAX_BLOBS_PER_USER} devices can store your Private Identity.`,
      };
    }
  }

  await prisma.anonSeedBlob.upsert({
    where: { userId_credentialId: { userId, credentialId } },
    create: { userId, credentialId, ciphertext, iv, wrapVersion },
    update: { ciphertext, iv, wrapVersion },
  });

  // No secret material in the audit metadata (§12 check 13): credentialId is a
  // public WebAuthn handle, wrapVersion a format tag — neither reveals the seed.
  await audit(userId, "anon_seed.blob_stored", {
    credentialId,
    wrapVersion,
    enrollmentEpoch: enrollment.enrollmentEpoch,
  });
  return { ok: true };
}

// List the signed-in user's registered passkey credential ids (public WebAuthn
// handles, no key material) so the client vault can limit its dedicated PRF
// `get()` to them (spec §7.1 step 2, allowCredentials). Quarantined passkeys are
// included on purpose: the PRF wrap is client-side crypto on the user's own
// seed, not a privileged server action, so the H-1 quarantine gate does not
// apply here.
export async function getAnonPasskeyCredentialIds(): Promise<Result<{ credentialIds: string[] }>> {
  if (!env.ANON_IDENTITY_ENABLED) return { ok: false, error: DISABLED_ERROR };
  const session = await requireSession();
  const rows = await prisma.authenticator.findMany({
    where: { userId: session.user.id },
    select: { credentialID: true },
  });
  return { ok: true, credentialIds: rows.map((r) => r.credentialID) };
}

// Return the owner's own wrapped blobs (spec §11.2 fetch-blob). CIPHERTEXT ONLY,
// scoped to the signed-in user by construction — no blob crosses accounts. The
// current epoch rides along so the client rebuilds the unwrap AAD.
export async function getSeedBlobs(): Promise<Result<{ blobs: SeedBlobView[] }>> {
  if (!env.ANON_IDENTITY_ENABLED) return { ok: false, error: DISABLED_ERROR };
  const session = await requireSession();
  const userId = session.user.id;

  const enrollment = await prisma.anonSeedEnrollment.findUnique({ where: { userId } });
  const enrollmentEpoch = enrollment?.enrollmentEpoch ?? 1;

  const rows = await prisma.anonSeedBlob.findMany({
    where: { userId },
    select: { credentialId: true, ciphertext: true, iv: true, wrapVersion: true },
  });
  const blobs = rows.map((r) => ({
    credentialId: r.credentialId,
    ciphertext: Buffer.from(r.ciphertext).toString("base64url"),
    iv: Buffer.from(r.iv).toString("base64url"),
    wrapVersion: r.wrapVersion,
    enrollmentEpoch,
  }));
  return { ok: true, blobs };
}

// Delete one stored blob (spec §11.2), owner-scoped.
export async function deleteSeedBlob(
  input: z.infer<typeof DeleteBlobInput>,
): Promise<Result<object>> {
  if (!env.ANON_IDENTITY_ENABLED) return { ok: false, error: DISABLED_ERROR };
  const session = await requireSession();
  const userId = session.user.id;

  const limited = rateLimitGuard(userId);
  if (limited) return limited;

  const parsed = DeleteBlobInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: "Invalid credential id" };

  const deleted = await prisma.anonSeedBlob.deleteMany({
    where: { userId, credentialId: parsed.data.credentialId },
  });
  if (deleted.count > 0) {
    await audit(userId, "anon_seed.blob_deleted", { credentialId: parsed.data.credentialId });
  }
  return { ok: true };
}

// Reset the anonymous key (spec §6.1): bump the epoch, null both timestamps, and
// delete every blob — atomically. The epoch bump is the anti-rollback property
// (I12): every surviving pre-reset blob fails GCM authentication forever after.
// A reset while ACTIVE is destructive (new seed = new identity everywhere) and
// requires the exact typed confirmation phrase; a reset while PENDING is free.
// The row is NEVER deleted, only reset (spec §6.1).
export async function resetAnonSeed(
  input: z.infer<typeof ResetInput> = {},
): Promise<Result<{ state: AnonSeedState }>> {
  if (!env.ANON_IDENTITY_ENABLED) return { ok: false, error: DISABLED_ERROR };
  const session = await requireSession();
  const userId = session.user.id;

  const limited = rateLimitGuard(userId);
  if (limited) return limited;

  const parsed = ResetInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: "Invalid input" };

  const existing = await prisma.anonSeedEnrollment.findUnique({ where: { userId } });
  if (!existing || existing.seedGeneratedAt === null) {
    return { ok: false, error: "No Private Identity to reset." };
  }

  const wasActive = existing.backupConfirmedAt !== null;
  if (wasActive && parsed.data.confirmPhrase?.trim().toLowerCase() !== RESET_CONFIRM_PHRASE) {
    return {
      ok: false,
      error: `Type "${RESET_CONFIRM_PHRASE}" to confirm — this permanently replaces your anonymous identity in every app.`,
    };
  }

  const row = await bumpEpochAndPurge(userId);

  await audit(userId, "anon_seed.reset", {
    enrollmentEpoch: row.enrollmentEpoch,
    wasActive,
  });
  return { ok: true, state: stateOf(row) };
}

// ---------------------------------------------------------------------------
// Re-key ("I lost my key") — identity plan, O-6 / re-key section.
// ---------------------------------------------------------------------------

const RekeyInput = z.object({ confirmPhrase: z.string().optional() });

export type RekeyResult =
  | { ok: true; state: AnonSeedState }
  // stepUp: below AAL2 or the auth is too old — route into a passkey re-auth.
  | { ok: false; stepUp: true; error: string }
  // The H-1 quarantine gate refused (grafted/quarantined acting credential).
  | { ok: false; quarantine: QuarantineRefusal; error: string }
  // A plain refusal (wrong phrase, cooldown, nothing to re-key, disabled, rate).
  | { ok: false; error: string; retryAt?: string };

// A signed-in user whose account never depended on the seed declares the root
// lost. Gates, hardest first (a re-key destroys the anonymous identity in every
// app): AAL2 + a real auth within 5 minutes + an unquarantined acting credential
// + a 7-day cooldown + the exact typed phrase. Only then bump the epoch and
// purge blobs. The client then generates a fresh root, is forced to back it up,
// and the checklist walks the user through re-keying into each connected app on
// their next login there. Failures are RETURNED, never thrown (prod scrubs a
// thrown server-action message to an opaque digest).
export async function rekeyAnonSeed(input: z.infer<typeof RekeyInput> = {}): Promise<RekeyResult> {
  if (!env.ANON_IDENTITY_ENABLED) return { ok: false, error: DISABLED_ERROR };

  const session = await getCurrentSession();
  if (!session?.user?.id) return { ok: false, error: "Not signed in." };
  const userId = session.user.id;

  const limited = rateLimitGuard(userId);
  if (limited) return limited;

  const parsed = RekeyInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: "Invalid input" };

  // AAL2 floor.
  if ((session.aal ?? 0) < 2) {
    return {
      ok: false,
      stepUp: true,
      error: "Re-keying requires signing in with a passkey first.",
    };
  }

  // 5-minute auth recency. Fail closed on a missing / non-finite auth_time.
  const authTime = session.auth_time;
  const nowSecs = Math.floor(Date.now() / 1000);
  if (
    typeof authTime !== "number" ||
    !Number.isFinite(authTime) ||
    nowSecs - authTime > REKEY_RECENCY_SECS
  ) {
    return {
      ok: false,
      stepUp: true,
      error: "Confirm it's you: re-authenticate with your passkey, then re-key within 5 minutes.",
    };
  }

  // Typed confirmation phrase.
  if (parsed.data.confirmPhrase?.trim().toLowerCase() !== REKEY_CONFIRM_PHRASE) {
    return {
      ok: false,
      error: `Type "${REKEY_CONFIRM_PHRASE}" to confirm — this permanently replaces your anonymous identity in every app.`,
    };
  }

  // H-1 quarantine gate: an unquarantined acting credential is required.
  const refusal = await gatePrivilegedAction(userId, session.cred, "anon-seed.rekey");
  if (refusal) return { ok: false, quarantine: refusal, error: refusal.message };

  // Cooldown backstop: refuse if a successful re-key landed within the window.
  const since = new Date(Date.now() - REKEY_COOLDOWN_MS);
  const recent = await prisma.auditLog.findFirst({
    where: { userId, action: "anon_seed.rekey", createdAt: { gt: since } },
    orderBy: { createdAt: "desc" },
    select: { createdAt: true },
  });
  if (recent) {
    const retryAt = new Date(recent.createdAt.getTime() + REKEY_COOLDOWN_MS).toISOString();
    return {
      ok: false,
      retryAt,
      error: "You re-keyed recently. For your security, re-keying is limited to once a week.",
    };
  }

  // Only an ACTIVE enrollment can be re-keyed (there is an identity to replace).
  const existing = await prisma.anonSeedEnrollment.findUnique({ where: { userId } });
  if (!existing || existing.backupConfirmedAt === null) {
    return { ok: false, error: "You have no active Private Identity to re-key." };
  }

  const row = await bumpEpochAndPurge(userId);
  await audit(userId, "anon_seed.rekey", { enrollmentEpoch: row.enrollmentEpoch });
  return { ok: true, state: stateOf(row) };
}
