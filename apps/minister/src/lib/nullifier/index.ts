import { randomBytes } from "node:crypto";

import { prisma } from "@/lib/prisma";

import { interimBackend } from "./interim";
import { signetBackend, withSignetEntryLock } from "./signet-backend";

// ===========================================================================
// Sybil-dedup nullifier service — FROZEN INTERFACE
// ===========================================================================
//
// One-credential-one-account enforcement, credential-anchored (github account
// id today), catching the multi-account Sybil the pairwise `sub` cannot. Two
// primitives live in this codebase and are PERMANENTLY DISTINCT: this gating
// nullifier (keyed HMAC / VOPRF, gating-only, plaintext-compared, NOT
// circuit-usable) and `@ministryofmany/nullifier` (Poseidon/BN254, sub-anchored,
// circuit-usable). No code path converts between them.
//
// This interface is FROZEN: the Signet backend (Phase 3) implements it
// UNCHANGED. Two backends select behind it by env flag:
//   * interim (Phase 1, THIS wedge): in-Minister HMAC + a Prisma ledger.
//   * signet  (Phase 3): RFC 9497 VOPRF + a ledger inside Signet.
//
// ⚠ CONTRACT — NETWORK I/O: every method here performs network I/O in the
// Signet backend (mTLS round-trips). NEVER call any of them inside an open
// `prisma.$transaction`. Follow the §2.6 post-commit discipline everywhere:
// collect the refs/handles you need INSIDE the transaction, commit, then run
// register/disclose/release/reassign AFTER the commit with idempotent retry.
// The interim backend is written to the same rule so the Phase 3 swap changes
// no call-site structure.

// The disclosed per-RP nullifier, version-prefixed `mnv1:`. Branded so a
// gating-nullifier string can never flow where a BN254 field string (the
// Poseidon primitive) is expected, and vice versa — the two are not
// interchangeable and there is no conversion.
export type MinisterGatingNullifier = string & {
  readonly __brand: "MinisterGatingNullifier";
};

export type RegisterDedupResult =
  { status: "registered" | "already_yours"; entryRef: string } | { status: "taken" };

export interface NullifierService {
  // Record the credential at issuance. `registered` = first sighting (a new
  // ledger entry). `already_yours` = the SAME owner re-issuing/renewing the same
  // credential (idempotent, same entryRef). `taken` = a DIFFERENT owner already
  // holds it → issuance must be refused (one credential, one account).
  registerDedup(input: {
    anchor: string;
    badgeType: string;
    ownerHandle: string;
  }): Promise<RegisterDedupResult>;

  // Derive the per-RP disclosed nullifier from a stored entry. Owner-checked:
  // the supplied handle must match the entry's stored owner or this throws
  // (fail closed — a mis-bound Badge.nullifierRef must never present another
  // user's Sybil nullifier).
  disclose(input: {
    entryRef: string;
    ownerHandle: string;
    clientId: string;
  }): Promise<MinisterGatingNullifier>;

  // Confirm a ledger entry still exists AND is owned by `ownerHandle`. Used for
  // MINT-SIDE RE-VALIDATION (§2.6): after a badge is persisted with its
  // nullifierRef, the runtime re-checks the entry survived, closing the
  // delete-vs-reissue TOCTOU where a concurrent release frees an entry between
  // registerDedup and the lagging badge INSERT. Owner-checked lookup, never a
  // throw — a gone or mis-owned entry returns `false` so the caller can
  // self-heal by re-registering. The Phase 3 Signet backend implements the same
  // owner-checked ref existence check.
  entryExistsForOwner(input: { entryRef: string; ownerHandle: string }): Promise<boolean>;

  // Release an entry so the credential is free to be re-registered from another
  // account (account/badge deletion). Owner-checked; idempotent (releasing a
  // gone entry is a no-op). SIBLING-GUARDED: an entry any Badge row still
  // references must NOT be freed — the interim backend enforces this
  // atomically inside the release statement itself (see interim.ts), because
  // a caller-side check-then-release is a proven dedup-bypass TOCTOU. The
  // Phase 3 signet backend cannot see Minister's Badge table, so the flip
  // MUST re-establish equivalent release atomicity across the split (build
  // plan Phase 3) — callers' correctness rests on it.
  release(input: { entryRef: string; ownerHandle: string }): Promise<void>;

  // Re-tag an EXPLICIT list of entries from one owner handle to another (account
  // merge, and its reverse). Owner-checked per ref; returns the number actually
  // moved. Never wholesale by owner — that could not tell donor-moved entries
  // from entries the survivor already held.
  reassignOwner(input: {
    entryRefs: string[];
    fromOwnerHandle: string;
    toOwnerHandle: string;
  }): Promise<number>;
}

// Backend selection. Default `interim` (Phase 1); `signet` (Phase 3) is the
// VOPRF client against Signet's PRF/dedup surface — flipping is a config
// change, not a code change.
type BackendKind = "interim" | "signet";

function selectBackendKind(): BackendKind {
  const backend = process.env.MINISTER_NULLIFIER_BACKEND ?? "interim";
  if (backend === "interim" || backend === "signet") return backend;
  throw new Error(`Unknown MINISTER_NULLIFIER_BACKEND: ${backend}`);
}

const backendKind: BackendKind = selectBackendKind();

export const nullifierService: NullifierService =
  backendKind === "signet" ? signetBackend : interimBackend;

// MINT-WINDOW SERIALIZATION (Phase 3 release atomicity, see signet-backend.ts
// module doc). The wizard runtime wraps [badge INSERT -> mint-side probe] for
// an anchor-bearing badge in this. Interim backend: a passthrough — its
// release statement is already atomically sibling-guarded in one snapshot.
// Signet backend: a Postgres advisory lock keyed on the entryRef, the same
// lock its release() holds across [sibling check -> /dedup/release], so the
// two windows are totally ordered and the Case-A delete-vs-reissue bypass
// cannot reopen across the Minister/Signet split.
//
// The callback receives `assertLockLive`: a cheap probe that THROWS if the
// serialization guarantee no longer holds (the advisory-lock transaction was
// rolled back, e.g. on timeout, so the window is running unserialized). Call
// it after the last read whose answer the lock must vouch for — the wizard
// calls it after the mint-side probe — so an evaporated lock aborts the mint
// fail-closed instead of trusting an unguarded probe result. Interim backend:
// a no-op (there is no lock whose lifetime could be violated).
export async function serializeMintWindow<T>(
  entryRef: string,
  fn: (assertLockLive: () => Promise<void>) => Promise<T>,
): Promise<T> {
  if (backendKind === "signet") {
    return withSignetEntryLock(entryRef, (tx) =>
      fn(async () => {
        // Throws (P2028) once the lock transaction is gone.
        await tx.$queryRaw`SELECT 1`;
      }),
    );
  }
  return fn(async () => {});
}

// ---------------------------------------------------------------------------
// Owner-handle minting (Minister-side, never leaves Minister)
// ---------------------------------------------------------------------------

// The per-user opaque owner handle: 16 random bytes base64url. Minted LAZILY on
// first use and never regenerated (owner-tag stability is what lets the ledger
// tell `already_yours` from `taken` across re-issues). Concurrency-safe: a
// conditional update claims the null slot; a racing minter that loses re-reads
// the winner's handle.
//
// ⚠ Plain Prisma write (no Signet I/O) — safe to call anywhere, but do NOT call
// it inside a transaction you also intend to run nullifier network methods in.
export async function ensureDedupHandle(userId: string): Promise<string> {
  const existing = await prisma.user.findUnique({
    where: { id: userId },
    select: { dedupHandle: true },
  });
  if (existing?.dedupHandle) return existing.dedupHandle;

  const candidate = randomBytes(16).toString("base64url");
  // Claim the null slot only. count === 0 means a concurrent minter won (or the
  // user vanished); re-read to return the authoritative handle.
  const claimed = await prisma.user.updateMany({
    where: { id: userId, dedupHandle: null },
    data: { dedupHandle: candidate },
  });
  if (claimed.count === 1) return candidate;

  const after = await prisma.user.findUnique({
    where: { id: userId },
    select: { dedupHandle: true },
  });
  if (!after?.dedupHandle) {
    throw new Error(`Failed to mint dedupHandle for user ${userId}`);
  }
  return after.dedupHandle;
}

// ---------------------------------------------------------------------------
// Lifecycle helpers (§2.6 post-commit discipline)
// ---------------------------------------------------------------------------

// Idempotent-retry wrapper for a post-commit nullifier op. On persistent
// failure it logs and swallows: a stranded/temporarily-burned entry is the
// conservative failure mode (never a dedup bypass), reconciled by an admin
// runbook. NEVER let a release/reassign failure fail the user-facing action —
// the DB mutation it follows has already committed.
//
// Retries use jittered exponential backoff: the interim backend fails rarely
// (local Prisma), but the Phase 3 Signet backend's expected failure is a
// transient mTLS/network blip, where immediate retries are worst-case. On
// terminal failure it routes an AuditLog row (best-effort) plus a console alert
// so the admin reconcile runbook has a durable record — not just a log line.
// (Phase 3 follow-up: thread the affected entryRefs into the op signature so the
// audit row can carry them for a targeted reconcile.)
const POSTCOMMIT_BASE_DELAY_MS = 50;

function jitteredBackoffMs(attemptIndex: number): number {
  const base = POSTCOMMIT_BASE_DELAY_MS * 2 ** attemptIndex;
  return base + Math.floor(Math.random() * base);
}

export async function runPostCommit(
  op: () => Promise<unknown>,
  context: string,
  attempts = 3,
): Promise<void> {
  let lastErr: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      await op();
      return;
    } catch (err) {
      lastErr = err;
      // Backoff before the next attempt only (never after the last).
      if (i < attempts - 1) {
        await new Promise((resolve) => setTimeout(resolve, jitteredBackoffMs(i)));
      }
    }
  }
  const message = lastErr instanceof Error ? lastErr.message : String(lastErr);
  // Operational alert; the op is a credential-ledger reconcile, not user data,
  // and carries no secret.
  console.error(`[nullifier] post-commit ${context} failed after ${attempts} attempts:`, lastErr);
  // Durable alert for the admin reconcile runbook. Best-effort: if the DB is the
  // very thing that failed, fall back to the console line already emitted above.
  try {
    await prisma.auditLog.create({
      data: {
        action: "nullifier.postcommit_failed",
        metadata: { context, attempts, error: message },
      },
    });
  } catch (auditErr) {
    console.error(`[nullifier] failed to record post-commit failure for ${context}:`, auditErr);
  }
}

// Capture every ledger ref an account holds, for release on account deletion.
// Read this INSIDE the deletion transaction (or just before it); run the
// releases AFTER commit via runPostCommit. No production account-deletion path
// calls this yet (Minister has no self-serve delete), but badge deletion and a
// future account-deletion both share this shape.
export async function collectUserNullifierRefs(
  userId: string,
): Promise<{ ownerHandle: string | null; entryRefs: string[] }> {
  const [user, badges] = await Promise.all([
    prisma.user.findUnique({ where: { id: userId }, select: { dedupHandle: true } }),
    prisma.badge.findMany({
      where: { userId, nullifierRef: { not: null } },
      select: { nullifierRef: true },
    }),
  ]);
  const entryRefs = badges
    .map((b) => b.nullifierRef)
    .filter((r): r is string => typeof r === "string");
  return { ownerHandle: user?.dedupHandle ?? null, entryRefs };
}
