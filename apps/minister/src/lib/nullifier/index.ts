import { randomBytes } from "node:crypto";

import { prisma } from "@/lib/prisma";

import { interimBackend } from "./interim";

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

  // Release an entry so the credential is free to be re-registered from another
  // account (account/badge deletion). Owner-checked; idempotent (releasing a
  // gone entry is a no-op).
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

// Backend selection. `interim` is the only backend in Phase 1; the flag is
// written now so the Phase 3 signet flip is a config change, not a code change.
function selectBackend(): NullifierService {
  const backend = process.env.MINISTER_NULLIFIER_BACKEND ?? "interim";
  switch (backend) {
    case "interim":
      return interimBackend;
    // case "signet": lands in Phase 3.
    default:
      throw new Error(`Unknown MINISTER_NULLIFIER_BACKEND: ${backend}`);
  }
}

export const nullifierService: NullifierService = selectBackend();

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
    }
  }
  // Operational alert; the op is a credential-ledger reconcile, not user data,
  // and carries no secret.
  console.error(`[nullifier] post-commit ${context} failed after ${attempts} attempts:`, lastErr);
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
