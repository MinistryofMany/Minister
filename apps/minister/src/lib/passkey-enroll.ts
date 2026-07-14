// Atomic passkey insert with quarantine lifecycle (H-1, DESIGNDECISIONS #5).
// The DB-coupled half of the write-time stamping rule; the pure decision lives
// in @/lib/credential-lifecycle. Kept out of @/auth so it's unit-testable
// without booting next-auth's Node env.

import type { AdapterAuthenticator } from "next-auth/adapters";

import { lifecycleForNewPasskey } from "@/lib/credential-lifecycle";
import { prisma } from "@/lib/prisma";

// Advisory-lock namespace for the per-user passkey-bootstrap serialization.
// The prefix keeps this lock space disjoint from every other advisory-lock
// user (e.g. the nullifier entry lock).
const PASSKEY_BOOTSTRAP_LOCK_NS = "minister:passkey:bootstrap:";

// Insert a passkey and stamp its quarantine lifecycle atomically. The count
// that decides bootstrap-active vs quarantined and the insert that acts on it
// must be one critical section: two concurrent enrollments on a fresh account
// could otherwise both read 0 and both land active (the bootstrap-count race).
// A per-user, transaction-scoped advisory lock (auto-released on commit OR
// abort, so there is no unlock path to miss on a throw) serializes the
// read -> write for a single user — the second enrollment sees count 1 and is
// quarantined — while enrollments for different users never contend. Returns
// the pre-insert count so the caller can tailor its out-of-band notification
// without re-reading.
export async function insertPasskeyWithLifecycle(
  data: AdapterAuthenticator,
): Promise<{ existing: number; created: AdapterAuthenticator }> {
  const { transports, ...rest } = data;
  return prisma.$transaction(async (tx) => {
    // hashtextextended maps the namespaced key to a stable bigint lock id.
    // Parameterized — never interpolated.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${PASSKEY_BOOTSTRAP_LOCK_NS + data.userId}, 0))`;
    const existing = await tx.authenticator.count({ where: { userId: data.userId } });
    const created = await tx.authenticator.create({
      data: {
        ...rest,
        ...(transports === undefined ? {} : { transports }),
        ...lifecycleForNewPasskey(existing),
      },
    });
    return { existing, created };
  });
}
