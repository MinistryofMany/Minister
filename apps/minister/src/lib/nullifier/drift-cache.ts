import { createHash, randomFillSync } from "node:crypto";

import { prisma } from "@/lib/prisma";

// Salted stage-2 drift detection (build-plan §2.1). Minister trusts Signet for
// the CORRECTNESS of the per-RP disclosed nullifier (`N_rp`) — stage 2 carries
// no DLEQ, so a buggy or compromised Signet could DRIFT the value for the same
// credential (ban-evasion) or COLLIDE two users (false-linking). Drift is what
// Minister CAN catch: keep one row per (entryRef, clientId) and, on every
// disclosure, recompute the salted digest and compare it to the stored one.
//
// Why a per-row RANDOM salt, and how it avoids the M1 equality oracle: the
// stored `check` is SHA-256(salt || N_rp). With a distinct random salt per row,
// two rows holding the SAME N_rp produce UNRELATED digests, so the table
// exposes no cross-row equality structure and no dictionary/preimage surface
// over N_rp values — exactly the property the M1 ledger move to Signet bought.
// Same-row comparison (this row's salt, this disclosure's N_rp) is all drift
// detection needs, and it is the ONLY comparison ever done. (False-linking —
// two users sharing an N_rp at one RP — is undetectable without cross-row
// equality, which M1 forbids; it stays inside Signet's documented trust
// envelope, per §2.1.)

// Digest of a nullifier under a given salt. The nullifier is a `mnv1:` ASCII
// string; its UTF-8 bytes are unambiguous. salt is prepended (never
// concatenated bare with a variable-length join that could alias).
// Returns a plain Uint8Array (backed by a non-shared ArrayBuffer) so it slots
// straight into Prisma's `Bytes` input without the Buffer/SharedArrayBuffer
// variance mismatch.
function digest(salt: Uint8Array, nrp: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(32);
  out.set(createHash("sha256").update(salt).update(Buffer.from(nrp, "utf8")).digest());
  return out;
}

// Assert the disclosed nullifier for (entryRef, clientId) matches what Signet
// returned the first time. Throws (fail closed) on drift so the caller omits
// the badge + alerts. A brand-new (entryRef, clientId) records the baseline.
//
// ⚠ Performs a DB write on first sighting — plain Prisma, no Signet I/O — but
// still MUST NOT run inside an open `prisma.$transaction` alongside the Signet
// disclose call (§2.6). loadApprovedBadgeJwts calls it outside any transaction.
export async function assertNullifierDriftConsistent(
  entryRef: string,
  clientId: string,
  nrp: string,
): Promise<void> {
  const existing = await prisma.nullifierRpCheck.findUnique({
    where: { entryRef_clientId: { entryRef, clientId } },
    select: { salt: true, check: true },
  });

  if (existing) {
    const recomputed = digest(existing.salt, nrp);
    // timingSafeEqual is unnecessary (both sides are Minister-local, non-secret
    // digests) but a length guard keeps Buffer.equals well-defined.
    if (!Buffer.from(existing.check).equals(recomputed)) {
      throw new Error(
        `nullifier drift detected for entryRef ${entryRef} at client ${clientId}: ` +
          "Signet returned a different value than first recorded",
      );
    }
    return;
  }

  // First disclosure of this credential to this RP: record the baseline. A
  // concurrent first disclosure of the same pair can race us to the unique
  // index; on P2002 we re-read the winner's row and compare against it, so a
  // genuine drift still fails closed while a benign race succeeds.
  const salt = randomFillSync(new Uint8Array(16));
  try {
    await prisma.nullifierRpCheck.create({
      data: { entryRef, clientId, salt, check: digest(salt, nrp) },
    });
  } catch (err) {
    if (isUniqueViolation(err)) {
      const winner = await prisma.nullifierRpCheck.findUnique({
        where: { entryRef_clientId: { entryRef, clientId } },
        select: { salt: true, check: true },
      });
      if (winner && Buffer.from(winner.check).equals(digest(winner.salt, nrp))) return;
      throw new Error(
        `nullifier drift detected for entryRef ${entryRef} at client ${clientId} ` +
          "(concurrent first disclosure disagreed)",
      );
    }
    throw err;
  }
}

function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    (err as { code?: unknown }).code === "P2002"
  );
}
