// Server half of the H-1 quarantine gate: loads the user's passkey rows and
// runs the pure evaluation from credential-lifecycle.ts. Three entry points
// for the three calling conventions in the codebase:
//
//   * loadPrivilegedGate     — read-only view for PAGES (banners/disabled
//                              buttons). No audit: rendering a page is not an
//                              attempt.
//   * gatePrivilegedAction   — for actions on the result-returning convention
//                              (merge-actions, recovery-code-actions). Audits
//                              the refusal and hands it back to be embedded in
//                              the action's tagged result.
//   * requirePrivilegedAction— for actions on the throwing convention
//                              (credential-actions). Audits, then throws
//                              PrivilegedActionQuarantineError, which the
//                              action-wrapper transport translates for the
//                              client.
//
// The acting credential id comes from the session's `cred` JWT claim (stamped
// in auth.config.ts on every passkey sign-in / step-up). Callers must have
// already enforced the AAL2 floor and the recovered-session refusal — this
// gate is IN ADDITION to those, never a replacement.

import { audit } from "@/lib/audit";
import {
  evaluatePrivilegedGate,
  PrivilegedActionQuarantineError,
  type PrivilegedActionName,
  type QuarantineRefusal,
} from "@/lib/credential-lifecycle";
import { prisma } from "@/lib/prisma";

async function evaluateForUser(
  userId: string,
  actingCredentialId: string | undefined,
): Promise<QuarantineRefusal | null> {
  const passkeys = await prisma.authenticator.findMany({
    where: { userId },
    select: { credentialID: true, status: true, quarantinedUntil: true },
  });
  return evaluatePrivilegedGate(passkeys, actingCredentialId);
}

export async function loadPrivilegedGate(
  userId: string,
  actingCredentialId: string | undefined,
): Promise<QuarantineRefusal | null> {
  return evaluateForUser(userId, actingCredentialId);
}

export async function gatePrivilegedAction(
  userId: string,
  actingCredentialId: string | undefined,
  action: PrivilegedActionName,
): Promise<QuarantineRefusal | null> {
  const refusal = await evaluateForUser(userId, actingCredentialId);
  if (refusal) {
    // Record every refused attempt: a burst of these is exactly the signal a
    // grafted-credential pivot attempt leaves behind.
    await audit(userId, "credential.quarantine_refused", {
      action,
      reason: refusal.reason,
      retryAt: refusal.retryAt,
    });
  }
  return refusal;
}

export async function requirePrivilegedAction(
  userId: string,
  actingCredentialId: string | undefined,
  action: PrivilegedActionName,
): Promise<void> {
  const refusal = await gatePrivilegedAction(userId, actingCredentialId, action);
  if (refusal) {
    throw new PrivilegedActionQuarantineError(refusal);
  }
}
