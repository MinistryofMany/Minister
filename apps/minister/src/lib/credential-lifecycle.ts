// Credential quarantine lifecycle — the pure half of the H-1 enforcement
// (DESIGNDECISIONS #5/#15). No Prisma, no audit, no next-auth: importable from
// client components (the credentials UI renders "clears in …" hints), from the
// edge-safe auth config, and from server actions alike. The DB-reading gate
// wrappers live in src/lib/credential-gate.ts.
//
// The model: a freshly added email/passkey lands status="quarantined" with a
// quarantinedUntil cooldown (72h, CREDENTIAL_QUARANTINE_MS). While the window
// is open the credential can SIGN IN but must not be able to authorize the
// privileged pivots an account thief wants (start a merge, mint recovery
// codes, change the primary email). Quarantine expires lazily: nothing
// re-stamps the row when the window lapses — effectiveCredentialStatus judges
// the stored status against the clock at read time, and that verdict is what
// both the UI and the gate consume.

import { CREDENTIAL_QUARANTINE_MS } from "@/lib/assurance";

export type CredentialStatus = "active" | "quarantined";

// Narrow a stored status string to the union, defaulting unknowns to active
// (the column default). Quarantine is only meaningful while it's the literal
// "quarantined" AND its window is still open: a quarantine whose
// `quarantinedUntil` has already lapsed reads as active (lazy expiry). This
// read-time check is the single point where an expired quarantine stops
// displaying and stops gating. A quarantined row with a null
// `quarantinedUntil` has no window to lapse, so it stays quarantined.
export function effectiveCredentialStatus(
  status: string,
  quarantinedUntil: Date | null,
  now: number = Date.now(),
): CredentialStatus {
  if (status !== "quarantined") return "active";
  if (quarantinedUntil !== null && quarantinedUntil.getTime() <= now) return "active";
  return "quarantined";
}

// Lifecycle for a passkey being INSERTED (the adapter's createAuthenticator
// seam — write-time, so a raw WebAuthn ceremony that skips the polite
// markPasskeyEnrolled finalize can't dodge it). The FIRST passkey on an
// account is the bootstrap exception (DESIGNDECISIONS #4): it must be active
// immediately or a magic-link-only user could never reach AAL2. Every
// subsequent passkey starts quarantined for the full window.
export function lifecycleForNewPasskey(
  existingPasskeyCount: number,
  now: number = Date.now(),
): { status: CredentialStatus; quarantinedUntil: Date | null } {
  return existingPasskeyCount === 0
    ? { status: "active", quarantinedUntil: null }
    : { status: "quarantined", quarantinedUntil: new Date(now + CREDENTIAL_QUARANTINE_MS) };
}

// Coarse, human duration for "when does this clear" copy. Deliberately fuzzy
// (hours/days, always rounded up) so the promise is kept even if the user
// acts exactly on time, and so SSR/client renders of the same instant agree.
export function describeRemaining(untilMs: number, now: number = Date.now()): string {
  const remaining = untilMs - now;
  if (remaining <= 0) return "moments";
  const hour = 60 * 60 * 1000;
  if (remaining < 1.5 * hour) return "about an hour";
  if (remaining < 48 * hour) return `about ${Math.ceil(remaining / hour)} hours`;
  return `about ${Math.ceil(remaining / (24 * hour))} days`;
}

// ---------------------------------------------------------------------------
// The privileged-action gate (H-1)
// ---------------------------------------------------------------------------

// The four privileged pivots the quarantine cooldown exists to contain.
export type PrivilegedActionName =
  "merge.start" | "merge.confirm" | "recovery-codes.generate" | "email.set-primary";

// A typed, user-presentable refusal. `message` is finished copy the UI can
// render as-is; `retryAt` (ISO) is when the refusal clears by itself, when it
// does; `canStepUp` says whether re-authenticating with an established
// (non-quarantined) passkey clears it right now — the UIs use it to offer the
// passkey ceremony instead of a dead end.
export interface QuarantineRefusal {
  reason: "no-active-passkey" | "acting-passkey-untrusted";
  retryAt: string | null;
  canStepUp: boolean;
  message: string;
}

// Thrown by requirePrivilegedAction (credential-gate.ts) for callers on the
// throwing convention (credential-actions). The action wrappers translate it
// into a tagged result for the client — the message/refusal must NOT be
// expected to cross the RSC boundary as a raw throw (Next.js scrubs thrown
// server-action errors to an opaque digest in production).
export class PrivilegedActionQuarantineError extends Error {
  readonly refusal: QuarantineRefusal;

  constructor(refusal: QuarantineRefusal) {
    super(refusal.message);
    this.name = "PrivilegedActionQuarantineError";
    this.refusal = refusal;
  }
}

export interface GatePasskeyRow {
  credentialID: string;
  status: string;
  quarantinedUntil: Date | null;
}

// The gate, pure. Two layered properties, both required (H-1 fix,
// DESIGNDECISIONS #5/#15):
//
//  1. The user must hold at least one NON-quarantined AAL2 credential (a
//     passkey — the only AAL2 kind today). This is the property that bounds
//     the headline attack: an intruder who grafts a passkey and evicts the
//     original is left holding only a quarantined credential, and the pivots
//     stay closed until the window (which the owner was emailed about) lapses.
//
//  2. When the session says WHICH passkey authenticated it (the `cred` JWT
//     claim, stamped on every passkey sign-in/step-up), that passkey must
//     itself be non-quarantined and still on the account. This closes the
//     subtler pivot: a session riding a fresh graft while the owner's
//     established passkey still exists. It is forgiving by construction — the
//     refusal is cleared instantly by re-authenticating with any established
//     passkey (canStepUp), which the UIs run as a one-tap ceremony.
//
// A session with NO cred claim (minted before the claim existed) passes layer
// 2 by design: fail-open there only ever grandfathers pre-deploy sessions,
// and layer 1 — the property H-1 names — still applies. Returns null when the
// action may proceed.
export function evaluatePrivilegedGate(
  passkeys: GatePasskeyRow[],
  actingCredentialId: string | undefined,
  now: number = Date.now(),
): QuarantineRefusal | null {
  const active = passkeys.filter(
    (p) => effectiveCredentialStatus(p.status, p.quarantinedUntil, now) === "active",
  );

  if (active.length === 0) {
    if (passkeys.length === 0) {
      return {
        reason: "no-active-passkey",
        retryAt: null,
        canStepUp: false,
        message:
          "This action needs a passkey on your account. Add a passkey under Settings → Credentials, then try again.",
      };
    }
    // Only quarantined passkeys. The earliest window to lapse is when the
    // user regains an active passkey and this clears on its own.
    const untils = passkeys
      .map((p) => p.quarantinedUntil)
      .filter((d): d is Date => d !== null)
      .map((d) => d.getTime())
      .sort((a, b) => a - b);
    const retryAtMs = untils[0];
    return {
      reason: "no-active-passkey",
      retryAt: retryAtMs !== undefined ? new Date(retryAtMs).toISOString() : null,
      canStepUp: false,
      message:
        retryAtMs !== undefined
          ? `For your security, this action is paused while your newly added passkey finishes its security hold. It unlocks in ${describeRemaining(retryAtMs, now)}. You can keep signing in and using your account as usual until then.`
          : "For your security, this action is paused while your passkey is in a security hold. You can keep signing in and using your account as usual.",
    };
  }

  if (actingCredentialId !== undefined) {
    const acting = passkeys.find((p) => p.credentialID === actingCredentialId);
    if (!acting) {
      return {
        reason: "acting-passkey-untrusted",
        retryAt: null,
        canStepUp: true,
        message:
          "This session signed in with a passkey that is no longer on your account. Confirm with one of your current passkeys to continue.",
      };
    }
    if (effectiveCredentialStatus(acting.status, acting.quarantinedUntil, now) === "quarantined") {
      const retryAtMs = acting.quarantinedUntil?.getTime();
      return {
        reason: "acting-passkey-untrusted",
        retryAt: retryAtMs !== undefined ? new Date(retryAtMs).toISOString() : null,
        canStepUp: true,
        message:
          retryAtMs !== undefined
            ? `For your security, this change can't be approved by the passkey you added recently while it's in its security hold. Confirm with one of your other passkeys, or wait — the new passkey clears in ${describeRemaining(retryAtMs, now)}.`
            : "For your security, this change can't be approved by a passkey that's in a security hold. Confirm with one of your other passkeys.",
      };
    }
  }

  return null;
}
