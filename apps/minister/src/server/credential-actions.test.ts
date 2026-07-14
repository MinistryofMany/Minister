import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Session } from "next-auth";

// ---------------------------------------------------------------------------
// Unit tests for the credential-management POLICY logic. Prisma, the mailer,
// and the notify side-effect are mocked. The session module is mocked too —
// importing the real one pulls in @/auth (next-auth's Node env), which can't
// load under vitest — but the mock re-implements requireAal / StepUpRequiredError
// faithfully (they're pure, depending only on session.aal), so step-up gating
// is genuinely exercised. No live DB, no network.
// ---------------------------------------------------------------------------

// Shared mock state. vi.hoisted runs before the hoisted vi.mock factories, so
// the factories can safely close over these (a plain top-level `const` can't —
// the factory is hoisted above it). Holds the programmable session, the prisma
// double, and the side-effect spies.
const h = vi.hoisted(() => {
  // A faithful copy of the pure AAL guard's typed error. The class defined here
  // IS the class the action code throws (both import from the mocked session
  // module), so the test's `instanceof StepUpRequiredError` checks are sound.
  class StepUpRequiredError extends Error {
    readonly requiredAal: number;
    readonly currentAal: number;
    constructor(requiredAal: number, currentAal: number) {
      super(`Step-up required: needs AAL${requiredAal} (session is AAL${currentAal})`);
      this.name = "StepUpRequiredError";
      this.requiredAal = requiredAal;
      this.currentAal = currentAal;
    }
  }
  return {
    StepUpRequiredError,
    state: { currentSession: null as unknown },
    notifyCredentialChange: vi.fn(async () => {}),
    sendMail: vi.fn(async () => {}),
    audit: vi.fn(async () => {}),
    db: {
      userEmail: {
        findMany: vi.fn(),
        findUnique: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        updateMany: vi.fn(),
        delete: vi.fn(),
        count: vi.fn(),
      },
      authenticator: {
        findMany: vi.fn(),
        findFirst: vi.fn(),
        findUnique: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        count: vi.fn(),
      },
      account: { findMany: vi.fn() },
      badge: { findMany: vi.fn() },
      user: { update: vi.fn() },
      verificationToken: {
        create: vi.fn(async () => ({})),
        delete: vi.fn(async () => ({})),
      },
      // $transaction(array) resolves each promise (the calls already ran).
      $transaction: vi.fn(async (ops: Promise<unknown>[]) => Promise.all(ops)),
    },
  };
});

// Mock @/lib/session: a programmable getCurrentSession plus a faithful copy of
// the pure AAL guard. Importing the real module pulls in @/auth (next-auth's
// Node env), which can't load under vitest.
vi.mock("@/lib/session", () => ({
  StepUpRequiredError: h.StepUpRequiredError,
  getCurrentSession: vi.fn(async () => h.state.currentSession),
  requireAal: (s: { aal?: number } | null, floor: number) => {
    const current = s?.aal ?? 0;
    if (current < floor) throw new h.StepUpRequiredError(floor, current);
  },
}));

vi.mock("@/lib/credential-notify", () => ({ notifyCredentialChange: h.notifyCredentialChange }));
vi.mock("@/lib/mailer", () => ({ sendMail: h.sendMail }));
vi.mock("@/lib/audit", () => ({ audit: h.audit }));
vi.mock("@/lib/prisma", () => ({ prisma: h.db }));

import { PrivilegedActionQuarantineError } from "@/lib/credential-lifecycle";
import { StepUpRequiredError } from "@/lib/session";

const db = h.db;
const notifyCredentialChange = h.notifyCredentialChange;
const sendMail = h.sendMail;

function setSession(s: Session | null): void {
  h.state.currentSession = s;
}

import {
  addEmail,
  addEmailAction,
  canAddPasskey,
  listCredentials,
  markPasskeyEnrolled,
  removeEmail,
  removePasskey,
  setPrimaryEmail,
  setPrimaryEmailAction,
} from "./credential-actions";

const USER = "user_1";

function session(aal: 0 | 1 | 2, opts: { recovered?: boolean; cred?: string } = {}): Session {
  return {
    user: { id: USER },
    aal,
    ...(opts.recovered ? { recovered: true } : {}),
    ...(opts.cred !== undefined ? { cred: opts.cred } : {}),
    expires: new Date(Date.now() + 3600_000).toISOString(),
  } as Session;
}

// Passkey row shapes for the H-1 gate (credential-gate reads
// prisma.authenticator.findMany through the same mocked client).
function activePasskey(credentialID = "cred_orig") {
  return { credentialID, status: "active", quarantinedUntil: null };
}
function quarantinedPasskey(credentialID = "cred_graft", msFromNow = 3_600_000) {
  return {
    credentialID,
    status: "quarantined",
    quarantinedUntil: new Date(Date.now() + msFromNow),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  setSession(null);
  process.env.AUTH_SECRET = "credential-actions-test-secret-32chars!!";
  db.verificationToken.create.mockResolvedValue({});
  db.verificationToken.delete.mockResolvedValue({});
  db.badge.findMany.mockResolvedValue([]);
  db.$transaction.mockImplementation(async (ops: Promise<unknown>[]) => Promise.all(ops));
});

// ---------------------------------------------------------------------------
// AAL gating — every mutation refuses below its floor with StepUpRequiredError.
// ---------------------------------------------------------------------------

describe("AAL gating", () => {
  it("addEmail below AAL2 throws StepUpRequiredError", async () => {
    setSession(session(1));
    await expect(addEmail("new@example.com")).rejects.toBeInstanceOf(StepUpRequiredError);
    expect(db.userEmail.create).not.toHaveBeenCalled();
  });

  it("removeEmail below AAL2 throws StepUpRequiredError", async () => {
    setSession(session(1));
    await expect(removeEmail("ue_1")).rejects.toBeInstanceOf(StepUpRequiredError);
  });

  it("setPrimaryEmail below AAL2 throws StepUpRequiredError", async () => {
    setSession(session(1));
    await expect(setPrimaryEmail("ue_1")).rejects.toBeInstanceOf(StepUpRequiredError);
  });

  it("removePasskey below AAL2 throws StepUpRequiredError", async () => {
    setSession(session(1));
    await expect(removePasskey("cred_1")).rejects.toBeInstanceOf(StepUpRequiredError);
  });

  it("unauthenticated calls throw 'Not signed in' (not step-up)", async () => {
    setSession(null);
    await expect(addEmail("x@example.com")).rejects.toThrow(/Not signed in/);
  });
});

// ---------------------------------------------------------------------------
// Recovered-session refusal — a reduced-capability session can't graft/evict.
// ---------------------------------------------------------------------------

describe("recovered-session refusal", () => {
  it("addEmail rejects a recovered session even at AAL2", async () => {
    setSession(session(2, { recovered: true }));
    await expect(addEmail("new@example.com")).rejects.toThrow(/recovery session/i);
    expect(db.userEmail.create).not.toHaveBeenCalled();
  });

  it("removePasskey rejects a recovered session even at AAL2", async () => {
    setSession(session(2, { recovered: true }));
    await expect(removePasskey("cred_1")).rejects.toThrow(/recovery session/i);
  });
});

// ---------------------------------------------------------------------------
// addEmail — quarantine stamping, uniqueness, verify mail, notify.
// ---------------------------------------------------------------------------

describe("addEmail", () => {
  it("creates a quarantined unverified row, mails a verify link, and notifies", async () => {
    setSession(session(2));
    db.userEmail.create.mockResolvedValue({ id: "ue_new" });

    const result = await addEmail("New@Example.com");

    expect(result).toEqual({ id: "ue_new", email: "new@example.com" });
    const createArg = db.userEmail.create.mock.calls[0]![0];
    expect(createArg.data.status).toBe("quarantined");
    expect(createArg.data.verifiedAt).toBeNull();
    expect(createArg.data.email).toBe("new@example.com"); // normalized lowercase
    expect(createArg.data.quarantinedUntil).toBeInstanceOf(Date);
    expect(createArg.data.quarantinedUntil.getTime()).toBeGreaterThan(Date.now());
    expect(sendMail).toHaveBeenCalledTimes(1);
    expect(notifyCredentialChange).toHaveBeenCalledWith(USER, expect.stringContaining("added"));
  });

  it("rejects an invalid email before touching the DB", async () => {
    setSession(session(2));
    await expect(addEmail("not-an-email")).rejects.toThrow(/valid email/i);
    expect(db.userEmail.create).not.toHaveBeenCalled();
  });

  it("maps a P2002 unique violation to a clear in-use error", async () => {
    setSession(session(2));
    const e = Object.assign(new Error("unique"), { code: "P2002" });
    db.userEmail.create.mockRejectedValue(e);
    await expect(addEmail("taken@example.com")).rejects.toThrow(/already in use/i);
    expect(notifyCredentialChange).not.toHaveBeenCalled();
  });

  it("surfaces a collision as a tagged result (merge offer) via addEmailAction", async () => {
    setSession(session(2));
    const e = Object.assign(new Error("unique"), { code: "P2002" });
    db.userEmail.create.mockRejectedValue(e);

    const result = await addEmailAction("Taken@Example.com");
    expect(result).toEqual({
      ok: false,
      collision: true,
      email: "taken@example.com",
      error: expect.stringContaining("already in use"),
    });
    expect(notifyCredentialChange).not.toHaveBeenCalled();
  });

  it("rolls the row back and rethrows when the verify mail fails", async () => {
    setSession(session(2));
    db.userEmail.create.mockResolvedValue({ id: "ue_new" });
    db.userEmail.delete.mockResolvedValue({});
    sendMail.mockRejectedValueOnce(new Error("smtp down"));

    await expect(addEmail("new@example.com")).rejects.toThrow(/smtp down/);
    expect(db.userEmail.delete).toHaveBeenCalledWith({ where: { id: "ue_new" } });
    expect(notifyCredentialChange).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// removeEmail — never strand the account with zero verified emails.
// ---------------------------------------------------------------------------

describe("removeEmail last-verified refusal", () => {
  it("refuses to remove the only verified email", async () => {
    setSession(session(2));
    db.userEmail.findUnique.mockResolvedValue({
      id: "ue_1",
      userId: USER,
      email: "only@example.com",
      isPrimary: true,
      verifiedAt: new Date(),
    });
    db.userEmail.count.mockResolvedValue(0); // no other verified emails

    await expect(removeEmail("ue_1")).rejects.toThrow(/last verified email/i);
    expect(db.userEmail.delete).not.toHaveBeenCalled();
  });

  it("removes a verified email when another verified email remains", async () => {
    setSession(session(2));
    db.userEmail.findUnique.mockResolvedValue({
      id: "ue_1",
      userId: USER,
      email: "work@example.com",
      isPrimary: false,
      verifiedAt: new Date(),
    });
    db.userEmail.count.mockResolvedValue(1);
    db.userEmail.delete.mockResolvedValue({});

    await removeEmail("ue_1");
    expect(db.userEmail.delete).toHaveBeenCalledWith({ where: { id: "ue_1" } });
    expect(notifyCredentialChange).toHaveBeenCalledWith(USER, expect.stringContaining("removed"));
  });

  it("removes an unverified non-primary email even with no other verified email", async () => {
    setSession(session(2));
    db.userEmail.findUnique.mockResolvedValue({
      id: "ue_pending",
      userId: USER,
      email: "pending@example.com",
      isPrimary: false,
      verifiedAt: null,
    });
    db.userEmail.count.mockResolvedValue(0);
    db.userEmail.delete.mockResolvedValue({});

    await removeEmail("ue_pending");
    expect(db.userEmail.delete).toHaveBeenCalled();
  });

  it("refuses when the email belongs to another user", async () => {
    setSession(session(2));
    db.userEmail.findUnique.mockResolvedValue({
      id: "ue_x",
      userId: "someone_else",
      email: "x@example.com",
      isPrimary: false,
      verifiedAt: new Date(),
    });
    await expect(removeEmail("ue_x")).rejects.toThrow(/not found/i);
  });
});

// ---------------------------------------------------------------------------
// setPrimaryEmail — single-primary invariant, must be verified.
// ---------------------------------------------------------------------------

describe("setPrimaryEmail single-primary invariant", () => {
  beforeEach(() => {
    // The H-1 gate reads the passkey rows; default to an established (active)
    // passkey so these invariant tests exercise the primary-email logic.
    db.authenticator.findMany.mockResolvedValue([activePasskey()]);
  });

  it("clears all primaries, sets one, and updates the User.email cache in one tx", async () => {
    setSession(session(2));
    db.userEmail.findUnique.mockResolvedValue({
      id: "ue_2",
      userId: USER,
      email: "new-primary@example.com",
      verifiedAt: new Date(),
    });
    db.userEmail.updateMany.mockResolvedValue({ count: 1 });
    db.userEmail.update.mockResolvedValue({});
    db.user.update.mockResolvedValue({});

    await setPrimaryEmail("ue_2");

    expect(db.$transaction).toHaveBeenCalledTimes(1);
    // clear-all precedes set-one (the single-primary invariant ordering).
    expect(db.userEmail.updateMany).toHaveBeenCalledWith({
      where: { userId: USER, isPrimary: true },
      data: { isPrimary: false },
    });
    expect(db.userEmail.update).toHaveBeenCalledWith({
      where: { id: "ue_2" },
      data: { isPrimary: true },
    });
    expect(db.user.update).toHaveBeenCalledWith({
      where: { id: USER },
      data: { email: "new-primary@example.com" },
    });
    expect(notifyCredentialChange).toHaveBeenCalled();
  });

  it("refuses to promote an unverified email", async () => {
    setSession(session(2));
    db.userEmail.findUnique.mockResolvedValue({
      id: "ue_3",
      userId: USER,
      email: "unverified@example.com",
      verifiedAt: null,
    });
    await expect(setPrimaryEmail("ue_3")).rejects.toThrow(/verify/i);
    expect(db.$transaction).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// setPrimaryEmail H-1 quarantine gate — the primary email is where security
// notifications land, so a session held up only by a fresh graft must not be
// able to redirect it. The REAL gate (credential-gate + credential-lifecycle)
// runs here against the mocked prisma client, so these are end-to-end policy
// tests of the enforcement, not of a mock.
// ---------------------------------------------------------------------------

describe("setPrimaryEmail H-1 quarantine gate", () => {
  beforeEach(() => {
    db.userEmail.findUnique.mockResolvedValue({
      id: "ue_2",
      userId: USER,
      email: "new-primary@example.com",
      verifiedAt: new Date(),
    });
    db.userEmail.updateMany.mockResolvedValue({ count: 1 });
    db.userEmail.update.mockResolvedValue({});
    db.user.update.mockResolvedValue({});
  });

  it("ATTACK: refuses when the user's only passkey is still quarantined", async () => {
    setSession(session(2, { cred: "cred_graft" }));
    db.authenticator.findMany.mockResolvedValue([quarantinedPasskey("cred_graft")]);

    await expect(setPrimaryEmail("ue_2")).rejects.toBeInstanceOf(PrivilegedActionQuarantineError);
    expect(db.$transaction).not.toHaveBeenCalled();
    expect(notifyCredentialChange).not.toHaveBeenCalled();
    // Every refused attempt leaves an audit trail — the pivot signature.
    expect(h.audit).toHaveBeenCalledWith(
      USER,
      "credential.quarantine_refused",
      expect.objectContaining({ action: "email.set-primary", reason: "no-active-passkey" }),
    );
  });

  it("ATTACK: refuses a session RIDING the quarantined graft even when the owner's active passkey still exists", async () => {
    setSession(session(2, { cred: "cred_graft" }));
    db.authenticator.findMany.mockResolvedValue([
      activePasskey("cred_orig"),
      quarantinedPasskey("cred_graft"),
    ]);

    let thrown: unknown;
    await setPrimaryEmail("ue_2").catch((e: unknown) => {
      thrown = e;
    });
    expect(thrown).toBeInstanceOf(PrivilegedActionQuarantineError);
    const refusal = (thrown as PrivilegedActionQuarantineError).refusal;
    expect(refusal.reason).toBe("acting-passkey-untrusted");
    // Forgiving path: re-authenticating with the established passkey clears it.
    expect(refusal.canStepUp).toBe(true);
    expect(db.$transaction).not.toHaveBeenCalled();
  });

  it("LEGIT: allows a session acting with an established passkey while a fresh graft exists", async () => {
    setSession(session(2, { cred: "cred_orig" }));
    db.authenticator.findMany.mockResolvedValue([
      activePasskey("cred_orig"),
      quarantinedPasskey("cred_graft"),
    ]);

    await setPrimaryEmail("ue_2");
    expect(db.$transaction).toHaveBeenCalledTimes(1);
  });

  it("LEGIT: a lapsed quarantine window clears the gate by itself (time-based clearance)", async () => {
    setSession(session(2, { cred: "cred_graft" }));
    db.authenticator.findMany.mockResolvedValue([quarantinedPasskey("cred_graft", -1000)]);

    await setPrimaryEmail("ue_2");
    expect(db.$transaction).toHaveBeenCalledTimes(1);
  });

  it("LEGIT: a legacy session without a cred claim passes when an active passkey exists", async () => {
    setSession(session(2)); // pre-claim JWT: no cred
    db.authenticator.findMany.mockResolvedValue([
      activePasskey("cred_orig"),
      quarantinedPasskey("cred_graft"),
    ]);

    await setPrimaryEmail("ue_2");
    expect(db.$transaction).toHaveBeenCalledTimes(1);
  });

  it("refuses a cred claim pointing at a passkey no longer on the account", async () => {
    setSession(session(2, { cred: "cred_removed" }));
    db.authenticator.findMany.mockResolvedValue([activePasskey("cred_orig")]);

    let thrown: unknown;
    await setPrimaryEmail("ue_2").catch((e: unknown) => {
      thrown = e;
    });
    expect(thrown).toBeInstanceOf(PrivilegedActionQuarantineError);
    expect((thrown as PrivilegedActionQuarantineError).refusal.canStepUp).toBe(true);
  });

  it("surfaces the refusal as a typed result with finished copy via setPrimaryEmailAction", async () => {
    setSession(session(2, { cred: "cred_graft" }));
    db.authenticator.findMany.mockResolvedValue([quarantinedPasskey("cred_graft")]);

    const res = await setPrimaryEmailAction("ue_2");
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected a refusal");
    if (res.stepUp) throw new Error("expected quarantine refusal, got stepUp");
    expect(res.quarantine).toBeDefined();
    expect(res.quarantine!.reason).toBe("no-active-passkey");
    expect(res.quarantine!.retryAt).not.toBeNull();
    // The message is user-facing copy that says when the hold clears.
    expect(res.error).toMatch(/unlocks in about/i);
  });
});

// ---------------------------------------------------------------------------
// canAddPasskey — bootstrap rule.
// ---------------------------------------------------------------------------

describe("canAddPasskey bootstrap rule", () => {
  it("allows the first passkey from an AAL1 session (bootstrap)", async () => {
    setSession(session(1));
    db.authenticator.count.mockResolvedValue(0);
    const r = await canAddPasskey();
    expect(r).toEqual({ allowed: true, bootstrap: true });
  });

  it("blocks a second passkey from an AAL1 session", async () => {
    setSession(session(1));
    db.authenticator.count.mockResolvedValue(1);
    const r = await canAddPasskey();
    expect(r.allowed).toBe(false);
    expect(r.bootstrap).toBe(false);
  });

  it("allows a second passkey from an AAL2 session", async () => {
    setSession(session(2));
    db.authenticator.count.mockResolvedValue(1);
    const r = await canAddPasskey();
    expect(r).toEqual({ allowed: true, bootstrap: false });
  });

  it("allows a recovered AAL1 session to bootstrap its first passkey", async () => {
    setSession(session(1, { recovered: true }));
    db.authenticator.count.mockResolvedValue(0);
    const r = await canAddPasskey();
    expect(r.allowed).toBe(true);
    expect(r.bootstrap).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// markPasskeyEnrolled — a READ-ONLY reporter since H-1 enforcement: the
// lifecycle stamp and the notification both moved to WRITE time (the
// adapter's createAuthenticator override in src/auth.ts), so a raw ceremony
// can't skip them and this client-callable action can't be abused to promote
// or re-stamp anything.
// ---------------------------------------------------------------------------

describe("markPasskeyEnrolled (read-only reporter)", () => {
  it("reports an active bootstrap passkey and writes nothing", async () => {
    setSession(session(2));
    db.authenticator.findFirst.mockResolvedValue({ status: "active", quarantinedUntil: null });

    const r = await markPasskeyEnrolled();
    expect(r).toEqual({ quarantined: false });
    expect(db.authenticator.update).not.toHaveBeenCalled();
    // Notification is the adapter's job at write time — never doubled here.
    expect(notifyCredentialChange).not.toHaveBeenCalled();
  });

  it("reports a quarantined (in-window) passkey and writes nothing", async () => {
    setSession(session(2));
    db.authenticator.findFirst.mockResolvedValue({
      status: "quarantined",
      quarantinedUntil: new Date(Date.now() + 3_600_000),
    });

    const r = await markPasskeyEnrolled();
    expect(r).toEqual({ quarantined: true });
    expect(db.authenticator.update).not.toHaveBeenCalled();
    expect(notifyCredentialChange).not.toHaveBeenCalled();
  });

  it("reports a lapsed-window passkey as not quarantined (lazy expiry)", async () => {
    setSession(session(2));
    db.authenticator.findFirst.mockResolvedValue({
      status: "quarantined",
      quarantinedUntil: new Date(Date.now() - 1000),
    });

    const r = await markPasskeyEnrolled();
    expect(r).toEqual({ quarantined: false });
    expect(db.authenticator.update).not.toHaveBeenCalled();
  });

  it("cannot be used to promote a sole in-window quarantined survivor (cooldown bypass)", async () => {
    // The historical attack: hijacked session grafts a passkey, removes the
    // victim's original, then calls this finalize hoping the "bootstrap"
    // branch promotes the survivor. The action no longer writes at all, so
    // there is nothing to abuse — the survivor stays quarantined.
    setSession(session(2));
    db.authenticator.findFirst.mockResolvedValue({
      status: "quarantined",
      quarantinedUntil: new Date(Date.now() + 3_600_000),
    });

    const r = await markPasskeyEnrolled();
    expect(r).toEqual({ quarantined: true });
    expect(db.authenticator.update).not.toHaveBeenCalled();
  });

  it("throws when there is no enrolled passkey to report on", async () => {
    setSession(session(2));
    db.authenticator.findFirst.mockResolvedValue(null);
    await expect(markPasskeyEnrolled()).rejects.toThrow(/No passkey/i);
  });
});

// ---------------------------------------------------------------------------
// removePasskey — last-passkey refusal.
// ---------------------------------------------------------------------------

describe("removePasskey last-passkey refusal", () => {
  it("refuses to remove the user's last passkey", async () => {
    setSession(session(2));
    db.authenticator.findUnique.mockResolvedValue({ credentialID: "cred_1", userId: USER });
    db.authenticator.count.mockResolvedValue(1);

    await expect(removePasskey("cred_1")).rejects.toThrow(/last passkey/i);
    expect(db.authenticator.delete).not.toHaveBeenCalled();
  });

  it("removes a passkey when another remains", async () => {
    setSession(session(2));
    db.authenticator.findUnique.mockResolvedValue({ credentialID: "cred_2", userId: USER });
    db.authenticator.count.mockResolvedValue(2);
    db.authenticator.delete.mockResolvedValue({});

    await removePasskey("cred_2");
    expect(db.authenticator.delete).toHaveBeenCalledWith({
      where: { userId_credentialID: { userId: USER, credentialID: "cred_2" } },
    });
    expect(notifyCredentialChange).toHaveBeenCalledWith(USER, expect.stringContaining("removed"));
  });

  it("does not promote an in-window quarantined survivor (add-then-remove attack)", async () => {
    // A hijacked AAL2 session adds a still-quarantined passkey, then removes the
    // victim's original (total was 2, so the last-passkey refusal above passes).
    // The survivor must NOT be promoted to active by the removal — its cooldown
    // window is left intact (DESIGNDECISIONS #5). Lapsed windows are handled at
    // read time by lazy expiry, not by a rewrite here.
    setSession(session(2));
    db.authenticator.findUnique.mockResolvedValue({ credentialID: "cred_1", userId: USER });
    db.authenticator.count.mockResolvedValue(2);
    db.authenticator.delete.mockResolvedValue({});

    await removePasskey("cred_1");

    expect(db.authenticator.delete).toHaveBeenCalledWith({
      where: { userId_credentialID: { userId: USER, credentialID: "cred_1" } },
    });
    expect(db.authenticator.update).not.toHaveBeenCalled();
  });

  it("never rewrites a surviving passkey's status on removal", async () => {
    setSession(session(2));
    db.authenticator.findUnique.mockResolvedValue({ credentialID: "cred_2", userId: USER });
    db.authenticator.count.mockResolvedValue(2);
    db.authenticator.delete.mockResolvedValue({});

    await removePasskey("cred_2");
    expect(db.authenticator.update).not.toHaveBeenCalled();
  });

  it("refuses when the passkey belongs to another user", async () => {
    setSession(session(2));
    db.authenticator.findUnique.mockResolvedValue({
      credentialID: "cred_x",
      userId: "someone_else",
    });
    await expect(removePasskey("cred_x")).rejects.toThrow(/not found/i);
  });
});

// ---------------------------------------------------------------------------
// Lazy quarantine expiry — a quarantine is judged against the clock at read
// time (asStatus, via listCredentials), so a lapsed window stops displaying as
// "Quarantined" without anything re-stamping the status column. This is what
// fixes "my only passkey is quarantined forever" and, together with removePasskey
// no longer promoting survivors, keeps an in-window quarantine intact.
// ---------------------------------------------------------------------------

describe("lazy quarantine expiry (listCredentials)", () => {
  function passkeyRow(quarantinedUntil: Date | null) {
    return {
      credentialID: "cred_1",
      label: null,
      status: "quarantined",
      quarantinedUntil,
      addedAt: new Date(),
      lastUsedAt: null,
    };
  }

  beforeEach(() => {
    setSession(session(2));
    db.userEmail.findMany.mockResolvedValue([]);
    db.account.findMany.mockResolvedValue([]);
  });

  it("reads a lapsed-window quarantined passkey as active", async () => {
    db.authenticator.findMany.mockResolvedValue([passkeyRow(new Date(Date.now() - 1000))]);

    const listing = await listCredentials();
    expect(listing.passkeys[0]!.status).toBe("active");
    // The raw timestamp is still surfaced (display/countdown context); only the
    // derived status flips once the window lapses.
    expect(listing.passkeys[0]!.quarantinedUntil).not.toBeNull();
  });

  it("keeps an in-window quarantined passkey quarantined", async () => {
    db.authenticator.findMany.mockResolvedValue([passkeyRow(new Date(Date.now() + 3_600_000))]);

    const listing = await listCredentials();
    expect(listing.passkeys[0]!.status).toBe("quarantined");
  });

  it("treats a quarantined row with no window as still quarantined", async () => {
    db.authenticator.findMany.mockResolvedValue([passkeyRow(null)]);

    const listing = await listCredentials();
    expect(listing.passkeys[0]!.status).toBe("quarantined");
  });
});

// ---------------------------------------------------------------------------
// Linked accounts — the section reads `oauth-account` BADGES (provider +
// optional handle), not Auth.js Account rows. Minister has no OAuth sign-in
// providers, so the Account table only ever holds passkey/magic-link rows;
// reading it made the section show passkeys and never the linked GitHub. Each
// linked account must appear exactly once, correctly labeled.
// ---------------------------------------------------------------------------

describe("linked accounts (listCredentials)", () => {
  function oauthBadge(id: string, provider: string, handle: string | null, issuedAt: Date) {
    return {
      id,
      attributes: handle === null ? { provider } : { provider, handle },
      issuedAt,
    };
  }

  beforeEach(() => {
    setSession(session(2));
    db.userEmail.findMany.mockResolvedValue([]);
    db.authenticator.findMany.mockResolvedValue([]);
  });

  it("maps oauth-account badges to linked accounts with provider + handle", async () => {
    db.badge.findMany.mockResolvedValue([
      oauthBadge("b_gh", "github", "octocat", new Date("2026-01-01T00:00:00Z")),
      oauthBadge("b_gg", "google", null, new Date("2026-02-01T00:00:00Z")),
    ]);

    const listing = await listCredentials();

    expect(listing.accounts).toEqual([
      {
        kind: "oauth",
        id: "b_gh",
        provider: "github",
        handle: "octocat",
        linkedAt: "2026-01-01T00:00:00.000Z",
      },
      {
        kind: "oauth",
        id: "b_gg",
        provider: "google",
        handle: null,
        linkedAt: "2026-02-01T00:00:00.000Z",
      },
    ]);
    // Passkeys never leak into the linked-accounts list (root of the dupe bug).
    expect(listing.accounts.some((a) => a.provider === "passkey")).toBe(false);
  });

  it("lists a re-proved account once, keeping the earliest link", async () => {
    db.badge.findMany.mockResolvedValue([
      oauthBadge("b_old", "github", "octocat", new Date("2026-01-01T00:00:00Z")),
      oauthBadge("b_new", "github", "octocat", new Date("2026-03-01T00:00:00Z")),
    ]);

    const listing = await listCredentials();

    expect(listing.accounts).toHaveLength(1);
    expect(listing.accounts[0]!.id).toBe("b_old");
    expect(listing.accounts[0]!.linkedAt).toBe("2026-01-01T00:00:00.000Z");
  });
});
