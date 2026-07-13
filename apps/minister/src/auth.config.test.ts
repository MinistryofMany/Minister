import { describe, expect, it } from "vitest";
import type { Account, Session, User } from "next-auth";
import type { JWT } from "next-auth/jwt";

import { authConfig } from "@/auth.config";

// The jwt/session callbacks are pure functions of their inputs (that is what
// makes them edge-safe), so they are tested directly: the acting-credential
// `cred` claim (H-1 / DESIGNDECISIONS #15) must be stamped on passkey
// authentication events, survive refreshes, and never come from AAL1
// providers.

type JwtCallback = (params: {
  token: JWT;
  user?: User;
  account?: Account | null;
}) => JWT | Promise<JWT>;
type SessionCallback = (params: { session: Session; token: JWT }) => Session | Promise<Session>;

const jwtCb = authConfig.callbacks!.jwt! as unknown as JwtCallback;
const sessionCb = authConfig.callbacks!.session! as unknown as SessionCallback;

function account(provider: string, providerAccountId: string): Account {
  return { provider, providerAccountId, type: "credentials" } as Account;
}

function baseSession(): Session {
  return {
    user: { id: "", name: null, email: null, image: null },
    expires: new Date(Date.now() + 3600_000).toISOString(),
  } as Session;
}

describe("jwt callback — cred (acting credential) claim", () => {
  it("stamps cred with the WebAuthn credentialID on a passkey sign-in", async () => {
    const token = await jwtCb({
      token: {},
      user: { id: "u1", sessionGeneration: 0 } as User,
      account: account("passkey", "credential-id-A"),
    });
    expect(token.cred).toBe("credential-id-A");
    expect(token.aal).toBe(2);
  });

  it("does NOT stamp cred on an email sign-in", async () => {
    const token = await jwtCb({
      token: {},
      user: { id: "u1", sessionGeneration: 0 } as User,
      account: account("email", "u1"),
    });
    expect(token.cred).toBeUndefined();
    expect(token.aal).toBe(1);
  });

  it("does NOT stamp cred on a recovery sign-in", async () => {
    const token = await jwtCb({
      token: {},
      user: { id: "u1", sessionGeneration: 0 } as User,
      account: account("recovery", "u1"),
    });
    expect(token.cred).toBeUndefined();
    expect(token.recovered).toBe(true);
  });

  it("preserves cred across a plain refresh (no account)", async () => {
    const token = await jwtCb({ token: { aal: 2, cred: "credential-id-A" } });
    expect(token.cred).toBe("credential-id-A");
  });

  it("latest passkey wins: a fresh registration overwrites the acting credential", async () => {
    // Registering a (quarantined) second passkey re-points the session's
    // acting credential at the graft, downgrading even an already-AAL2
    // session's privileged power until an established passkey re-proves —
    // exactly the graft case the quarantine gate exists for.
    const token = await jwtCb({
      token: { aal: 2, cred: "credential-id-A" },
      account: account("passkey", "credential-id-B"),
    });
    expect(token.cred).toBe("credential-id-B");
  });

  it("an email step-up does not clobber the passkey cred", async () => {
    const token = await jwtCb({
      token: { aal: 2, cred: "credential-id-A" },
      account: account("email", "u1"),
    });
    expect(token.cred).toBe("credential-id-A");
    // AAL never drops on step-up (Math.max).
    expect(token.aal).toBe(2);
  });
});

describe("session callback — cred exposure", () => {
  it("surfaces a string cred onto the session", async () => {
    const s = await sessionCb({
      session: baseSession(),
      token: { id: "u1", aal: 2, cred: "credential-id-A" },
    });
    expect(s.cred).toBe("credential-id-A");
  });

  it("leaves cred undefined for tokens without one", async () => {
    const s = await sessionCb({ session: baseSession(), token: { id: "u1", aal: 1 } });
    expect(s.cred).toBeUndefined();
  });
});
