import { SignJWT } from "jose";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

// In-memory stand-in for the VerificationToken single-use markers, so these
// tests exercise the real crypto offline (no DB). create() records a marker;
// delete() consumes it and throws a Prisma-style P2025 when it's missing —
// which is exactly what verifyRecoveryTicket relies on for single-use.
const markers = new Set<string>();

vi.mock("@/lib/prisma", () => ({
  prisma: {
    verificationToken: {
      create: vi.fn(async ({ data }: { data: { identifier: string; token: string } }) => {
        markers.add(`${data.identifier}:${data.token}`);
        return data;
      }),
      delete: vi.fn(
        async ({
          where,
        }: {
          where: { identifier_token: { identifier: string; token: string } };
        }) => {
          const key = `${where.identifier_token.identifier}:${where.identifier_token.token}`;
          if (!markers.has(key)) {
            const err = new Error("Record to delete does not exist.") as Error & { code: string };
            err.code = "P2025";
            throw err;
          }
          markers.delete(key);
          return where;
        },
      ),
    },
  },
}));

import { issueRecoveryTicket, verifyRecoveryTicket } from "./recovery-ticket";

const KEY = "recovery-ticket-test-secret-32chars!!";

describe("recovery-ticket", () => {
  const ORIGINAL = process.env.AUTH_SECRET;

  beforeEach(() => {
    markers.clear();
    process.env.AUTH_SECRET = KEY;
  });

  afterAll(() => {
    if (ORIGINAL === undefined) delete process.env.AUTH_SECRET;
    else process.env.AUTH_SECRET = ORIGINAL;
  });

  it("issues a ticket that verifies back to the userId", async () => {
    const ticket = await issueRecoveryTicket("user_abc");
    const result = await verifyRecoveryTicket(ticket);
    expect(result).toEqual({ userId: "user_abc" });
  });

  it("is single-use: the second verify of the same ticket fails", async () => {
    const ticket = await issueRecoveryTicket("user_abc");
    expect(await verifyRecoveryTicket(ticket)).toEqual({ userId: "user_abc" });
    expect(await verifyRecoveryTicket(ticket)).toBeNull();
  });

  it("rejects a tampered ticket (broken signature)", async () => {
    const ticket = await issueRecoveryTicket("user_abc");
    // Flip the FIRST signature character (a high-significance base64url digit).
    // The LAST char of a 43-char (256-bit) HMAC encodes only ~2 significant bits,
    // so flipping it decodes to the same bytes ~6.7% of the time and the "tamper"
    // would be a no-op — making this assertion flaky. The first char always
    // changes the decoded signature, so the verify reliably rejects.
    const [header, body, sig] = ticket.split(".");
    if (!header || !body || !sig) throw new Error("ticket is not a well-formed JWT");
    const tampered = (sig.startsWith("A") ? "B" : "A") + sig.slice(1);
    expect(await verifyRecoveryTicket(`${header}.${body}.${tampered}`)).toBeNull();
  });

  it("rejects a ticket signed with a different secret", async () => {
    const jti = "some-jti";
    markers.add(`recovery-ticket:${jti}`);
    const forged = await new SignJWT({ userId: "user_abc" })
      .setProtectedHeader({ alg: "HS256", typ: "minister-recovery-ticket" })
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(new TextEncoder().encode("a-totally-different-secret-32chars!!"));
    expect(await verifyRecoveryTicket(forged)).toBeNull();
  });

  it("rejects an expired ticket", async () => {
    const jti = "expired-jti";
    markers.add(`recovery-ticket:${jti}`);
    const expired = await new SignJWT({ userId: "user_abc" })
      .setProtectedHeader({ alg: "HS256", typ: "minister-recovery-ticket" })
      .setJti(jti)
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1800)
      .sign(new TextEncoder().encode(KEY));
    expect(await verifyRecoveryTicket(expired)).toBeNull();
  });

  it("rejects a token with the wrong typ header", async () => {
    const jti = "wrong-typ-jti";
    markers.add(`recovery-ticket:${jti}`);
    const wrongTyp = await new SignJWT({ userId: "user_abc" })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(new TextEncoder().encode(KEY));
    expect(await verifyRecoveryTicket(wrongTyp)).toBeNull();
  });

  it("rejects a token missing userId", async () => {
    const jti = "no-user-jti";
    markers.add(`recovery-ticket:${jti}`);
    const noUser = await new SignJWT({})
      .setProtectedHeader({ alg: "HS256", typ: "minister-recovery-ticket" })
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(new TextEncoder().encode(KEY));
    expect(await verifyRecoveryTicket(noUser)).toBeNull();
  });

  it("throws when AUTH_SECRET is too short at issue", async () => {
    process.env.AUTH_SECRET = "short";
    await expect(issueRecoveryTicket("user_abc")).rejects.toThrow(/AUTH_SECRET/);
  });
});
