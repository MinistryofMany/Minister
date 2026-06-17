import { SignJWT } from "jose";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

// In-memory stand-in for the VerificationToken single-use markers, so these
// tests exercise the real crypto offline (no DB). create() records a marker;
// delete() consumes it and throws a Prisma-style P2025 when it's missing —
// which is exactly what verifyDonorProof relies on for single-use.
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
          const k = `${where.identifier_token.identifier}:${where.identifier_token.token}`;
          if (!markers.has(k)) {
            const err = new Error("Record to delete does not exist.") as Error & { code: string };
            err.code = "P2025";
            throw err;
          }
          markers.delete(k);
          return where;
        },
      ),
    },
  },
}));

import { issueDonorProof, verifyDonorProof } from "./merge-proof";

const KEY = "donor-proof-test-secret-32chars!!!!!";
const TYP = "minister-donor-proof";

describe("merge-proof", () => {
  const ORIGINAL = process.env.AUTH_SECRET;

  beforeEach(() => {
    markers.clear();
    process.env.AUTH_SECRET = KEY;
  });

  afterAll(() => {
    if (ORIGINAL === undefined) delete process.env.AUTH_SECRET;
    else process.env.AUTH_SECRET = ORIGINAL;
  });

  it("issues a ticket that verifies back to the donorUserId", async () => {
    const ticket = await issueDonorProof("donor_abc");
    const result = await verifyDonorProof(ticket);
    expect(result).toEqual({ donorUserId: "donor_abc" });
  });

  it("is single-use: the second verify of the same ticket fails", async () => {
    const ticket = await issueDonorProof("donor_abc");
    expect(await verifyDonorProof(ticket)).toEqual({ donorUserId: "donor_abc" });
    expect(await verifyDonorProof(ticket)).toBeNull();
  });

  it("rejects a tampered ticket (broken signature)", async () => {
    const ticket = await issueDonorProof("donor_abc");
    const [header, body, sig] = ticket.split(".");
    if (!header || !body || !sig) throw new Error("ticket is not a well-formed JWT");
    // Flip the FIRST signature character (a high-significance base64url digit).
    // The LAST char of a 43-char (256-bit) HMAC encodes only ~2 significant bits,
    // so flipping it decodes to the same bytes ~6.7% of the time and the "tamper"
    // would be a no-op — making this assertion flaky. The first char always
    // changes the decoded signature, so the verify reliably rejects.
    const tampered = (sig.startsWith("A") ? "B" : "A") + sig.slice(1);
    expect(await verifyDonorProof(`${header}.${body}.${tampered}`)).toBeNull();
  });

  it("rejects a ticket signed with a different secret", async () => {
    const jti = "some-jti";
    markers.add(`donor-proof-ticket:${jti}`);
    const forged = await new SignJWT({ donorUserId: "donor_abc" })
      .setProtectedHeader({ alg: "HS256", typ: TYP })
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(new TextEncoder().encode("a-totally-different-secret-32chars!!"));
    expect(await verifyDonorProof(forged)).toBeNull();
  });

  it("rejects an expired ticket", async () => {
    const jti = "expired-jti";
    markers.add(`donor-proof-ticket:${jti}`);
    const expired = await new SignJWT({ donorUserId: "donor_abc" })
      .setProtectedHeader({ alg: "HS256", typ: TYP })
      .setJti(jti)
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1800)
      .sign(new TextEncoder().encode(KEY));
    expect(await verifyDonorProof(expired)).toBeNull();
  });

  it("rejects a token with the wrong typ header", async () => {
    const jti = "wrong-typ-jti";
    markers.add(`donor-proof-ticket:${jti}`);
    const wrongTyp = await new SignJWT({ donorUserId: "donor_abc" })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(new TextEncoder().encode(KEY));
    expect(await verifyDonorProof(wrongTyp)).toBeNull();
  });

  it("rejects a token missing donorUserId", async () => {
    const jti = "no-donor-jti";
    markers.add(`donor-proof-ticket:${jti}`);
    const noDonor = await new SignJWT({})
      .setProtectedHeader({ alg: "HS256", typ: TYP })
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(new TextEncoder().encode(KEY));
    expect(await verifyDonorProof(noDonor)).toBeNull();
  });

  it("a ticket for one donor never verifies as another (caller compares the returned id)", async () => {
    const ticket = await issueDonorProof("donor_one");
    const result = await verifyDonorProof(ticket);
    // The lib returns the bound id; the merge action compares it to the
    // donor it intends to merge. A mismatch is the caller's reject.
    expect(result?.donorUserId).toBe("donor_one");
    expect(result?.donorUserId).not.toBe("donor_two");
  });

  it("throws when AUTH_SECRET is too short at issue", async () => {
    process.env.AUTH_SECRET = "short";
    await expect(issueDonorProof("donor_abc")).rejects.toThrow(/AUTH_SECRET/);
  });
});
