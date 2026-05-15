import { SignJWT } from "jose";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { ValidAuthorizeRequest } from "./oidc-authorize";
import { signOidcRequest, verifyOidcRequest } from "./oidc-request-token";

const SECRET = "test-auth-secret-must-be-at-least-32-chars!!";

describe("OIDC request token round trip", () => {
  const ORIGINAL = process.env.AUTH_SECRET;

  beforeAll(() => {
    process.env.AUTH_SECRET = SECRET;
  });
  afterAll(() => {
    if (ORIGINAL === undefined) delete process.env.AUTH_SECRET;
    else process.env.AUTH_SECRET = ORIGINAL;
  });

  const request: ValidAuthorizeRequest = {
    clientId: "tc_test",
    clientName: "Test Client",
    allowedScopes: ["openid", "profile", "badge:email-domain"],
    redirectUri: "http://localhost:3100/cb",
    scopes: ["openid", "profile", "badge:email-domain"],
    state: "STATE_123",
    nonce: "NONCE_abc",
    codeChallenge: "challenge_xyz",
    codeChallengeMethod: "S256",
  };

  it("round-trips a validated request unchanged", async () => {
    const token = await signOidcRequest(request);
    const back = await verifyOidcRequest(token);
    expect(back).toEqual(request);
  });

  it("rejects a token signed with a different secret", async () => {
    const token = await signOidcRequest(request);
    process.env.AUTH_SECRET = "different-secret-also-32-chars-min!!";
    await expect(verifyOidcRequest(token)).rejects.toThrow();
    process.env.AUTH_SECRET = SECRET;
  });

  it("rejects a token whose `typ` header doesn't match", async () => {
    const wrongType = await new SignJWT({ req: request })
      .setProtectedHeader({ alg: "HS256", typ: "wrong-type" })
      .setIssuedAt()
      .setExpirationTime("1m")
      .sign(new TextEncoder().encode(SECRET));
    await expect(verifyOidcRequest(wrongType)).rejects.toThrow();
  });

  it("rejects a token missing the `req` payload claim", async () => {
    const noReq = await new SignJWT({ somethingElse: "x" })
      .setProtectedHeader({ alg: "HS256", typ: "tessera-oidc-req" })
      .setIssuedAt()
      .setExpirationTime("1m")
      .sign(new TextEncoder().encode(SECRET));
    await expect(verifyOidcRequest(noReq)).rejects.toThrow(/payload/);
  });

  it("refuses to sign when AUTH_SECRET is shorter than 32 chars", async () => {
    process.env.AUTH_SECRET = "too-short";
    await expect(signOidcRequest(request)).rejects.toThrow(/32 chars/);
    process.env.AUTH_SECRET = SECRET;
  });
});
