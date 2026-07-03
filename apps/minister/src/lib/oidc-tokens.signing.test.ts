import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { _resetIssuerCache, loadIssuer, type Issuer } from "@minister/vc";
import { decodeProtectedHeader, jwtVerify } from "jose";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { mintAccessToken, mintIdToken } from "./oidc-tokens";

// Proves the two-key split at the app boundary: id/access tokens sign with the
// in-process token key (#key-3), NOT the badge key (#key-2, KMS-backed in prod).
// A token must verify against the token key and be rejected by the badge key,
// so a stolen token key cannot masquerade as the badge issuer and vice versa.
describe("mintIdToken / mintAccessToken key separation", () => {
  let tmpDir: string;
  let issuer: Issuer;

  beforeAll(() => {
    process.env.AUTH_URL = "https://ministry.id";
  });

  beforeEach(async () => {
    _resetIssuerCache();
    tmpDir = await mkdtemp(join(tmpdir(), "minister-tok-test-"));
    issuer = await loadIssuer({ domain: "ministry.id", devKeyPath: join(tmpDir, "issuer.jwk") });
  });

  afterEach(async () => {
    _resetIssuerCache();
    await rm(tmpDir, { recursive: true, force: true });
  });

  it("signs the id_token with the token key (#key-3), verifiable by the token public key only", async () => {
    const jwt = await mintIdToken(issuer, { sub: "sub_1", aud: "client_1", nonce: "n" });

    expect(decodeProtectedHeader(jwt).kid).toBe(issuer.token.kid);
    expect(issuer.token.kid).toBe("did:web:ministry.id#key-3");

    // Verifies against the token key...
    await expect(
      jwtVerify(jwt, issuer.token.publicKey, { algorithms: ["EdDSA"] }),
    ).resolves.toBeTruthy();
    // ...and is rejected by the badge key (#key-2).
    await expect(jwtVerify(jwt, issuer.publicKey, { algorithms: ["EdDSA"] })).rejects.toBeTruthy();
  });

  it("signs the access token with the token key (#key-3) as well", async () => {
    const jwt = await mintAccessToken(issuer, {
      jti: "at_1",
      sub: "sub_1",
      clientId: "client_1",
      scopes: ["openid"],
    });
    expect(decodeProtectedHeader(jwt).kid).toBe(issuer.token.kid);
    await expect(
      jwtVerify(jwt, issuer.token.publicKey, { algorithms: ["EdDSA"] }),
    ).resolves.toBeTruthy();
    await expect(jwtVerify(jwt, issuer.publicKey, { algorithms: ["EdDSA"] })).rejects.toBeTruthy();
  });

  it("the badge key and token key are distinct public keys, both served in JWKS", async () => {
    expect(issuer.publicJwk.x).not.toBe(issuer.token.publicJwk.x);
    expect(issuer.publicJwk.kid).toBe("did:web:ministry.id#key-2");
    expect(issuer.token.publicJwk.kid).toBe("did:web:ministry.id#key-3");
  });
});
