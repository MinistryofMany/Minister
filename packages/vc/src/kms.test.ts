import { jwtVerify } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { buildUserDid } from "./did";
import { issueVc } from "./issue";
import { _resetIssuerCache, loadIssuer } from "./key";
import {
  assertKmsPublicKeyMatches,
  createAwsKmsClient,
  ed25519JwkX,
  kmsSigner,
  MAX_RAW_MESSAGE_BYTES,
  type KmsSignInput,
  type KmsSigningClient,
} from "./kms";
import { signCompactJwt } from "./signer";
import { verifyVc } from "./verify";

// The provisioned KMS key's public material (from the signing plan). SPKI is
// standard base64; the derived JWK `x` is base64url.
const KMS_KEY_ARN = "arn:aws:kms:us-east-2:820761077505:key/ff0ac3ab-e770-4e54-a142-8e0cfb5592d0";
const KMS_SPKI_B64 = "MCowBQYDK2VwAyEAQC2GiODNhQe5aCx/yZRildhid/QB+qxSSP+pOY4SW7c=";
const KMS_PUBLIC_X = "QC2GiODNhQe5aCx_yZRildhid_QB-qxSSP-pOY4SW7c";
const KMS_PUBLIC_JWK = JSON.stringify({
  kty: "OKP",
  crv: "Ed25519",
  x: KMS_PUBLIC_X,
  alg: "EdDSA",
  use: "sig",
});

const spki = () => new Uint8Array(Buffer.from(KMS_SPKI_B64, "base64"));

// Mock KMS client that records sign calls and returns canned bytes. Implements
// exactly the two-method surface `KmsSigningClient` requires.
function mockKms(opts: {
  signature?: Uint8Array;
  publicKey?: Uint8Array;
}): KmsSigningClient & { signCalls: KmsSignInput[] } {
  const signCalls: KmsSignInput[] = [];
  return {
    signCalls,
    async sign(input) {
      signCalls.push(input);
      return { Signature: opts.signature };
    },
    async getPublicKey() {
      return { PublicKey: opts.publicKey };
    },
  };
}

describe("ed25519JwkX", () => {
  it("derives the base64url raw key from a DER SPKI Ed25519 public key", () => {
    expect(ed25519JwkX(spki())).toBe(KMS_PUBLIC_X);
  });

  it("rejects a wrong-length input", () => {
    expect(() => ed25519JwkX(new Uint8Array(43))).toThrow(/Ed25519 SPKI/);
  });

  it("rejects a right-length input with the wrong SPKI prefix (not Ed25519)", () => {
    const bad = spki();
    bad[1] = 0x2b; // corrupt a prefix byte
    expect(() => ed25519JwkX(bad)).toThrow(/SPKI prefix/);
  });
});

describe("kmsSigner", () => {
  it("pins RAW + ED25519_SHA_512 and the key id, returning the 64-byte signature", async () => {
    const sig = new Uint8Array(64).fill(7);
    const client = mockKms({ signature: sig });
    const signer = kmsSigner(client, KMS_KEY_ARN);

    const out = await signer.sign(new TextEncoder().encode("hello"));
    expect(out).toBe(sig);
    expect(client.signCalls).toHaveLength(1);
    expect(client.signCalls[0]).toMatchObject({
      KeyId: KMS_KEY_ARN,
      MessageType: "RAW",
      SigningAlgorithm: "ED25519_SHA_512",
    });
  });

  it("signs a message of exactly 4096 bytes (the boundary is inclusive)", async () => {
    const client = mockKms({ signature: new Uint8Array(64) });
    const signer = kmsSigner(client, KMS_KEY_ARN);
    await expect(signer.sign(new Uint8Array(MAX_RAW_MESSAGE_BYTES))).resolves.toBeInstanceOf(
      Uint8Array,
    );
    expect(client.signCalls).toHaveLength(1);
  });

  it("rejects a 4097-byte message BEFORE calling KMS (id_tokens must not route here)", async () => {
    const client = mockKms({ signature: new Uint8Array(64) });
    const signer = kmsSigner(client, KMS_KEY_ARN);
    await expect(signer.sign(new Uint8Array(MAX_RAW_MESSAGE_BYTES + 1))).rejects.toThrow(
      /RAW sign limit exceeded/,
    );
    // The guard must fire before the network call.
    expect(client.signCalls).toHaveLength(0);
  });

  it("fails closed when KMS returns a non-64-byte signature", async () => {
    const client = mockKms({ signature: new Uint8Array(32) });
    const signer = kmsSigner(client, KMS_KEY_ARN);
    await expect(signer.sign(new Uint8Array(10))).rejects.toThrow(/malformed signature/);
  });

  it("fails closed when KMS returns no signature", async () => {
    const client = mockKms({ signature: undefined });
    const signer = kmsSigner(client, KMS_KEY_ARN);
    await expect(signer.sign(new Uint8Array(10))).rejects.toThrow(/malformed signature/);
  });
});

describe("assertKmsPublicKeyMatches", () => {
  it("resolves when KMS's key matches the pinned x", async () => {
    const client = mockKms({ publicKey: spki() });
    await expect(
      assertKmsPublicKeyMatches(client, KMS_KEY_ARN, KMS_PUBLIC_X),
    ).resolves.toBeUndefined();
  });

  it("throws when KMS's key differs from the pinned x", async () => {
    const client = mockKms({ publicKey: spki() });
    await expect(
      assertKmsPublicKeyMatches(client, KMS_KEY_ARN, "someOtherPinnedXValue"),
    ).rejects.toThrow(/public key mismatch/);
  });

  it("throws when KMS returns no public key", async () => {
    const client = mockKms({ publicKey: undefined });
    await expect(assertKmsPublicKeyMatches(client, KMS_KEY_ARN, KMS_PUBLIC_X)).rejects.toThrow(
      /no public key/,
    );
  });
});

describe("loadIssuer with a KMS badge key (mock client)", () => {
  beforeEach(() => _resetIssuerCache());
  afterEach(() => _resetIssuerCache());

  it("boots with #key-2 as the badge kid and routes badge signing to KMS", async () => {
    const signature = new Uint8Array(64).fill(9);
    const client = mockKms({ signature, publicKey: spki() });
    const issuer = await loadIssuer({
      domain: "ministry.id",
      kms: { keyId: KMS_KEY_ARN, publicJwk: KMS_PUBLIC_JWK, client },
    });

    // Badge key is #key-2; token key is a distinct in-process #key-3.
    expect(issuer.kid).toBe("did:web:ministry.id#key-2");
    expect(issuer.publicJwk.x).toBe(KMS_PUBLIC_X);
    expect(issuer.token.kid).toBe("did:web:ministry.id#key-3");
    expect(issuer.token.publicJwk.x).not.toBe(KMS_PUBLIC_X);

    // Signing a badge routes through the injected KMS client.
    await issuer.signer.sign(new TextEncoder().encode("x"));
    expect(client.signCalls).toHaveLength(1);
  });

  it("refuses to boot (fail-closed) when the pinned JWK disagrees with KMS", async () => {
    const client = mockKms({ signature: new Uint8Array(64), publicKey: spki() });
    const wrongPin = JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    await expect(
      loadIssuer({
        domain: "ministry.id",
        kms: { keyId: KMS_KEY_ARN, publicJwk: wrongPin, client },
      }),
    ).rejects.toThrow(/public key mismatch/);
  });

  it("produces a valid, kid=#key-2 badge VC when the mock KMS delegates to a real Ed25519 key", async () => {
    // The mock signs with a real in-process Ed25519 key and reports its SPKI,
    // so the emitted VC actually verifies — proving the compact JWS the KMS
    // path builds is valid AND carries kid=#key-2 (no live AWS needed).
    const { generateKeyPairSync, sign: nodeSign } = await import("node:crypto");
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const spkiDer = new Uint8Array(publicKey.export({ type: "spki", format: "der" }));
    const pinnedJwk = JSON.stringify({ kty: "OKP", crv: "Ed25519", x: ed25519JwkX(spkiDer) });

    const client: KmsSigningClient = {
      async sign(input) {
        return { Signature: new Uint8Array(nodeSign(null, input.Message, privateKey)) };
      },
      async getPublicKey() {
        return { PublicKey: spkiDer };
      },
    };

    const issuer = await loadIssuer({
      domain: "ministry.id",
      kms: { keyId: KMS_KEY_ARN, publicJwk: pinnedJwk, client },
    });
    const subjectDid = buildUserDid(issuer.domain, "u_kms");
    const vcJwt = await issueVc(issuer, "email-domain", subjectDid, { domain: "example.com" });

    const verified = await verifyVc(issuer, vcJwt);
    expect(verified.sub).toBe(subjectDid);
    const { protectedHeader } = await jwtVerify(vcJwt, issuer.publicKey, { algorithms: ["EdDSA"] });
    expect(protectedHeader.kid).toBe("did:web:ministry.id#key-2");
  });
});

// Live end-to-end round trip against the real KMS key. Skipped unless
// MINISTER_KMS_LIVE_TEST is set (requires AWS credentials able to kms:Sign +
// kms:GetPublicKey on the key). Proves a KMS RAW/ED25519_SHA_512 signature
// verifies as a compact JWS `EdDSA` against the served public JWK.
describe.skipIf(!process.env.MINISTER_KMS_LIVE_TEST)("KMS live round trip", () => {
  beforeEach(() => _resetIssuerCache());
  afterEach(() => _resetIssuerCache());

  it("a KMS-signed badge VC verifies against the pinned public JWK", async () => {
    const client = createAwsKmsClient({ region: "us-east-2" });

    // Boot assertion against the real key.
    await expect(
      assertKmsPublicKeyMatches(client, KMS_KEY_ARN, KMS_PUBLIC_X),
    ).resolves.toBeUndefined();

    const issuer = await loadIssuer({
      domain: "ministry.id",
      kms: { keyId: KMS_KEY_ARN, publicJwk: KMS_PUBLIC_JWK, client },
    });
    const subjectDid = buildUserDid(issuer.domain, "live_user");
    const vcJwt = await issueVc(issuer, "email-domain", subjectDid, { domain: "example.com" });

    // Verify via the package verifier...
    const verified = await verifyVc(issuer, vcJwt);
    expect(verified.sub).toBe(subjectDid);

    // ...and independently via jose against the served public JWK (exactly what
    // an RP does), pinning algorithms to EdDSA.
    const { payload, protectedHeader } = await jwtVerify(vcJwt, issuer.publicKey, {
      algorithms: ["EdDSA"],
    });
    expect(protectedHeader.kid).toBe("did:web:ministry.id#key-2");
    expect(payload.iss).toBe(issuer.did);
  });

  it("signs a raw message with kmsSigner and it verifies as pure Ed25519 JWS", async () => {
    const client = createAwsKmsClient({ region: "us-east-2" });
    const signer = kmsSigner(client, KMS_KEY_ARN);
    const jwt = await signCompactJwt(
      { alg: "EdDSA", kid: "did:web:ministry.id#key-2", typ: "JWT" },
      { hello: "world", iat: Math.floor(Date.now() / 1000) },
      signer,
    );
    const { payload } = await jwtVerify(jwt, await importPinnedKey(), { algorithms: ["EdDSA"] });
    expect(payload.hello).toBe("world");
  });
});

async function importPinnedKey() {
  const { importJWK } = await import("jose");
  return importJWK({ kty: "OKP", crv: "Ed25519", x: KMS_PUBLIC_X, alg: "EdDSA" }, "EdDSA");
}
