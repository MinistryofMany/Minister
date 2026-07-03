import { describe, expect, it } from "vitest";

import { buildDid, buildKid, buildPairwiseUserDid, buildUserDid, getDidDocument } from "./did";
import type { Issuer } from "./types";

describe("buildDid", () => {
  it("formats a did:web identifier from a domain", () => {
    expect(buildDid("minister.local")).toBe("did:web:minister.local");
  });

  it("does not add a path component for bare domains", () => {
    expect(buildDid("example.com")).toBe("did:web:example.com");
  });
});

describe("buildKid", () => {
  it("appends a key fragment to a DID", () => {
    expect(buildKid("did:web:minister.local")).toBe("did:web:minister.local#key-1");
  });

  it("honors a custom fragment", () => {
    expect(buildKid("did:web:minister.local", "alt")).toBe("did:web:minister.local#alt");
  });
});

describe("buildUserDid", () => {
  it("namespaces user IDs under a did:web", () => {
    expect(buildUserDid("minister.local", "u_123")).toBe("did:web:minister.local:users:u_123");
  });
});

describe("buildPairwiseUserDid", () => {
  it("uses the :u: marker (not the legacy :users:) with the pairwise sub", () => {
    expect(buildPairwiseUserDid("ministry.id", "abc_PAIRWISE")).toBe(
      "did:web:ministry.id:u:abc_PAIRWISE",
    );
  });

  it("is distinct from the stable buildUserDid shape for the same domain", () => {
    // The stable :users: shape carries a cross-RP user id and is never
    // disclosed; the pairwise :u: shape is the only one that leaves Minister.
    expect(buildPairwiseUserDid("ministry.id", "s")).not.toBe(buildUserDid("ministry.id", "s"));
  });
});

describe("getDidDocument", () => {
  // Minimum Issuer fixture for testing. The DID document doesn't care
  // about the actual key material, only the public JWK + identifiers.
  const issuer = {
    domain: "minister.local",
    did: "did:web:minister.local",
    kid: "did:web:minister.local#key-2",
    publicJwk: {
      kty: "OKP",
      crv: "Ed25519",
      x: "AAAA",
      alg: "EdDSA",
      use: "sig",
      kid: "did:web:minister.local#key-2",
    },
    signer: { sign: async () => new Uint8Array(64) },
    publicKey: {} as Issuer["publicKey"],
    token: {
      kid: "did:web:minister.local#key-3",
      privateKey: {} as Issuer["token"]["privateKey"],
      publicKey: {} as Issuer["token"]["publicKey"],
      publicJwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: "BBBB",
        alg: "EdDSA",
        use: "sig",
        kid: "did:web:minister.local#key-3",
      },
    },
  } satisfies Issuer;

  it("emits the W3C DID context and security-suite context", () => {
    const doc = getDidDocument(issuer);
    expect(doc["@context"]).toEqual([
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ]);
  });

  it("uses the issuer's DID as the document id", () => {
    expect(getDidDocument(issuer).id).toBe(issuer.did);
  });

  it("emits one JsonWebKey2020 verificationMethod controlled by the issuer", () => {
    const doc = getDidDocument(issuer);
    expect(doc.verificationMethod).toHaveLength(1);
    expect(doc.verificationMethod[0]).toEqual({
      id: issuer.kid,
      type: "JsonWebKey2020",
      controller: issuer.did,
      publicKeyJwk: issuer.publicJwk,
    });
  });

  it("references the kid in both assertionMethod and authentication", () => {
    const doc = getDidDocument(issuer);
    expect(doc.assertionMethod).toEqual([issuer.kid]);
    expect(doc.authentication).toEqual([issuer.kid]);
  });
});
