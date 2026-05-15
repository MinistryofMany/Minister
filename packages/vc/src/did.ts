import type { Issuer, DidDocument } from "./types";

// did:web identifier for a domain. Per W3C did:web spec, the document is
// expected at https://<domain>/.well-known/did.json.
export function buildDid(domain: string): string {
  return `did:web:${domain}`;
}

export function buildKid(did: string, fragment = "key-1"): string {
  return `${did}#${fragment}`;
}

// Subject DID used in `sub` of issued VCs. Path components after the
// domain encode a user namespace.
export function buildUserDid(domain: string, userId: string): string {
  return `did:web:${domain}:users:${userId}`;
}

export function getDidDocument(issuer: Issuer): DidDocument {
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: issuer.did,
    verificationMethod: [
      {
        id: issuer.kid,
        type: "JsonWebKey2020",
        controller: issuer.did,
        // Public-only JWK; private fields are stripped in loadIssuer.
        publicKeyJwk: issuer.publicJwk,
      },
    ],
    assertionMethod: [issuer.kid],
    authentication: [issuer.kid],
  };
}
