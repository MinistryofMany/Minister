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
//
// This is the GLOBAL holder DID, embedding the raw internal userId. It is
// used only for Minister's internal stored record (`Badge.vcJwt`) and MUST
// NOT be disclosed to a relying party (it correlates across RPs and leaks
// the internal id). At disclosure the VC is re-minted under a pairwise
// subject - see buildPairwiseUserDid.
export function buildUserDid(domain: string, userId: string): string {
  return `did:web:${domain}:users:${userId}`;
}

// Pairwise (per-relying-party) subject DID used in disclosed VCs. The `sub`
// component is an opaque, per-RP pseudonym (Minister's OIDC pairwise `sub`,
// or a non-correlating opaque token for share links). It carries no raw
// userId and is distinct from the `:users:` namespace above, so the two are
// never confused. Different RPs see different DIDs for the same user.
export function buildPairwiseUserDid(domain: string, sub: string): string {
  return `did:web:${domain}:u:${sub}`;
}

export function getDidDocument(issuer: Issuer): DidDocument {
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
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
