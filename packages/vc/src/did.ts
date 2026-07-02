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

// Per-RP PAIRWISE subject DID used in `sub` / `credentialSubject.id` of a
// badge VC re-minted at disclosure time. `pairwiseSub` is the OIDC pairwise
// pseudonym for the (user, relying-party) pair (the SAME value stamped as the
// id_token `sub`), so the trailing component lets a relying party bind a
// disclosed badge to the login while two colluding relying parties see
// different subjects for the same user.
//
// Note the `:u:` marker (distinct from the legacy `:users:` from
// `buildUserDid`): the `:users:<userId>` shape carries a STABLE cross-RP user
// id and is never disclosed to a relying party; `:u:<pairwiseSub>` is the only
// subject shape that leaves Minister in a disclosed VC.
export function buildPairwiseUserDid(domain: string, pairwiseSub: string): string {
  return `did:web:${domain}:u:${pairwiseSub}`;
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
