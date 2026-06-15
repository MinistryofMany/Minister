import type { JWK, KeyLike } from "jose";

// Loaded Minister issuer key + its DID-bound identifiers. Threaded through
// `issueVc` / `verifyVc` so the package itself never reads env directly.
export interface Issuer {
  domain: string;
  did: string;
  kid: string;
  privateKey: KeyLike;
  publicKey: KeyLike;
  publicJwk: JWK;
}

// W3C VC Data Model 2.0 payload, restricted to the shapes Minister issues
// today. credentialSubject.id is required because we always bind a VC to
// a subject DID (the user's did:web URL).
export interface CredentialSubject {
  id: string;
  [claim: string]: unknown;
}

export interface VerifiableCredentialClaim {
  "@context": string[];
  type: string[];
  credentialSubject: CredentialSubject;
}

export interface VerifiedCredential {
  iss: string;
  sub: string;
  jti?: string;
  iat: number;
  nbf?: number;
  exp?: number;
  vc: VerifiableCredentialClaim;
}

export interface IssueOptions {
  jti?: string;
  // e.g. "1y", "30d", or seconds-from-now. Defaults to "1y".
  expiresIn?: string | number;
  notBefore?: Date;
  extraContexts?: string[];
}

// DID document — minimal shape we serve at /.well-known/did.json.
export interface DidDocument {
  "@context": string[];
  id: string;
  verificationMethod: Array<{
    id: string;
    type: "JsonWebKey2020";
    controller: string;
    publicKeyJwk: JWK;
  }>;
  assertionMethod: string[];
  authentication: string[];
}
