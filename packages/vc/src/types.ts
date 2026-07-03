import type { JWK, KeyLike } from "jose";

// Pluggable signer over a JWS signing input. The seam that lets badge VCs be
// signed by AWS KMS (non-extractable, HSM-held) while tokens keep an in-process
// key. `sign` MUST return a pure-Ed25519 (RFC 8032 §5.1, no prehash) signature
// over the exact bytes given — that is what a compact JWS `EdDSA` verifier
// expects. Implementations live in `signer.ts` (local) and `kms.ts` (KMS).
export interface IssuerSigner {
  sign(signingInput: Uint8Array): Promise<Uint8Array>;
}

// In-process token-signing key (#key-3). Signs the OIDC id_token and access
// token, which can exceed KMS's 4096-byte RAW-sign limit once several badges
// are embedded, so they never route through KMS. Its public JWK is served in
// JWKS but deliberately NOT in the DID document's `assertionMethod`: it attests
// nothing. The reference RP verifier (`@minister/client`) resolves badge keys
// from the DID document's `assertionMethod` — NOT the raw JWKS — and rejects any
// badge whose `kid` is not listed there, so a stolen token key cannot forge a
// badge VC that verifier will accept. Verifiers that instead trust the raw JWKS
// select a key by `kid` and WOULD accept a `#key-3`-signed badge; the split only
// holds for verifiers that pin to `assertionMethod`.
export interface TokenSigningKey {
  kid: string;
  privateKey: KeyLike;
  publicKey: KeyLike;
  publicJwk: JWK;
}

// Loaded Minister issuer key + its DID-bound identifiers. Threaded through
// `issueVc` / `verifyVc` so the package itself never reads env directly.
//
// Two keys, distinguished by `kid`:
//   - Badge key (#key-2): `signer` + `kid` + `publicKey`/`publicJwk`. Signs
//     badge VCs (`issueVc`, `reMintVc`). In production `signer` is KMS-backed;
//     in dev/tests it wraps a local Ed25519 key. `publicKey` is the badge
//     verification key (also the `reMintVc` integrity gate) and the sole entry
//     in the DID document's `assertionMethod`.
//   - Token key (#key-3): `token`. In-process only; signs id/access tokens.
export interface Issuer {
  domain: string;
  did: string;
  kid: string;
  signer: IssuerSigner;
  publicKey: KeyLike;
  publicJwk: JWK;
  token: TokenSigningKey;
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
