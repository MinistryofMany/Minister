import { sign as nodeSign, type KeyObject } from "node:crypto";

import { base64url, type KeyLike } from "jose";

import type { IssuerSigner } from "./types";

// In-process Ed25519 signer. Wraps Node's `crypto.sign(null, ...)`, which for an
// Ed25519 key produces exactly the pure-Ed25519 (RFC 8032) signature a compact
// JWS `EdDSA` verifier expects. Used for the token key (#key-3) always, and for
// the badge key (#key-2) in dev/tests where there is no KMS.
export function localSigner(privateKey: KeyLike): IssuerSigner {
  return {
    async sign(signingInput: Uint8Array): Promise<Uint8Array> {
      // jose's importJWK/generateKeyPair returns a Node KeyObject in the Node
      // runtime for OKP/Ed25519. `crypto.sign(null, data, key)` selects EdDSA
      // with no prehash for Ed25519 keys.
      return nodeSign(null, signingInput, privateKey as KeyObject);
    },
  };
}

// Build a compact JWS by hand: `b64u(header).b64u(payload).b64u(sig)`. jose's
// SignJWT takes key material only (no pluggable signer hook), so the KMS path
// cannot use it — this replicates the compact-JWS construction and delegates the
// signature to the `IssuerSigner`. The header/payload are serialized exactly as
// given; callers stamp `iat`/`nbf`/`exp`/`jti` before calling.
export async function signCompactJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signer: IssuerSigner,
): Promise<string> {
  const encodedHeader = base64url.encode(JSON.stringify(header));
  const encodedPayload = base64url.encode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64url.encode(signature)}`;
}
