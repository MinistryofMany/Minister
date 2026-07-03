import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
  type KMSClientConfig,
} from "@aws-sdk/client-kms";
import { base64url } from "jose";

import type { IssuerSigner } from "./types";

// KMS signing parameters are CONSTANTS, never options. There is deliberately no
// code path that reaches `ED25519_PH_SHA_512` (HashEdDSA — does not verify as
// JWS `EdDSA`) or `MessageType=DIGEST`. Misuse would require editing this file.
const SIGNING_ALGORITHM = "ED25519_SHA_512" as const;
const MESSAGE_TYPE = "RAW" as const;

// KMS `Sign` with `MessageType=RAW` caps the message at exactly 4096 bytes. A
// JWS signing input above this must never be sent to KMS (id_tokens can exceed
// it once badges are embedded); we reject with a domain error BEFORE the call.
export const MAX_RAW_MESSAGE_BYTES = 4096;

// A pure-Ed25519 signature is always 64 bytes (R||S). Anything else means KMS
// returned something we must not ship as a JWS signature — fail closed.
const ED25519_SIGNATURE_BYTES = 64;

// RFC 8410 SubjectPublicKeyInfo prefix for an Ed25519 public key (12 bytes),
// followed by the 32-byte raw key. `GetPublicKey` returns this DER SPKI.
const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const ED25519_SPKI_LENGTH = ED25519_SPKI_PREFIX.length + 32;

export interface KmsSignInput {
  KeyId: string;
  Message: Uint8Array;
  MessageType: typeof MESSAGE_TYPE;
  SigningAlgorithm: typeof SIGNING_ALGORITHM;
}

export interface KmsSignOutput {
  Signature?: Uint8Array;
}

export interface KmsGetPublicKeyOutput {
  PublicKey?: Uint8Array;
}

// Narrow client surface Minister needs — two methods, no command objects. The
// real AWS SDK is adapted by `createAwsKmsClient`; tests inject a mock that
// implements exactly these two methods.
export interface KmsSigningClient {
  sign(input: KmsSignInput): Promise<KmsSignOutput>;
  getPublicKey(input: { KeyId: string }): Promise<KmsGetPublicKeyOutput>;
}

// Adapt the AWS SDK v3 KMS client to `KmsSigningClient`. One module-level
// client per key (keep-alive connection reuse) is created by the caller and
// passed in; default SDK retry (3, jittered) is fine for a deterministic sign.
export function createAwsKmsClient(config: KMSClientConfig = {}): KmsSigningClient {
  const client = new KMSClient(config);
  return {
    async sign(input) {
      const out = await client.send(new SignCommand(input));
      return { Signature: out.Signature };
    },
    async getPublicKey(input) {
      const out = await client.send(new GetPublicKeyCommand(input));
      return { PublicKey: out.PublicKey };
    },
  };
}

// Derive the base64url raw-key `x` (the JWK coordinate) from a DER SPKI Ed25519
// public key, validating the RFC 8410 prefix and length so a wrong key spec
// can't silently produce a garbage `x`.
export function ed25519JwkX(spki: Uint8Array): string {
  if (spki.length !== ED25519_SPKI_LENGTH) {
    throw new Error(
      `KMS public key is not a ${ED25519_SPKI_LENGTH}-byte Ed25519 SPKI (got ${spki.length} bytes)`,
    );
  }
  for (let i = 0; i < ED25519_SPKI_PREFIX.length; i++) {
    if (spki[i] !== ED25519_SPKI_PREFIX[i]) {
      throw new Error("KMS public key has an unexpected SPKI prefix (not Ed25519)");
    }
  }
  return base64url.encode(spki.subarray(ED25519_SPKI_PREFIX.length));
}

// Boot-time trust anchor: call `GetPublicKey` and assert the derived `x` equals
// the pinned public JWK `x`. A mismatch means we would publish signatures that
// verify against nothing (the silent-rejection failure class) — so refuse to
// boot. `x` is public material; including both values in the error is safe.
export async function assertKmsPublicKeyMatches(
  client: KmsSigningClient,
  keyId: string,
  expectedX: string,
): Promise<void> {
  const { PublicKey } = await client.getPublicKey({ KeyId: keyId });
  if (!PublicKey) {
    throw new Error("KMS GetPublicKey returned no public key");
  }
  const actualX = ed25519JwkX(PublicKey);
  if (actualX !== expectedX) {
    throw new Error(
      `KMS public key mismatch: pinned x=${expectedX} but KMS key ${keyId} has x=${actualX}`,
    );
  }
}

// KMS-backed `IssuerSigner`. Pins RAW + ED25519_SHA_512, rejects any signing
// input over the 4096-byte RAW limit BEFORE the network call, and asserts the
// returned signature is exactly 64 bytes. No fallback: a KMS error propagates
// and issuance/disclosure fails closed.
export function kmsSigner(client: KmsSigningClient, keyId: string): IssuerSigner {
  return {
    async sign(signingInput: Uint8Array): Promise<Uint8Array> {
      if (signingInput.byteLength > MAX_RAW_MESSAGE_BYTES) {
        throw new Error(
          `KMS RAW sign limit exceeded: ${signingInput.byteLength} > ${MAX_RAW_MESSAGE_BYTES} bytes — this artifact must not be signed by KMS`,
        );
      }
      const { Signature } = await client.sign({
        KeyId: keyId,
        Message: signingInput,
        MessageType: MESSAGE_TYPE,
        SigningAlgorithm: SIGNING_ALGORITHM,
      });
      if (!Signature || Signature.byteLength !== ED25519_SIGNATURE_BYTES) {
        throw new Error(
          `KMS returned a malformed signature (expected ${ED25519_SIGNATURE_BYTES} bytes, got ${Signature?.byteLength ?? 0})`,
        );
      }
      return Signature;
    },
  };
}
