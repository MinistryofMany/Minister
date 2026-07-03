import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { generateKeyPair, importJWK, exportJWK, type JWK, type KeyLike } from "jose";

import { buildDid, buildKid } from "./did";
import { localSigner } from "./signer";
import type { KmsSigningClient } from "./kms";
import type { Issuer, IssuerSigner, TokenSigningKey } from "./types";

// KMS-backed badge key (#key-2). When present, the badge signer is AWS KMS and
// `publicJwk` is PINNED here (public material) so boot does not depend on KMS
// availability — but at load we still call GetPublicKey and hard-fail on any
// mismatch (fail-closed trust anchor).
export interface KmsIssuerOptions {
  // Full key ARN (IAM policies reference the ARN, not the alias).
  keyId: string;
  // Pinned public JWK JSON for the KMS key (OKP/Ed25519, public-only).
  publicJwk: string;
  region?: string;
  // Test seam: inject a mock KMS client. Real callers omit this.
  client?: KmsSigningClient;
}

interface LoadIssuerOptions {
  // The minister-side hostname. Drives did:web identifier construction.
  domain: string;
  // Badge key (#key-2), LOCAL path (dev/tests, or prod without KMS): the raw
  // JSON of a private JWK. Loader parses + imports.
  privateJwk?: string;
  // Dev-only fallback for the local badge key. If neither `privateJwk` nor
  // `kms` is set AND this is provided, loader reads/writes a persistent key
  // here, generating one on first boot.
  devKeyPath?: string;
  // Badge key (#key-2), KMS-backed (production). Mutually exclusive with the
  // local badge-key sources above; when set it wins.
  kms?: KmsIssuerOptions;
  // Token key (#key-3), always in-process. Raw JSON of a private JWK.
  tokenJwk?: string;
  // Dev-only fallback for the token key. Read/generate+persist. When neither
  // `tokenJwk` nor this is set, an EPHEMERAL in-memory token key is generated
  // (tests / dev fallback); prod callers must supply `tokenJwk`.
  tokenDevKeyPath?: string;
}

const ALG = "EdDSA";
const CRV = "Ed25519";
const BADGE_KID_FRAGMENT = "key-2";
const TOKEN_KID_FRAGMENT = "key-3";

function stripPrivate(jwk: JWK): JWK {
  // jose includes d (private scalar). Strip for public-facing copies.
  const { d: _d, ...pub } = jwk;
  return pub;
}

async function importIssuerJwk(jwkJson: string): Promise<{
  privateKey: KeyLike;
  publicKey: KeyLike;
  publicJwk: JWK;
}> {
  const jwk = JSON.parse(jwkJson) as JWK;
  if (jwk.kty !== "OKP" || jwk.crv !== CRV) {
    throw new Error(`Issuer key must be OKP/${CRV} (got kty=${jwk.kty}, crv=${jwk.crv})`);
  }
  if (!jwk.d) {
    throw new Error("Issuer JWK is missing private scalar 'd'");
  }
  const privateKey = (await importJWK(jwk, ALG)) as KeyLike;
  const publicJwk = stripPrivate(jwk);
  const publicKey = (await importJWK(publicJwk, ALG)) as KeyLike;
  return { privateKey, publicKey, publicJwk };
}

async function generateJwkJson(): Promise<string> {
  const { privateKey } = await generateKeyPair(ALG, {
    crv: CRV,
    extractable: true,
  });
  const jwk = await exportJWK(privateKey);
  jwk.alg = ALG;
  jwk.use = "sig";
  return JSON.stringify(jwk);
}

async function readOrGeneratePersisted(keyPath: string): Promise<string> {
  try {
    return await readFile(keyPath, "utf8");
  } catch {
    // First boot in dev — generate and persist.
    const jwkJson = await generateJwkJson();
    await mkdir(dirname(keyPath), { recursive: true });
    await writeFile(keyPath, jwkJson, { mode: 0o600 });
    return jwkJson;
  }
}

interface BadgeKeyMaterial {
  signer: IssuerSigner;
  publicKey: KeyLike;
  publicJwk: JWK;
}

async function loadKmsBadgeKey(kms: KmsIssuerOptions, kid: string): Promise<BadgeKeyMaterial> {
  const pinned = JSON.parse(kms.publicJwk) as JWK;
  if (pinned.kty !== "OKP" || pinned.crv !== CRV) {
    throw new Error(`KMS public JWK must be OKP/${CRV} (got kty=${pinned.kty}, crv=${pinned.crv})`);
  }
  if (typeof pinned.x !== "string" || pinned.x.length === 0) {
    throw new Error("KMS public JWK is missing coordinate 'x'");
  }
  if (pinned.d) {
    throw new Error("KMS public JWK must be public-only (unexpected private scalar 'd')");
  }
  const publicJwk: JWK = { kty: "OKP", crv: CRV, x: pinned.x, alg: ALG, use: "sig", kid };
  const publicKey = (await importJWK(publicJwk, ALG)) as KeyLike;

  // Dynamic import keeps the AWS SDK out of the require graph on the common
  // (dev/test/local) path — it loads only when a KMS key is actually wired.
  const { kmsSigner, assertKmsPublicKeyMatches, createAwsKmsClient } = await import("./kms");
  const client = kms.client ?? createAwsKmsClient({ region: kms.region });
  // Fail-closed trust anchor: refuse to boot if KMS's key ≠ the pinned key.
  await assertKmsPublicKeyMatches(client, kms.keyId, pinned.x);

  return { signer: kmsSigner(client, kms.keyId), publicKey, publicJwk };
}

async function loadLocalBadgeKey(
  options: LoadIssuerOptions,
  kid: string,
): Promise<BadgeKeyMaterial> {
  let jwkJson = options.privateJwk;
  if (!jwkJson) {
    if (!options.devKeyPath) {
      throw new Error(
        "Minister badge key missing: set ISSUER_PRIVATE_JWK or MINISTER_KMS_KEY_ID, or pass devKeyPath",
      );
    }
    jwkJson = await readOrGeneratePersisted(options.devKeyPath);
  }
  const { privateKey, publicKey, publicJwk } = await importIssuerJwk(jwkJson);
  return {
    signer: localSigner(privateKey),
    publicKey,
    publicJwk: { ...publicJwk, alg: ALG, use: "sig", kid },
  };
}

async function loadTokenKey(options: LoadIssuerOptions, kid: string): Promise<TokenSigningKey> {
  let jwkJson = options.tokenJwk;
  if (!jwkJson) {
    jwkJson = options.tokenDevKeyPath
      ? await readOrGeneratePersisted(options.tokenDevKeyPath)
      : await generateJwkJson();
  }
  const { privateKey, publicKey, publicJwk } = await importIssuerJwk(jwkJson);
  return {
    kid,
    privateKey,
    publicKey,
    publicJwk: { ...publicJwk, alg: ALG, use: "sig", kid },
  };
}

// Idempotent: same args → same Issuer instance for the life of the
// process. Across processes, persistence depends on env / dev-key file.
let cached: Issuer | undefined;
let cacheKey: string | undefined;

// The KMS client (when injected for tests) is not serializable; the cache key
// captures only the identity-bearing, serializable options.
function computeCacheKey(options: LoadIssuerOptions): string {
  return JSON.stringify({
    domain: options.domain,
    privateJwk: options.privateJwk,
    devKeyPath: options.devKeyPath,
    kms: options.kms
      ? { keyId: options.kms.keyId, publicJwk: options.kms.publicJwk, region: options.kms.region }
      : undefined,
    tokenJwk: options.tokenJwk,
    tokenDevKeyPath: options.tokenDevKeyPath,
  });
}

export async function loadIssuer(options: LoadIssuerOptions): Promise<Issuer> {
  const key = computeCacheKey(options);
  if (cached && cacheKey === key) return cached;

  const did = buildDid(options.domain);
  const badgeKid = buildKid(did, BADGE_KID_FRAGMENT);
  const tokenKid = buildKid(did, TOKEN_KID_FRAGMENT);

  const badge = options.kms
    ? await loadKmsBadgeKey(options.kms, badgeKid)
    : await loadLocalBadgeKey(options, badgeKid);
  const token = await loadTokenKey(options, tokenKid);

  const issuer: Issuer = {
    domain: options.domain,
    did,
    kid: badgeKid,
    signer: badge.signer,
    publicKey: badge.publicKey,
    publicJwk: badge.publicJwk,
    token,
  };

  cached = issuer;
  cacheKey = key;
  return issuer;
}

// Test seam — primarily for hot-reload safety in dev. Production callers
// shouldn't need this.
export function _resetIssuerCache(): void {
  cached = undefined;
  cacheKey = undefined;
}
