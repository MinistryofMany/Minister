import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import {
  generateKeyPair,
  importJWK,
  exportJWK,
  type JWK,
  type KeyLike,
} from "jose";

import { buildDid, buildKid } from "./did";
import type { Issuer } from "./types";

interface LoadIssuerOptions {
  // The minister-side hostname. Drives did:web identifier construction.
  domain: string;
  // PEM/JWK provided via env in production. Pass the raw JSON string of
  // the private JWK; loader will parse + import.
  privateJwk?: string;
  // Dev-only fallback. If `privateJwk` is not provided AND this path is
  // set, loader reads/writes a persistent key here. Generates one on
  // first boot.
  devKeyPath?: string;
}

const ALG = "EdDSA";
const CRV = "Ed25519";

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
    throw new Error(
      `Issuer key must be OKP/${CRV} (got kty=${jwk.kty}, crv=${jwk.crv})`,
    );
  }
  if (!jwk.d) {
    throw new Error("Issuer JWK is missing private scalar 'd'");
  }
  const privateKey = (await importJWK(jwk, ALG)) as KeyLike;
  const publicJwk = stripPrivate(jwk);
  const publicKey = (await importJWK(publicJwk, ALG)) as KeyLike;
  return { privateKey, publicKey, publicJwk };
}

async function generateAndPersist(devKeyPath: string): Promise<string> {
  const { privateKey } = await generateKeyPair(ALG, {
    crv: CRV,
    extractable: true,
  });
  const jwk = await exportJWK(privateKey);
  jwk.alg = ALG;
  jwk.use = "sig";
  await mkdir(dirname(devKeyPath), { recursive: true });
  await writeFile(devKeyPath, JSON.stringify(jwk, null, 2), {
    mode: 0o600,
  });
  return JSON.stringify(jwk);
}

// Idempotent: same args → same Issuer instance for the life of the
// process. Across processes, persistence depends on env / dev-key file.
let cached: Issuer | undefined;
let cacheKey: string | undefined;

export async function loadIssuer(options: LoadIssuerOptions): Promise<Issuer> {
  const key = JSON.stringify(options);
  if (cached && cacheKey === key) return cached;

  let jwkJson = options.privateJwk;

  if (!jwkJson) {
    if (!options.devKeyPath) {
      throw new Error(
        "Minister issuer key missing: set ISSUER_PRIVATE_JWK or pass devKeyPath",
      );
    }
    try {
      jwkJson = await readFile(options.devKeyPath, "utf8");
    } catch {
      // First boot in dev — generate and persist.
      jwkJson = await generateAndPersist(options.devKeyPath);
    }
  }

  const { privateKey, publicKey, publicJwk } = await importIssuerJwk(jwkJson);
  const did = buildDid(options.domain);
  const kid = buildKid(did);

  const issuer: Issuer = {
    domain: options.domain,
    did,
    kid,
    privateKey,
    publicKey,
    publicJwk: { ...publicJwk, alg: ALG, use: "sig", kid },
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
