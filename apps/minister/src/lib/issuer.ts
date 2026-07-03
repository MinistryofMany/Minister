import { join } from "node:path";

import { loadIssuer, type Issuer, type KmsIssuerOptions } from "@minister/vc";

// Singleton issuer for the process. Caches under globalThis so HMR in
// dev doesn't churn through fresh keys.
declare global {
  var __ministerIssuerPromise: Promise<Issuer> | undefined;
}

// Dev-only persistent key files (gitignored). Badge key = #key-2, token
// key = #key-3. In prod both come from env / KMS; these paths are unused.
const DEV_KEY_PATH = join(process.cwd(), "dev-keys", "issuer.jwk");
const TOKEN_DEV_KEY_PATH = join(process.cwd(), "dev-keys", "token.jwk");

// Resolve the KMS badge-key config from env. Returns undefined when KMS is not
// wired (dev/local, or a prod fallback to a local ISSUER_PRIVATE_JWK). When
// MINISTER_KMS_KEY_ID is set, ISSUER_KMS_PUBLIC_JWK is REQUIRED — the pinned
// public key is the boot-time trust anchor loadIssuer verifies against KMS.
function resolveKmsOptions(): KmsIssuerOptions | undefined {
  const keyId = process.env.MINISTER_KMS_KEY_ID;
  if (!keyId) return undefined;
  const publicJwk = process.env.ISSUER_KMS_PUBLIC_JWK;
  if (!publicJwk) {
    throw new Error(
      "MINISTER_KMS_KEY_ID is set but ISSUER_KMS_PUBLIC_JWK (the pinned key-2 public JWK) is missing",
    );
  }
  return { keyId, publicJwk, region: process.env.AWS_REGION };
}

export function getIssuer(): Promise<Issuer> {
  if (!globalThis.__ministerIssuerPromise) {
    const domain = process.env.MINISTER_ISSUER_DOMAIN ?? "minister.local";
    const isProd = process.env.NODE_ENV === "production";
    const kms = resolveKmsOptions();

    // Token key (#key-3) is always in-process. Prod must provide it explicitly;
    // dev generates + persists to a gitignored file.
    const tokenJwk = process.env.TOKEN_SIGNING_JWK;
    if (isProd && !tokenJwk) {
      throw new Error("TOKEN_SIGNING_JWK must be set in production (id/access-token signing key)");
    }

    const promise = loadIssuer({
      domain,
      // KMS wins for the badge key; only fall back to a local private JWK when
      // KMS is not configured. In prod the local badge key is required; in dev
      // we pass devKeyPath so a fresh boot generates + persists one.
      privateJwk: kms ? undefined : process.env.ISSUER_PRIVATE_JWK,
      devKeyPath: isProd || kms ? undefined : DEV_KEY_PATH,
      kms,
      tokenJwk,
      tokenDevKeyPath: isProd ? undefined : TOKEN_DEV_KEY_PATH,
    });

    // Never cache a REJECTED promise. loadIssuer's KMS trust-anchor check
    // (assertKmsPublicKeyMatches) hits AWS at first load; a transient blip there
    // would otherwise poison the global for the process lifetime, re-throwing the
    // stale rejection on every later call until a restart. Clear the cache on
    // failure so the next getIssuer() re-attempts the load.
    promise.catch(() => {
      if (globalThis.__ministerIssuerPromise === promise) {
        globalThis.__ministerIssuerPromise = undefined;
      }
    });

    globalThis.__ministerIssuerPromise = promise;
  }
  return globalThis.__ministerIssuerPromise;
}
