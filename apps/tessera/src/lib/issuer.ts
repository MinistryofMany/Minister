import { join } from "node:path";

import { loadIssuer, type Issuer } from "@tessera/vc";

// Singleton issuer for the process. Caches under globalThis so HMR in
// dev doesn't churn through fresh keys.
declare global {
  var __tesseraIssuerPromise: Promise<Issuer> | undefined;
}

const DEV_KEY_PATH = join(process.cwd(), "dev-keys", "issuer.jwk");

export function getIssuer(): Promise<Issuer> {
  if (!globalThis.__tesseraIssuerPromise) {
    const domain = process.env.TESSERA_ISSUER_DOMAIN ?? "tessera.local";
    globalThis.__tesseraIssuerPromise = loadIssuer({
      domain,
      privateJwk: process.env.ISSUER_PRIVATE_JWK,
      // In prod, ISSUER_PRIVATE_JWK is required. We still pass devKeyPath
      // so that fresh dev boots (no env) generate + persist a key rather
      // than erroring out.
      devKeyPath:
        process.env.NODE_ENV === "production" ? undefined : DEV_KEY_PATH,
    });
  }
  return globalThis.__tesseraIssuerPromise;
}
