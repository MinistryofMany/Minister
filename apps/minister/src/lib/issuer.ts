import { join } from "node:path";

import { loadIssuer, type Issuer } from "@minister/vc";

// Singleton issuer for the process. Caches under globalThis so HMR in
// dev doesn't churn through fresh keys.
declare global {
  var __ministerIssuerPromise: Promise<Issuer> | undefined;
}

const DEV_KEY_PATH = join(process.cwd(), "dev-keys", "issuer.jwk");

export function getIssuer(): Promise<Issuer> {
  if (!globalThis.__ministerIssuerPromise) {
    const domain = process.env.MINISTER_ISSUER_DOMAIN ?? "minister.local";
    globalThis.__ministerIssuerPromise = loadIssuer({
      domain,
      privateJwk: process.env.ISSUER_PRIVATE_JWK,
      // In prod, ISSUER_PRIVATE_JWK is required. We still pass devKeyPath
      // so that fresh dev boots (no env) generate + persist a key rather
      // than erroring out.
      devKeyPath:
        process.env.NODE_ENV === "production" ? undefined : DEV_KEY_PATH,
    });
  }
  return globalThis.__ministerIssuerPromise;
}
