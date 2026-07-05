// Next.js startup hook (App Router, stable in 15). Runs once per server
// boot, before any request is served. We use it for fail-loud-at-boot
// config checks that we'd otherwise only discover deep inside a request.

export async function register(): Promise<void> {
  // Only meaningful on the Node.js runtime; skip the edge bundle.
  if (process.env.NEXT_RUNTIME !== "nodejs") return;

  // MUST run first: pull SecureString secrets from SSM into process.env before
  // anything reads config — the issuer keys (issuer.ts), Prisma's DATABASE_URL,
  // Auth.js's AUTH_SECRET, and the OIDC pairwise secret. Next awaits register()
  // before serving requests, and the edge middleware sandbox snapshots
  // process.env on its first request (after this), so AUTH_SECRET reaches
  // middleware too. Fail-closed in prod (throws), inert with no SSM path.
  const { loadSecretsFromSsm } = await import("@/lib/secrets");
  await loadSecretsFromSsm();

  // Validate the server env NOW — AFTER the SSM secrets are in process.env and
  // before any request runs. env.ts parses process.env at module load and THROWS
  // on a bad/half-configured deploy: a non-local pairwise backend missing its
  // MINISTER_SIGNET_* transport, a pure `signet` sub-backend while
  // OIDC_PAIRWISE_SECRET is still present, a MINISTER_SUB_BACKEND typo, an
  // http:// (non-mTLS) Signet URL, or a missing/short pairwise secret. Without
  // this a half-configured shadow/signet-fallback/signet deploy boots clean and
  // 500s deep inside token minting instead of failing fast here.
  //
  // Ordering is load-bearing: it MUST run after loadSecretsFromSsm() (the secret,
  // DATABASE_URL, and cert material may all arrive from SSM) and it is a DYNAMIC
  // import so the module is not pulled into the edge/middleware compile and does
  // not parse before the SSM load has populated process.env.
  await import("@/env");

  const { validateTlsnVerifierConfig } = await import("@/lib/tlsn-verifier");
  validateTlsnVerifierConfig();

  // Crypto-core Phase 3: when the signet nullifier backend is selected,
  // fetch-and-verify the pinned VOPRF public key against the live Signet at
  // boot, fail-closed (the build plan's "mirrors the KMS JWK pattern"). A
  // mis-pinned deploy, wrong MINISTER_SIGNET_URL, or bad mTLS material dies
  // HERE, legibly, instead of on the first user's badge mint. Runs after the
  // SSM load above (the pin and cert material may come from SSM).
  //
  // The explicit NEXT_RUNTIME guard (redundant with the early return above at
  // runtime) is FOR WEBPACK: instrumentation is compiled for the edge bundle
  // too, where node:https/node:fs cannot resolve — the statically-false
  // branch makes webpack drop this import from the edge compile entirely.
  if (
    process.env.NEXT_RUNTIME === "nodejs" &&
    process.env.MINISTER_NULLIFIER_BACKEND === "signet"
  ) {
    const { signetBackend } = await import("@/lib/nullifier/signet-backend");
    await signetBackend.verifyPin();
  }
}
