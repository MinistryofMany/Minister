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

  const { validateTlsnVerifierConfig } = await import("@/lib/tlsn-verifier");
  validateTlsnVerifierConfig();
}
