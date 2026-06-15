// Next.js startup hook (App Router, stable in 15). Runs once per server
// boot, before any request is served. We use it for fail-loud-at-boot
// config checks that we'd otherwise only discover deep inside a request.

export async function register(): Promise<void> {
  // Only meaningful on the Node.js runtime; skip the edge bundle.
  if (process.env.NEXT_RUNTIME !== "nodejs") return;

  const { validateTlsnVerifierConfig } = await import("@/lib/tlsn-verifier");
  validateTlsnVerifierConfig();
}
