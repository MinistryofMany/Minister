import { z } from "zod";

// Client for the `services/tlsn-verifier` Rust HTTP sidecar.
//
// Why a sidecar over WASM-in-Node: pin one tlsn version, isolate
// breaking-upstream-changes from the app, keep all `tlsn-verifier`
// crate code in Rust where it lives. The Next.js app makes a single
// POST per submission.
//
// Wire shape (POST /verify):
//   request : { presentation: <base64-bytes>, expectedDomain: <string> }
//   response: { ok: true, transcript: { ... } }
//           | { ok: false, error: <string> }
// The transcript is the verified plaintext from the recorded session,
// shape determined by the tlsn-verifier crate. Plugins extract their
// fact of interest from it.

const VerifyOk = z.object({
  ok: z.literal(true),
  transcript: z.object({
    sent: z.string(), // bytes the client sent (request)
    received: z.string(), // bytes the server returned (response)
    serverName: z.string(),
  }),
  // Notary's public key the verifier used to validate the co-signature.
  // Lets the caller pin the notary if it cares.
  notaryKey: z.string().optional(),
});

const VerifyErr = z.object({
  ok: z.literal(false),
  error: z.string(),
});

const VerifyResponse = z.discriminatedUnion("ok", [VerifyOk, VerifyErr]);

export type VerifiedTranscript = z.infer<typeof VerifyOk>["transcript"];

export class TlsnVerifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TlsnVerifierError";
  }
}

export interface VerifyArgs {
  // base64-encoded TLSNotary presentation bytes as produced by the
  // tlsn prover.
  presentation: string;
  // The hostname the plugin expects the presentation to be from. The
  // verifier sidecar rejects mismatches.
  expectedDomain: string;
}

function verifierUrl(): string {
  // Default points at the docker-compose service. Override with
  // TLSN_VERIFIER_URL when running minister on the host alongside a
  // compose-managed verifier.
  return process.env.TLSN_VERIFIER_URL ?? "http://tlsn-verifier:7048";
}

// Comma-separated allowlist of hostnames the verifier URL may point at.
// When set, validateTlsnVerifierConfig() warns if the configured host is
// not present. The full SSRF fix (hard-rejecting out-of-allowlist hosts)
// is gated on this infra landing — see docs/status.md.
const ALLOWLIST_ENV = "MINISTER_TLSN_VERIFIER_ALLOWED_HOSTS";

export interface TlsnVerifierConfigResult {
  ok: boolean;
  warnings: string[];
}

// Pure, exported, and side-effect-light (apart from the optional warn
// emitter) so it can be unit-tested. Called at server startup from
// instrumentation.ts; it WARNS but never throws — this nags every boot
// until the allowlist infra is deployed.
export function validateTlsnVerifierConfig(
  env: Record<string, string | undefined> = process.env,
  warn: (msg: string) => void = console.warn,
): TlsnVerifierConfigResult {
  const warnings: string[] = [];
  const raw = env.TLSN_VERIFIER_URL;

  if (raw === undefined || raw.trim() === "") {
    warnings.push(
      `[tlsn-verifier] TLSN_VERIFIER_URL is unset; falling back to the compose default. ` +
        `Set it explicitly in production.`,
    );
  } else {
    let parsed: URL | undefined;
    try {
      parsed = new URL(raw);
    } catch {
      warnings.push(`[tlsn-verifier] TLSN_VERIFIER_URL is not a valid URL: ${raw}`);
    }

    if (parsed) {
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        warnings.push(`[tlsn-verifier] TLSN_VERIFIER_URL must use http(s); got ${parsed.protocol}`);
      }

      const allowRaw = env[ALLOWLIST_ENV];
      if (allowRaw === undefined || allowRaw.trim() === "") {
        warnings.push(
          `[tlsn-verifier] SSRF hardening INCOMPLETE: ${ALLOWLIST_ENV} not configured; ` +
            `the verifier URL host is not allowlist-enforced.`,
        );
      } else {
        const allowed = allowRaw
          .split(",")
          .map((h) => h.trim().toLowerCase())
          .filter((h) => h.length > 0);
        const host = parsed.hostname.toLowerCase();
        if (!allowed.includes(host)) {
          warnings.push(
            `[tlsn-verifier] TLSN_VERIFIER_URL host "${host}" is not in ${ALLOWLIST_ENV} ` +
              `(${allowed.join(", ")}).`,
          );
        }
      }
    }
  }

  for (const w of warnings) warn(w);
  return { ok: warnings.length === 0, warnings };
}

export async function verifyPresentation(args: VerifyArgs): Promise<VerifiedTranscript> {
  const base = verifierUrl().replace(/\/$/, "");
  // Defense-in-depth: refuse to fetch a non-http(s) verifier URL even if
  // the startup warning was ignored. Guards against file:/, etc.
  let scheme: string;
  try {
    scheme = new URL(base).protocol;
  } catch {
    throw new TlsnVerifierError(`tlsn-verifier URL is not a valid URL: ${base}`);
  }
  if (scheme !== "http:" && scheme !== "https:") {
    throw new TlsnVerifierError(`tlsn-verifier URL must use http(s), got ${scheme}`);
  }
  const url = `${base}/verify`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        presentation: args.presentation,
        expectedDomain: args.expectedDomain,
      }),
    });
  } catch (cause) {
    throw new TlsnVerifierError(
      `Could not reach tlsn-verifier at ${url}: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
  }

  let json: unknown;
  try {
    json = await response.json();
  } catch {
    throw new TlsnVerifierError(`tlsn-verifier returned non-JSON (HTTP ${response.status})`);
  }

  const parsed = VerifyResponse.safeParse(json);
  if (!parsed.success) {
    throw new TlsnVerifierError(
      `tlsn-verifier response did not match the expected shape: ${parsed.error.message}`,
    );
  }
  if (!parsed.data.ok) {
    throw new TlsnVerifierError(parsed.data.error);
  }
  return parsed.data.transcript;
}
