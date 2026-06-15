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

export async function verifyPresentation(args: VerifyArgs): Promise<VerifiedTranscript> {
  const url = `${verifierUrl().replace(/\/$/, "")}/verify`;
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
