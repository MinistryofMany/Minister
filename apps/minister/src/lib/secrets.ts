import { GetParametersByPathCommand, SSMClient, type Parameter } from "@aws-sdk/client-ssm";

// AWS SSM Parameter Store secret loader.
//
// Lightsail (us-east-2) cannot attach IAM instance roles, so ONE static AWS
// key (the box's AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) stays plaintext on
// the box as a bootstrap. Everything else — DATABASE_URL, AUTH_SECRET, the
// pairwise secret, the token key, SMTP + OAuth creds — lives as SSM
// SecureString params and is fetched at boot with that bootstrap key, then
// injected into process.env BEFORE the app reads any config.
//
// Called once from instrumentation.register() on the Node runtime, which Next
// awaits before serving a single request. The edge middleware sandbox snapshots
// process.env lazily on its first invocation (after boot), so AUTH_SECRET and
// friends injected here are visible to middleware too — no separate edge fetch.

// Secrets that MUST be present after an SSM load in production. Mirrors the
// fail-closed posture of issuer.ts ("TOKEN_SIGNING_JWK must be set"): if the
// store is reachable but a core identity/session/token secret is absent, refuse
// to boot rather than start half-configured and fail deep inside a request.
// SMTP_URL and GITHUB_CLIENT_SECRET are still injected when present but are not
// hard-required here — the mailer and the GitHub plugin enforce their own.
const REQUIRED_IN_PROD = [
  "AUTH_SECRET",
  "DATABASE_URL",
  "OIDC_PAIRWISE_SECRET",
  "TOKEN_SIGNING_JWK",
] as const;

function isProd(): boolean {
  return process.env.NODE_ENV === "production";
}

// Injectable so tests can exercise the merge / fail-closed logic without AWS.
export type ParameterFetcher = (path: string) => Promise<Parameter[]>;

/**
 * Fetch SecureString secrets from AWS SSM Parameter Store and inject them into
 * process.env. Path comes from MINISTER_SECRETS_SSM_PATH (e.g. "/minister/prod").
 * Each parameter "<path>/<VARNAME>" is set as process.env.<VARNAME>. An existing
 * (non-empty) env value always wins, so a dev/CI override or the box's bootstrap
 * vars are never clobbered.
 *
 * Fail-closed contract:
 *  - No path configured           -> no-op (dev/local, or pre-cutover prod on a
 *                                    plaintext env — the code ships inert until
 *                                    the SSM path is set at cutover).
 *  - Path set, prod, fetch fails
 *    or a required secret missing  -> throw; refuse to boot.
 *  - Path set, non-prod, failure   -> warn and continue on env/dev fallback.
 */
export async function loadSecretsFromSsm(
  fetchParameters: ParameterFetcher = fetchAllParameters,
): Promise<void> {
  const path = process.env.MINISTER_SECRETS_SSM_PATH?.trim();
  if (!path) return;

  let params: Parameter[];
  try {
    params = await fetchParameters(path);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (isProd()) {
      throw new Error(
        `Failed to load secrets from SSM path "${path}": ${message}. ` +
          "Refusing to boot (production fail-closed).",
      );
    }
    console.warn(
      `[secrets] SSM load from "${path}" failed; continuing on env/dev fallback (non-prod): ${message}`,
    );
    return;
  }

  const prefix = path.endsWith("/") ? path : `${path}/`;
  let injected = 0;
  for (const param of params) {
    if (!param.Name || param.Value === undefined) continue;
    const name = varNameFrom(param.Name, prefix);
    if (!name) continue;
    // Env override wins: only fill what is unset or empty.
    const existing = process.env[name];
    if (existing === undefined || existing === "") {
      process.env[name] = param.Value;
      injected += 1;
    }
  }

  if (isProd()) {
    const missing = REQUIRED_IN_PROD.filter((key) => !process.env[key]);
    if (missing.length > 0) {
      throw new Error(
        `SSM load from "${path}" is missing required secret(s): ${missing.join(", ")}. ` +
          "Refusing to boot (production fail-closed).",
      );
    }
  }

  console.info(`[secrets] loaded ${injected} secret(s) from SSM path "${path}".`);
}

// "/minister/prod/AUTH_SECRET" (+ prefix "/minister/prod/") -> "AUTH_SECRET".
// Recursive GetParametersByPath returns fully-qualified names; fall back to the
// last path segment if the prefix somehow does not match.
function varNameFrom(fullName: string, prefix: string): string {
  const stripped = fullName.startsWith(prefix) ? fullName.slice(prefix.length) : fullName;
  const lastSlash = stripped.lastIndexOf("/");
  return lastSlash >= 0 ? stripped.slice(lastSlash + 1) : stripped;
}

async function fetchAllParameters(path: string): Promise<Parameter[]> {
  const client = new SSMClient({ region: process.env.AWS_REGION });
  const out: Parameter[] = [];
  let nextToken: string | undefined;
  do {
    const res = await client.send(
      new GetParametersByPathCommand({
        Path: path,
        Recursive: true,
        WithDecryption: true,
        NextToken: nextToken,
      }),
    );
    if (res.Parameters) out.push(...res.Parameters);
    nextToken = res.NextToken;
  } while (nextToken);
  return out;
}
