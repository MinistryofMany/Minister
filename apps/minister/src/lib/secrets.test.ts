import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Parameter } from "@aws-sdk/client-ssm";

import { loadSecretsFromSsm } from "./secrets";

const PATH = "/minister/prod";

function params(entries: Record<string, string>): Parameter[] {
  return Object.entries(entries).map(([name, value]) => ({
    Name: `${PATH}/${name}`,
    Value: value,
  }));
}

// A full set of the required-in-prod secrets, so the fail-closed check passes
// unless a test deliberately omits one.
const REQUIRED = {
  AUTH_SECRET: "auth-secret-val",
  DATABASE_URL: "postgres://db",
  OIDC_PAIRWISE_SECRET: "pairwise-val",
  TOKEN_SIGNING_JWK: '{"kty":"OKP"}',
};

describe("loadSecretsFromSsm", () => {
  const saved = { ...process.env };

  beforeEach(() => {
    vi.restoreAllMocks();
    // Start each test from a clean, deterministic env.
    for (const key of ["MINISTER_SECRETS_SSM_PATH", ...Object.keys(REQUIRED), "SMTP_URL"]) {
      delete process.env[key];
    }
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    process.env = { ...saved };
  });

  it("is a no-op when no SSM path is configured", async () => {
    const fetcher = vi.fn(async () => params(REQUIRED));
    await loadSecretsFromSsm(fetcher);
    expect(fetcher).not.toHaveBeenCalled();
    expect(process.env.AUTH_SECRET).toBeUndefined();
  });

  it("injects fetched params into process.env", async () => {
    process.env.MINISTER_SECRETS_SSM_PATH = PATH;
    await loadSecretsFromSsm(async () => params({ ...REQUIRED, SMTP_URL: "smtp://x" }));
    expect(process.env.AUTH_SECRET).toBe("auth-secret-val");
    expect(process.env.DATABASE_URL).toBe("postgres://db");
    expect(process.env.SMTP_URL).toBe("smtp://x");
  });

  it("does not clobber an existing (non-empty) env value", async () => {
    process.env.MINISTER_SECRETS_SSM_PATH = PATH;
    process.env.AUTH_SECRET = "from-env-wins";
    await loadSecretsFromSsm(async () => params(REQUIRED));
    expect(process.env.AUTH_SECRET).toBe("from-env-wins");
    expect(process.env.DATABASE_URL).toBe("postgres://db");
  });

  it("overrides an empty-string env value", async () => {
    process.env.MINISTER_SECRETS_SSM_PATH = PATH;
    process.env.AUTH_SECRET = "";
    await loadSecretsFromSsm(async () => params(REQUIRED));
    expect(process.env.AUTH_SECRET).toBe("auth-secret-val");
  });

  it("throws in production when the fetch fails (fail-closed)", async () => {
    process.env.MINISTER_SECRETS_SSM_PATH = PATH;
    vi.stubEnv("NODE_ENV", "production");
    await expect(
      loadSecretsFromSsm(async () => {
        throw new Error("AccessDenied");
      }),
    ).rejects.toThrow(/Refusing to boot/);
  });

  it("throws in production when a required secret is missing (fail-closed)", async () => {
    process.env.MINISTER_SECRETS_SSM_PATH = PATH;
    vi.stubEnv("NODE_ENV", "production");
    const { TOKEN_SIGNING_JWK: _omit, ...partial } = REQUIRED;
    await expect(loadSecretsFromSsm(async () => params(partial))).rejects.toThrow(
      /missing required secret\(s\): TOKEN_SIGNING_JWK/,
    );
  });

  it("does not throw in non-prod when the fetch fails", async () => {
    process.env.MINISTER_SECRETS_SSM_PATH = PATH;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await expect(
      loadSecretsFromSsm(async () => {
        throw new Error("network down");
      }),
    ).resolves.toBeUndefined();
    expect(warn).toHaveBeenCalled();
  });

  it("succeeds in production when all required secrets are present", async () => {
    process.env.MINISTER_SECRETS_SSM_PATH = PATH;
    vi.stubEnv("NODE_ENV", "production");
    vi.spyOn(console, "info").mockImplementation(() => {});
    await expect(loadSecretsFromSsm(async () => params(REQUIRED))).resolves.toBeUndefined();
    expect(process.env.OIDC_PAIRWISE_SECRET).toBe("pairwise-val");
  });
});
