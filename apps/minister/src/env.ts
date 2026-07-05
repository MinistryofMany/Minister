import { z } from "zod";

// Validate env at module load. Bad config should crash the server, not
// surface as a 500 deep inside a request handler.

const serverSchema = z
  .object({
    DATABASE_URL: z.string().url(),

    AUTH_SECRET: z.string().min(32, "AUTH_SECRET must be at least 32 chars"),
    AUTH_URL: z.string().url().optional(),
    AUTH_TRUST_HOST: z
      .union([z.literal("true"), z.literal("false")])
      .optional()
      .transform((v) => v === "true"),

    // Issuer identity. In dev: minister.local (symbolic — the DID document is
    // only resolvable once we have real DNS + TLS).
    MINISTER_ISSUER_DOMAIN: z.string().default("minister.local"),

    // Secret used to derive pairwise pseudonymous OIDC `sub` values.
    // Different RPs see different `sub`s for the same user. Required unless the
    // pairwise sub is derived in Signet (below); the min-length check is
    // applied in the refine so an unset value surfaces the required-error, not
    // a length-error.
    OIDC_PAIRWISE_SECRET: z.string().optional(),

    // Selects the pairwise-sub derivation backend. Dead until Phase 7 wires the
    // Signet cutover; declared now so the required-secret rule below can
    // reference it without a later contradiction — the Phase 7c-ii SSM deletion
    // of OIDC_PAIRWISE_SECRET must not trip a hard-required env once the pairwise
    // sub is derived inside Signet.
    MINISTER_SUB_BACKEND: z.string().optional(),

    // Sybil-dedup nullifier backend (crypto-core Phase 3). `interim` keeps the
    // in-Minister HMAC ledger; `signet` routes stage-1 through Signet's VOPRF
    // surface and requires the full MINISTER_SIGNET_* set below (checked in
    // the refine so a half-configured signet backend fails at boot, never as
    // a 500 inside a wizard step).
    MINISTER_NULLIFIER_BACKEND: z.enum(["interim", "signet"]).default("interim"),
    // Signet base URL, e.g. https://signet:8443 (mTLS).
    MINISTER_SIGNET_URL: z.string().url().optional(),
    // mTLS material: inline PEM or a file path (resolved in the backend).
    MINISTER_SIGNET_CLIENT_CERT: z.string().optional(),
    MINISTER_SIGNET_CLIENT_KEY: z.string().optional(),
    MINISTER_SIGNET_CA_CERT: z.string().optional(),
    // The pinned VOPRF public key pkS printed by `signet init-service-keys`
    // (base64url no padding, 43 chars). The backend fetch-and-verifies it
    // against /prf/public-key and DLEQ-verifies every evaluation against it,
    // fail-closed — the ISSUER_KMS_PUBLIC_JWK pattern.
    MINISTER_SIGNET_DEDUP_PUBKEY: z
      .string()
      .regex(/^[A-Za-z0-9_-]{43}$/, "must be base64url(32 bytes), no padding")
      .optional(),

    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  })
  .superRefine((val, ctx) => {
    // The signet nullifier backend is unusable half-configured: require the
    // full transport + pin set at boot.
    if (val.MINISTER_NULLIFIER_BACKEND === "signet") {
      for (const key of [
        "MINISTER_SIGNET_URL",
        "MINISTER_SIGNET_CLIENT_CERT",
        "MINISTER_SIGNET_CLIENT_KEY",
        "MINISTER_SIGNET_CA_CERT",
        "MINISTER_SIGNET_DEDUP_PUBKEY",
      ] as const) {
        if (!val[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required when MINISTER_NULLIFIER_BACKEND=signet`,
          });
        }
      }
    }
    // OIDC_PAIRWISE_SECRET is REQUIRED unless the pairwise sub is derived in
    // Signet (which holds the imported secret). Boot fails fast here rather than
    // deriving under an absent/wrong key deep inside a token mint.
    if (val.MINISTER_SUB_BACKEND === "signet") return;
    if (!val.OIDC_PAIRWISE_SECRET) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["OIDC_PAIRWISE_SECRET"],
        message: "OIDC_PAIRWISE_SECRET is required (unless MINISTER_SUB_BACKEND=signet)",
      });
    } else if (val.OIDC_PAIRWISE_SECRET.length < 32) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["OIDC_PAIRWISE_SECRET"],
        message: "OIDC_PAIRWISE_SECRET must be at least 32 chars",
      });
    }
  });

const env = serverSchema.parse(process.env);

export { env };
