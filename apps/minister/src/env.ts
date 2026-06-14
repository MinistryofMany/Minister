import { z } from "zod";

// Validate env at module load. Bad config should crash the server, not
// surface as a 500 deep inside a request handler.

const serverSchema = z.object({
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
  // Different RPs see different `sub`s for the same user.
  OIDC_PAIRWISE_SECRET: z.string().min(32).optional(),

  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
});

const env = serverSchema.parse(process.env);

export { env };
