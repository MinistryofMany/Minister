#!/usr/bin/env tsx
// Admin CLI: create an OIDC client. Prints the generated client_secret
// once — there is no way to recover it after this point. Re-run to
// rotate (creates a new client; the old row stays unless you delete
// it).
//
// Usage:
//   pnpm --filter @tessera/app oidc:seed-client \
//     --name "Demo client" \
//     --redirect-uri http://localhost:3100/api/auth/callback/tessera \
//     --scope openid --scope profile --scope badge:email-domain
//
// Set DATABASE_URL the same way the app does (e.g. via .env or the
// docker-compose service env). The script reads it via process.env.

import { parseArgs } from "node:util";

import { PrismaClient } from "../src/generated/prisma/index.js";
import {
  generateClientId,
  generateClientSecret,
  hashClientSecret,
} from "../src/lib/oidc-clients.js";

const { values } = parseArgs({
  options: {
    name: { type: "string" },
    "redirect-uri": { type: "string", multiple: true },
    scope: { type: "string", multiple: true },
    "owner-user-id": { type: "string" },
    public: { type: "boolean" },
  },
});

const name = values.name;
const redirectUris = values["redirect-uri"] ?? [];
const scopes = values.scope ?? ["openid"];
const ownerUserId = values["owner-user-id"];
const isPublic = Boolean(values.public);

if (!name || redirectUris.length === 0) {
  console.error(
    "Required: --name <string> and at least one --redirect-uri <url>",
  );
  process.exit(2);
}

const prisma = new PrismaClient();

try {
  const clientId = generateClientId();
  const plainSecret = isPublic ? null : generateClientSecret();
  const clientSecretHash = plainSecret
    ? await hashClientSecret(plainSecret)
    : null;

  await prisma.oidcClient.create({
    data: {
      clientId,
      clientSecretHash,
      name,
      redirectUris,
      allowedScopes: scopes,
      ownerUserId: ownerUserId ?? null,
    },
  });

  console.log("\nOIDC client created.\n");
  console.log(`  name           ${name}`);
  console.log(`  client_id      ${clientId}`);
  if (plainSecret) {
    console.log(`  client_secret  ${plainSecret}`);
    console.log("\n  ↑ store this secret now; it cannot be recovered.\n");
  } else {
    console.log("  public client  (no secret; PKCE required)");
  }
  console.log(`  redirect_uris  ${redirectUris.join(", ")}`);
  console.log(`  scopes         ${scopes.join(" ")}`);
} catch (err) {
  console.error("Failed to create client:", err);
  process.exit(1);
} finally {
  await prisma.$disconnect();
}
