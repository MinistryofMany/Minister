#!/usr/bin/env tsx
// Admin CLI: create-or-update an OIDC client.
//
// Two modes:
//   1. Random — generate client_id and client_secret. Prints the
//      plaintext secret once. Re-running creates a NEW client.
//   2. Deterministic — pass --client-id and --client-secret. Upserts
//      by clientId, so docker-compose can run this every boot to keep
//      the demo client wired up without growing duplicate rows.
//
// Usage:
//   pnpm --filter @minister/app oidc:seed-client \
//     --name "Demo client" \
//     --redirect-uri http://localhost:3100/api/auth/callback/minister \
//     --scope openid --scope profile --scope badge:email-domain \
//     [--client-id demo_client --client-secret <secret>] \
//     [--public]
//
// Set DATABASE_URL the same way the app does.

import { parseArgs } from "node:util";

import { PrismaClient } from "../src/generated/prisma/index.js";
import { validateClientId } from "../src/lib/oidc-client-admin.js";
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
    "client-id": { type: "string" },
    "client-secret": { type: "string" },
    public: { type: "boolean" },
  },
});

const name = values.name;
const redirectUris = values["redirect-uri"] ?? [];
const scopes = values.scope ?? ["openid"];
const ownerUserId = values["owner-user-id"];
const fixedClientId = values["client-id"];
const fixedClientSecret = values["client-secret"];
const isPublic = Boolean(values.public);

if (!name || redirectUris.length === 0) {
  console.error("Required: --name <string> and at least one --redirect-uri <url>");
  process.exit(2);
}
if (fixedClientSecret && !fixedClientId) {
  console.error("--client-secret requires --client-id");
  process.exit(2);
}
// Charset guard on the operator-chosen id (build plan §2.1): a delimiter inside
// a clientId would collide the legacy colon-joined pairwise-HMAC inputs. Random
// ids from generateClientId always pass; only --client-id can smuggle one in.
if (fixedClientId) {
  const check = validateClientId(fixedClientId);
  if (!check.ok) {
    console.error(check.error);
    process.exit(2);
  }
}

const prisma = new PrismaClient();

try {
  const clientId = fixedClientId ?? generateClientId();
  // Whether to display the plaintext secret post-run. Only do this
  // when WE generated it — if the operator passed --client-secret they
  // already have it.
  const generatedSecret = isPublic ? null : fixedClientSecret ? null : generateClientSecret();
  const effectiveSecret = isPublic ? null : (fixedClientSecret ?? generatedSecret);
  const clientSecretHash = effectiveSecret ? await hashClientSecret(effectiveSecret) : null;

  const data = {
    clientId,
    clientSecretHash,
    name,
    redirectUris,
    allowedScopes: scopes,
    ownerUserId: ownerUserId ?? null,
  };

  const upserted = await prisma.oidcClient.upsert({
    where: { clientId },
    create: data,
    update: {
      // Don't overwrite ownerUserId on re-runs — operator may have set
      // it after the initial seed.
      clientSecretHash: data.clientSecretHash,
      name: data.name,
      redirectUris: data.redirectUris,
      allowedScopes: data.allowedScopes,
    },
    select: { createdAt: true },
  });

  // Detect create vs update by comparing createdAt to "now within a
  // second" — Prisma doesn't return a flag for upsert outcome.
  const justCreated = Date.now() - upserted.createdAt.getTime() < 2000;
  console.log(`\nOIDC client ${justCreated ? "created" : "updated"}.\n`);
  console.log(`  name           ${name}`);
  console.log(`  client_id      ${clientId}`);
  if (generatedSecret) {
    console.log(`  client_secret  ${generatedSecret}`);
    console.log("\n  ↑ store this secret now; it cannot be recovered.\n");
  } else if (isPublic) {
    console.log("  public client  (no secret; PKCE required)");
  } else {
    console.log("  client_secret  (unchanged from caller-provided value)");
  }
  console.log(`  redirect_uris  ${redirectUris.join(", ")}`);
  console.log(`  scopes         ${scopes.join(" ")}`);
} catch (err) {
  console.error("Failed to seed client:", err);
  process.exit(1);
} finally {
  await prisma.$disconnect();
}
