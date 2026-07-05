import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { PrismaClient } from "../src/generated/prisma/index.js";
import { ARTIFACTS_DIR, E2E_DATABASE_URL, MAIL_FILE, STORAGE } from "./env";

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// Push the schema into the dedicated e2e database (creates it on first
// run), then wipe every table so each run starts from zero. Storage
// states from the previous run die with their User rows — the setup
// project re-mints them.
export default async function globalSetup(): Promise<void> {
  execFileSync(
    path.join(appDir, "node_modules", ".bin", "prisma"),
    ["db", "push", "--skip-generate"],
    {
      cwd: appDir,
      env: { ...process.env, DATABASE_URL: E2E_DATABASE_URL },
      stdio: "pipe",
    },
  );

  const prisma = new PrismaClient({ datasourceUrl: E2E_DATABASE_URL });
  try {
    // Children first where cascades don't already cover it.
    await prisma.shareLinkView.deleteMany();
    await prisma.shareLink.deleteMany();
    await prisma.inviteRedemption.deleteMany();
    await prisma.inviteCode.deleteMany();
    await prisma.badge.deleteMany();
    await prisma.eligibility.deleteMany();
    // The Sybil-dedup ledger + drift cache are NOT FK-linked to Badge/User
    // (nullifierRef is an opaque string, no cascade), so they must be wiped
    // explicitly or anchors leak across runs and issuance is refused `taken`.
    await prisma.nullifierRpCheck.deleteMany();
    await prisma.nullifierEntry.deleteMany();
    await prisma.oidcAccessToken.deleteMany();
    await prisma.oidcAuthorizationCode.deleteMany();
    await prisma.oidcClient.deleteMany();
    await prisma.wizardSession.deleteMany();
    await prisma.auditLog.deleteMany();
    await prisma.authenticator.deleteMany();
    await prisma.session.deleteMany();
    await prisma.account.deleteMany();
    await prisma.verificationToken.deleteMany();
    await prisma.user.deleteMany();
  } finally {
    await prisma.$disconnect();
  }

  mkdirSync(ARTIFACTS_DIR, { recursive: true });
  mkdirSync(path.dirname(STORAGE.user), { recursive: true });
  writeFileSync(MAIL_FILE, "");
}
