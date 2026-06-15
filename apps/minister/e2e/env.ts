import { fileURLToPath } from "node:url";
import path from "node:path";

// Shared constants between playwright.config.ts (which boots the dev
// server with this env) and the specs/helpers (which read it back).

const here = path.dirname(fileURLToPath(import.meta.url));

export const E2E_PORT = 3901;
export const BASE_URL = `http://localhost:${E2E_PORT}`;

// Dedicated database on the compose postgres (host port 5433) so e2e
// runs never touch dev data. global-setup pushes the schema and wipes
// every table.
export const E2E_DATABASE_URL =
  process.env.E2E_DATABASE_URL ??
  "postgresql://minister:minister@localhost:5433/minister_e2e?schema=public";

export const E2E_AUTH_SECRET = "e2e-only-secret-0123456789abcdef0123456789abcdef";

export const ARTIFACTS_DIR = path.join(here, ".artifacts");
export const MAIL_FILE = path.join(ARTIFACTS_DIR, "mail.jsonl");

export const STORAGE = {
  user: path.join(here, ".auth", "user.json"),
  admin: path.join(here, ".auth", "admin.json"),
};

export const USER_EMAIL = "user@e2e.test";
export const ADMIN_EMAIL = "admin@e2e.test";
