import { randomBytes } from "node:crypto";

import { hash as argonHash, verify as argonVerify } from "@node-rs/argon2";

import { prisma } from "@/lib/prisma";

// OWASP-recommended argon2id parameters for password-equivalent secrets.
// memoryCost is in KB; 19 MB / 2 iterations / 1 parallelism is the
// OWASP cheat sheet baseline.
const ARGON_PARAMS = {
  memoryCost: 19 * 1024,
  timeCost: 2,
  parallelism: 1,
} as const;

export async function hashClientSecret(plaintext: string): Promise<string> {
  return argonHash(plaintext, ARGON_PARAMS);
}

export async function verifyClientSecret(plaintext: string, encoded: string): Promise<boolean> {
  try {
    return await argonVerify(encoded, plaintext);
  } catch {
    return false;
  }
}

// 24 bytes random → 32-character base64url client_id / secret. Plenty
// of entropy and URL-safe so it can land in Authorization headers
// without re-encoding.
export function generateClientId(): string {
  return `tc_${randomBytes(18).toString("base64url")}`;
}

export function generateClientSecret(): string {
  return randomBytes(32).toString("base64url");
}

export async function findClient(clientId: string) {
  return prisma.oidcClient.findUnique({ where: { clientId } });
}

// Constant-time-equivalent redirect URI check: exact string match per
// RFC 6749 §3.1.2.2 (no substring, no relaxed-path).
export function isRegisteredRedirectUri(
  client: { redirectUris: string[] },
  candidate: string,
): boolean {
  return client.redirectUris.includes(candidate);
}
