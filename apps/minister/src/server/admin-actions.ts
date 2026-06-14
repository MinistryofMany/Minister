"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { audit } from "@/lib/audit";
import { generateInviteCode, normalizeInviteCode } from "@/lib/invite-codes";
import {
  parseRedirectUris,
  validateClientScopes,
} from "@/lib/oidc-client-admin";
import {
  generateClientId,
  generateClientSecret,
  hashClientSecret,
} from "@/lib/oidc-clients";
import { prisma } from "@/lib/prisma";
import { requireAdmin } from "@/lib/session";

export type AdminActionResult =
  | { ok: true }
  | { ok: false; error: string };

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

const SetBannedInput = z.object({
  userId: z.string().cuid(),
  banned: z.boolean(),
});

export async function setUserBanned(
  input: z.infer<typeof SetBannedInput>,
): Promise<AdminActionResult> {
  const session = await requireAdmin();
  const parsed = SetBannedInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: "Invalid input" };
  const { userId, banned } = parsed.data;

  if (userId === session.user.id) {
    return { ok: false, error: "You can't ban yourself" };
  }

  // Admins can't ban other admins — demote first. Keeps a compromised
  // admin account from locking every admin out.
  const result = await prisma.user.updateMany({
    where: { id: userId, isAdmin: false },
    data: banned
      ? // Bumping sessionGeneration kicks the user's live sessions on
        // their next request rather than waiting out the 24h JWT TTL.
        { isBanned: true, sessionGeneration: { increment: 1 } }
      : { isBanned: false },
  });
  if (result.count === 0) {
    return { ok: false, error: "User not found (or is an admin)" };
  }

  await audit(session.user.id, banned ? "admin.user_banned" : "admin.user_unbanned", {
    targetUserId: userId,
  });

  revalidatePath("/admin/users");
  return { ok: true };
}

const SetAdminInput = z.object({
  userId: z.string().cuid(),
  admin: z.boolean(),
});

export async function setUserAdmin(
  input: z.infer<typeof SetAdminInput>,
): Promise<AdminActionResult> {
  const session = await requireAdmin();
  const parsed = SetAdminInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: "Invalid input" };
  const { userId, admin } = parsed.data;

  // No self-service on your own flag — prevents demoting yourself into
  // a zero-admin lockout. Another admin (or make-admin.ts) can.
  if (userId === session.user.id) {
    return { ok: false, error: "You can't change your own admin status" };
  }

  // Promoting a banned user would be contradictory; unban first.
  const result = await prisma.user.updateMany({
    where: admin ? { id: userId, isBanned: false } : { id: userId },
    data: { isAdmin: admin },
  });
  if (result.count === 0) {
    return { ok: false, error: "User not found (or is banned)" };
  }

  // Same action names make-admin.ts uses, so the audit trail reads
  // uniformly regardless of which path granted it.
  await audit(session.user.id, admin ? "admin.granted" : "admin.revoked", {
    targetUserId: userId,
    via: "/admin/users",
  });

  revalidatePath("/admin/users");
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Invite codes
// ---------------------------------------------------------------------------

const MAX_INVITE_TTL_DAYS = 365;

const CreateInviteCodeInput = z.object({
  label: z.string().trim().min(1, "Label is required").max(80),
  // Empty string = auto-generate.
  customCode: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9-]{4,64}$/, "Codes are 4-64 letters, digits, or hyphens")
    .optional()
    .or(z.literal("").transform(() => undefined)),
  // 0 = unlimited.
  usesTotal: z.coerce.number().int().min(0).max(100_000).default(1),
  // Unset = never expires.
  ttlDays: z.coerce
    .number()
    .int()
    .min(1)
    .max(MAX_INVITE_TTL_DAYS)
    .optional()
    .or(z.literal("").transform(() => undefined)),
});

export type CreateInviteCodeResult =
  | { ok: true; code: string }
  | { ok: false; error: string };

export async function createInviteCode(
  input: z.infer<typeof CreateInviteCodeInput>,
): Promise<CreateInviteCodeResult> {
  const session = await requireAdmin();
  const parsed = CreateInviteCodeInput.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      error: parsed.error.issues[0]?.message ?? "Invalid input",
    };
  }
  const { label, customCode, usesTotal, ttlDays } = parsed.data;

  const code = normalizeInviteCode(customCode ?? generateInviteCode());
  const expiresAt = ttlDays
    ? new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000)
    : null;

  const existing = await prisma.inviteCode.findUnique({ where: { code } });
  if (existing) {
    return { ok: false, error: "That code already exists" };
  }

  const row = await prisma.inviteCode.create({
    data: {
      code,
      label,
      usesTotal,
      usesRemaining: usesTotal,
      expiresAt,
      createdBy: session.user.id,
    },
    select: { id: true },
  });

  // The code itself stays out of the audit log — same policy as VC
  // claims and plugin redemption metadata.
  await audit(session.user.id, "admin.invite_code.created", {
    inviteCodeId: row.id,
    label,
    usesTotal,
    expiresAt: expiresAt?.toISOString() ?? null,
  });

  revalidatePath("/admin/invite-codes");
  return { ok: true, code };
}

const RevokeInviteCodeInput = z.object({
  inviteCodeId: z.string().cuid(),
});

export async function revokeInviteCode(
  input: z.infer<typeof RevokeInviteCodeInput>,
): Promise<AdminActionResult> {
  const session = await requireAdmin();
  const parsed = RevokeInviteCodeInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: "Invalid input" };

  const result = await prisma.inviteCode.updateMany({
    where: { id: parsed.data.inviteCodeId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  if (result.count === 0) {
    return { ok: false, error: "Code not found or already revoked" };
  }

  await audit(session.user.id, "admin.invite_code.revoked", {
    inviteCodeId: parsed.data.inviteCodeId,
  });

  revalidatePath("/admin/invite-codes");
  return { ok: true };
}

// ---------------------------------------------------------------------------
// OIDC clients
// ---------------------------------------------------------------------------

const OidcClientFields = z.object({
  name: z.string().trim().min(1, "Name is required").max(80),
  // Textarea contents — one URI per line; parsed/validated by
  // parseRedirectUris.
  redirectUris: z.string(),
  scopes: z.array(z.string()).min(1, "Pick at least one scope"),
});

const CreateOidcClientInput = OidcClientFields.extend({
  // Public clients (SPAs, native apps) get no secret — PKCE only.
  publicClient: z.boolean().default(false),
});

export type CreateOidcClientResult =
  | { ok: true; clientId: string; clientSecret: string | null }
  | { ok: false; error: string };

export async function createOidcClient(
  input: z.infer<typeof CreateOidcClientInput>,
): Promise<CreateOidcClientResult> {
  const session = await requireAdmin();
  const parsed = CreateOidcClientInput.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      error: parsed.error.issues[0]?.message ?? "Invalid input",
    };
  }

  const uris = parseRedirectUris(parsed.data.redirectUris);
  if (!uris.ok) return { ok: false, error: uris.error };
  const scopes = validateClientScopes(parsed.data.scopes);
  if (!scopes.ok) return { ok: false, error: scopes.error };

  const clientId = generateClientId();
  const clientSecret = parsed.data.publicClient ? null : generateClientSecret();

  const row = await prisma.oidcClient.create({
    data: {
      clientId,
      clientSecretHash: clientSecret
        ? await hashClientSecret(clientSecret)
        : null,
      name: parsed.data.name,
      redirectUris: uris.uris,
      allowedScopes: scopes.scopes,
      ownerUserId: session.user.id,
    },
    select: { id: true },
  });

  await audit(session.user.id, "admin.oidc_client.created", {
    oidcClientId: row.id,
    clientId,
    name: parsed.data.name,
    publicClient: parsed.data.publicClient,
    redirectUris: uris.uris,
    scopes: scopes.scopes,
  });

  revalidatePath("/admin/oidc-clients");
  // The plaintext secret exists only in this response — it's hashed at
  // rest, so the UI must show it now or never.
  return { ok: true, clientId, clientSecret };
}

const UpdateOidcClientInput = OidcClientFields.extend({
  id: z.string().cuid(),
});

export async function updateOidcClient(
  input: z.infer<typeof UpdateOidcClientInput>,
): Promise<AdminActionResult> {
  const session = await requireAdmin();
  const parsed = UpdateOidcClientInput.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      error: parsed.error.issues[0]?.message ?? "Invalid input",
    };
  }

  const uris = parseRedirectUris(parsed.data.redirectUris);
  if (!uris.ok) return { ok: false, error: uris.error };
  const scopes = validateClientScopes(parsed.data.scopes);
  if (!scopes.ok) return { ok: false, error: scopes.error };

  const result = await prisma.oidcClient.updateMany({
    where: { id: parsed.data.id },
    data: {
      name: parsed.data.name,
      redirectUris: uris.uris,
      allowedScopes: scopes.scopes,
    },
  });
  if (result.count === 0) return { ok: false, error: "Client not found" };

  await audit(session.user.id, "admin.oidc_client.updated", {
    oidcClientId: parsed.data.id,
    name: parsed.data.name,
    redirectUris: uris.uris,
    scopes: scopes.scopes,
  });

  revalidatePath("/admin/oidc-clients");
  return { ok: true };
}

const ClientIdInput = z.object({ id: z.string().cuid() });

export type RotateOidcSecretResult =
  | { ok: true; clientSecret: string }
  | { ok: false; error: string };

export async function rotateOidcClientSecret(
  input: z.infer<typeof ClientIdInput>,
): Promise<RotateOidcSecretResult> {
  const session = await requireAdmin();
  const parsed = ClientIdInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: "Invalid input" };

  const client = await prisma.oidcClient.findUnique({
    where: { id: parsed.data.id },
    select: { id: true, clientId: true, clientSecretHash: true },
  });
  if (!client) return { ok: false, error: "Client not found" };
  if (!client.clientSecretHash) {
    return { ok: false, error: "Public clients have no secret to rotate" };
  }

  const clientSecret = generateClientSecret();
  await prisma.oidcClient.update({
    where: { id: client.id },
    data: { clientSecretHash: await hashClientSecret(clientSecret) },
  });

  // The old secret stops working immediately — any RP still configured
  // with it fails at /oidc/token until updated.
  await audit(session.user.id, "admin.oidc_client.secret_rotated", {
    oidcClientId: client.id,
    clientId: client.clientId,
  });

  revalidatePath("/admin/oidc-clients");
  return { ok: true, clientSecret };
}

export async function deleteOidcClient(
  input: z.infer<typeof ClientIdInput>,
): Promise<AdminActionResult> {
  const session = await requireAdmin();
  const parsed = ClientIdInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: "Invalid input" };

  const client = await prisma.oidcClient.findUnique({
    where: { id: parsed.data.id },
    select: { id: true, clientId: true, name: true },
  });
  if (!client) return { ok: false, error: "Client not found" };

  // Outstanding tokens/codes reference the client by clientId string
  // (no FK) — revoke them in the same transaction so a deleted client
  // can't keep calling /oidc/userinfo.
  const [revokedTokens] = await prisma.$transaction([
    prisma.oidcAccessToken.deleteMany({
      where: { clientId: client.clientId },
    }),
    prisma.oidcAuthorizationCode.deleteMany({
      where: { clientId: client.clientId },
    }),
    prisma.oidcClient.delete({ where: { id: client.id } }),
  ]);

  await audit(session.user.id, "admin.oidc_client.deleted", {
    oidcClientId: client.id,
    clientId: client.clientId,
    name: client.name,
    revokedAccessTokens: revokedTokens.count,
  });

  revalidatePath("/admin/oidc-clients");
  return { ok: true };
}
