import type { Prisma } from "@/generated/prisma";
import { prisma } from "@/lib/prisma";

// The subset of the client audit() needs. Both the global `prisma` client and an
// interactive-transaction client (`Prisma.TransactionClient`) satisfy it, so a
// caller can write the audit row INSIDE its own transaction (making the mutation
// and its audit atomic — a config change can never commit unlogged).
type AuditClient = Pick<Prisma.TransactionClient, "auditLog">;

// Append an audit log entry. Do NOT pass anything sensitive — raw VC
// JWTs, magic-link tokens, plugin step data, PKCE verifiers all stay
// out of the metadata blob (per CLAUDE.md's security model).
//
// Pass `client` (a transaction client) to enroll the audit write in an ongoing
// transaction; it defaults to the global prisma client (its own write).
export async function audit(
  userId: string | null,
  action: string,
  metadata: Record<string, unknown> = {},
  client: AuditClient = prisma,
): Promise<void> {
  await client.auditLog.create({
    data: {
      userId,
      action,
      metadata: metadata as Prisma.InputJsonValue,
    },
  });
}
