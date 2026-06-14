import type { Prisma } from "@/generated/prisma";
import { prisma } from "@/lib/prisma";

// Append an audit log entry. Do NOT pass anything sensitive — raw VC
// JWTs, magic-link tokens, plugin step data, PKCE verifiers all stay
// out of the metadata blob (per CLAUDE.md's security model).
export async function audit(
  userId: string | null,
  action: string,
  metadata: Record<string, unknown> = {},
): Promise<void> {
  await prisma.auditLog.create({
    data: {
      userId,
      action,
      metadata: metadata as Prisma.InputJsonValue,
    },
  });
}
