"use server";

import { revalidatePath } from "next/cache";

import { audit } from "@/lib/audit";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";
import { normalizeProfileInput, type UpdateProfileInput } from "@/server/profile-validation";

// Next.js requires every export of a "use server" file to be an async
// function, so the pure validator (and its type) live in profile-validation.ts
// and are only imported here, not re-exported.

export async function updateProfile(
  input: UpdateProfileInput,
): Promise<{ ok: true } | { error: string }> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    throw new Error("Not signed in");
  }

  // Validation failures are RETURNED as { error } rather than thrown: Next.js
  // redacts thrown server-action messages in production, so a thrown
  // "Avatar URL must use https:" would reach the user as an opaque digest.
  let displayName: string | null;
  let avatarUrl: string | null;
  try {
    const normalized = normalizeProfileInput(input);
    displayName = normalized.displayName;
    avatarUrl = normalized.avatarUrl;
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Invalid profile value" };
  }

  await prisma.user.update({
    where: { id: session.user.id },
    data: { displayName, avatarUrl },
  });

  // Booleans only — never the raw curated values — per the audit log's
  // no-sensitive-payload rule.
  await audit(session.user.id, "profile.updated", {
    name: displayName !== null,
    avatar: avatarUrl !== null,
  });

  revalidatePath("/settings");
  revalidatePath("/profile");

  return { ok: true };
}
