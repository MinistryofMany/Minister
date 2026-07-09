"use server";

import { revalidatePath } from "next/cache";

import { audit } from "@/lib/audit";
import { gravatarUrl } from "@/lib/gravatar";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";
import { normalizeProfileEditorInput, type ProfileEditorInput } from "@/server/profile-validation";

// Next.js requires every export of a "use server" file to be an async
// function, so the pure validator (and its type), the SVG generator, and the
// Gravatar helper all live in plain modules and are only imported here, not
// re-exported.

export async function updateProfile(
  input: ProfileEditorInput,
): Promise<{ ok: true } | { error: string }> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    throw new Error("Not signed in");
  }
  const userId = session.user.id;

  // Validation failures are RETURNED as { error } rather than thrown: Next.js
  // redacts thrown server-action messages in production, so a thrown
  // "Avatar URL must use https:" would reach the user as an opaque digest.
  let displayName: string | null;
  let avatar: ReturnType<typeof normalizeProfileEditorInput>["avatar"];
  try {
    const normalized = normalizeProfileEditorInput(input);
    displayName = normalized.displayName;
    avatar = normalized.avatar;
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Invalid profile value" };
  }

  // Resolve the tagged selection to the single stored value (avatarUrl):
  //   - deterministic -> null (the identicon renders from the user id, no URL)
  //   - url           -> the validated https URL, stored verbatim
  //   - gravatar      -> derive ONLY from an email PROVEN on this account. The
  //                      email arrives from the client, so we re-verify it here
  //                      against the UserEmail store; an unproven (or someone
  //                      else's) address can never be turned into a Gravatar URL.
  let avatarUrl: string | null;
  switch (avatar.kind) {
    case "deterministic":
      avatarUrl = null;
      break;
    case "url":
      avatarUrl = avatar.url;
      break;
    case "gravatar": {
      const proven = await prisma.userEmail.findFirst({
        where: { userId, email: avatar.email, verifiedAt: { not: null } },
        select: { id: true },
      });
      if (!proven) {
        return { error: "Verify that email on your account before using its Gravatar." };
      }
      avatarUrl = gravatarUrl(avatar.email);
      break;
    }
  }

  await prisma.user.update({
    where: { id: userId },
    data: { displayName, avatarUrl },
  });

  // Booleans and the non-sensitive avatar KIND only — never the raw curated
  // values, and never the Gravatar URL (it embeds an email hash) — per the
  // audit log's no-sensitive-payload rule.
  await audit(userId, "profile.updated", {
    name: displayName !== null,
    avatarKind: avatar.kind,
  });

  revalidatePath("/settings");
  revalidatePath("/profile");

  return { ok: true };
}
