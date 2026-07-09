"use server";

import { randomBytes } from "node:crypto";

import { revalidatePath } from "next/cache";

import { audit } from "@/lib/audit";
import { MAX_AVATAR_BYTES, validateAvatarBytes } from "@/lib/avatar-image";
import { buildUploadedAvatarUrl } from "@/lib/avatar-url";
import { gravatarUrl } from "@/lib/gravatar";
import { oidcIssuerUrl } from "@/lib/oidc-config";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";
import { normalizeProfileEditorInput, type ProfileEditorInput } from "@/server/profile-validation";

// Next.js requires every export of a "use server" file to be an async
// function, so the pure validator (and its type), the image magic-byte sniffer,
// the serve-URL builder, and the Gravatar helper all live in plain modules and
// are only imported here, not re-exported.

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
  //   - uploaded      -> KEEP the existing serve-route avatarUrl untouched (this
  //                      path only edits the display name); a NEW photo goes
  //                      through uploadAvatarAction. If no upload actually
  //                      exists, fall back to deterministic.
  //
  // For every non-`uploaded` outcome the user is no longer using an uploaded
  // photo, so we DELETE any stored UserAvatar blob in the same write — the bytea
  // must never outlive the avatarUrl that pointed at it.
  if (avatar.kind === "uploaded") {
    const existing = await prisma.userAvatar.findUnique({
      where: { userId },
      select: { userId: true },
    });
    if (existing) {
      // Keep the current uploaded avatar (avatarUrl already points at it); only
      // the display name may have changed.
      await prisma.user.update({ where: { id: userId }, data: { displayName } });
      await audit(userId, "profile.updated", {
        name: displayName !== null,
        avatarKind: "uploaded",
      });
      revalidatePath("/settings");
      revalidatePath("/profile");
      return { ok: true };
    }
    // Nothing uploaded to keep — behave as the deterministic default.
    await prisma.user.update({ where: { id: userId }, data: { displayName, avatarUrl: null } });
    await audit(userId, "profile.updated", {
      name: displayName !== null,
      avatarKind: "deterministic",
    });
    revalidatePath("/settings");
    revalidatePath("/profile");
    return { ok: true };
  }

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

  // Update the profile and drop any now-orphaned uploaded blob atomically.
  // deleteMany (not delete) is a no-op when the user never uploaded one, so it
  // never throws a missing-row error.
  await prisma.$transaction([
    prisma.user.update({ where: { id: userId }, data: { displayName, avatarUrl } }),
    prisma.userAvatar.deleteMany({ where: { userId } }),
  ]);

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

// Handle a PNG/JPEG/WebP avatar upload. Gated behind the current session — a
// user edits only their OWN avatar. The whole trust boundary for the bytes is
// validateAvatarBytes (size cap + magic-byte sniff; SVG and every non-raster
// type rejected). We store the validated bytes VERBATIM (no re-encode, no new
// deps) plus the SNIFFED content type into UserAvatar, then point avatarUrl at
// the internal serve route with a cache-busting version so the existing
// avatarUrl-inference treats this user as "uploaded" and the OIDC `picture`
// claim discloses this absolute URL exactly like the gravatar/url cases.
export async function uploadAvatarAction(
  formData: FormData,
): Promise<{ ok: true } | { error: string }> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    throw new Error("Not signed in");
  }
  const userId = session.user.id;

  // Reuse the editor's display-name normalization/validation (length, control
  // chars). The avatar tag is irrelevant here — we only want the name back.
  const displayNameRaw = formData.get("displayName");
  let displayName: string | null;
  try {
    const normalized = normalizeProfileEditorInput({
      displayName: typeof displayNameRaw === "string" ? displayNameRaw : "",
      avatar: { kind: "uploaded" },
    });
    displayName = normalized.displayName;
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Invalid profile value" };
  }

  const file = formData.get("file");
  if (!(file instanceof File) || file.size === 0) {
    return { error: "Choose an image to upload." };
  }
  // Check the declared size before reading the body into memory, so an
  // oversize upload is rejected without buffering megabytes.
  if (file.size > MAX_AVATAR_BYTES) {
    return { error: "That image is over 512 KB. Pick a smaller one." };
  }

  const bytes = new Uint8Array(await file.arrayBuffer());
  const result = validateAvatarBytes(bytes, file.type);
  if (!result.ok) {
    return { error: result.error };
  }

  // The persisted, later-DISCLOSED URL must be built from a server-controlled
  // canonical origin (AUTH_URL), never a client Host header — otherwise an
  // upload with a forged Host could point the stored avatarUrl (and the OIDC
  // picture claim) at an attacker host.
  let origin: string;
  try {
    origin = oidcIssuerUrl();
  } catch {
    return { error: "Uploads are unavailable right now. Try again later." };
  }

  // An OPAQUE, unguessable public handle for this blob — NEVER the userId. The
  // serve route (and the disclosed `picture` claim) key on this instead of the
  // account id, so an RP granted the avatar claim can't recover the global
  // Minister userId and correlate the user across RPs (which would defeat the
  // pairwise `sub`). Only consumed on the create branch; a replace keeps the
  // existing publicId (upsert.update leaves it untouched), so the URL stays
  // stable across re-uploads while `?v=` busts caches.
  const publicId = randomBytes(16).toString("base64url");

  // Persist the blob and repoint avatarUrl in ONE interactive transaction: the
  // blob is publicly served the instant it exists, so a mid-action failure
  // between the two writes must never leave a servable blob behind a stale
  // avatarUrl (or a fresh avatarUrl pointing at no blob). The callback form is
  // required because the URL needs the upserted publicId + updatedAt.
  await prisma.$transaction(async (tx) => {
    const saved = await tx.userAvatar.upsert({
      where: { userId },
      create: { userId, publicId, data: Buffer.from(bytes), contentType: result.contentType },
      update: { data: Buffer.from(bytes), contentType: result.contentType },
      select: { publicId: true, updatedAt: true },
    });
    const url = buildUploadedAvatarUrl(origin, saved.publicId, saved.updatedAt.getTime());
    await tx.user.update({ where: { id: userId }, data: { displayName, avatarUrl: url } });
  });

  // Non-sensitive fields only: the content type is not user data, and the URL
  // is an internal serve route (no email hash, unlike Gravatar).
  await audit(userId, "profile.updated", {
    name: displayName !== null,
    avatarKind: "uploaded",
    contentType: result.contentType,
  });

  revalidatePath("/settings");
  revalidatePath("/profile");

  return { ok: true };
}
