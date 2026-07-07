"use server";

import { revalidatePath } from "next/cache";

import { audit } from "@/lib/audit";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";
import { normalizeProfileInput } from "@/server/profile-validation";

// Edit the per-relying-party profile persona (OidcProfileOverride) from
// Settings → Connected apps. The disclosure paths (token/userinfo) read this
// row first, per field, falling back to the global curated default. This is
// the "editable after" half of the snapshot-per-app feature; first-consent
// seeding lives in oidc-actions.approveConsent.

interface UpdateRpProfileInput {
  clientId: string;
  displayName: string;
  avatarUrl: string;
}

export async function updateRpProfile(
  input: UpdateRpProfileInput,
): Promise<{ ok: true } | { error: string }> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    throw new Error("Not signed in");
  }
  const userId = session.user.id;

  // A user may only shape a persona for an RP they actually connected to.
  // Without this a crafted clientId would let a user create an override row
  // for an arbitrary client. The grant is the durable per-(user, client)
  // record of a real prior consent. Authz failure stays a throw (not a
  // reachable state via the UI, which only lists connected apps).
  const grant = await prisma.oidcGrant.findUnique({
    where: { userId_clientId: { userId, clientId: input.clientId } },
    select: { clientId: true },
  });
  if (!grant) {
    throw new Error("No connected app with that id");
  }

  // Same validator as the global editor: https-only avatar, length caps,
  // control-char stripping; empty → null (clears the field — under the
  // snapshot-per-app model that means "share nothing for this field with this
  // app"). Validation failures are RETURNED as { error } (not thrown): Next.js
  // redacts thrown server-action messages in prod, so a thrown "must use
  // https:" would surface to the user as an opaque digest.
  let displayName: string | null;
  let avatarUrl: string | null;
  try {
    const normalized = normalizeProfileInput({
      displayName: input.displayName,
      avatarUrl: input.avatarUrl,
    });
    displayName = normalized.displayName;
    avatarUrl = normalized.avatarUrl;
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Invalid profile value" };
  }

  await prisma.oidcProfileOverride.upsert({
    where: { userId_clientId: { userId, clientId: input.clientId } },
    create: { userId, clientId: input.clientId, displayName, avatarUrl },
    update: { displayName, avatarUrl },
  });

  // Booleans only — never the raw persona values — per the audit log's
  // no-sensitive-payload rule.
  await audit(userId, "rp_profile.updated", {
    clientId: input.clientId,
    name: displayName !== null,
    avatar: avatarUrl !== null,
  });

  revalidatePath("/settings/apps");

  return { ok: true };
}
