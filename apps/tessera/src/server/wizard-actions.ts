"use server";

import { headers } from "next/headers";

import { getCurrentSession } from "@/lib/session";
import { startWizard, submitStep } from "@/server/wizard";

async function requireUserId(): Promise<string> {
  const session = await getCurrentSession();
  if (!session?.user?.id) throw new Error("Not signed in");
  return session.user.id;
}

async function getOrigin(): Promise<string> {
  const h = await headers();
  const proto = h.get("x-forwarded-proto") ?? "http";
  const host = h.get("host") ?? "localhost:3000";
  return `${proto}://${host}`;
}

export async function startWizardAction(pluginId: string) {
  const userId = await requireUserId();
  const origin = await getOrigin();
  const { sessionId, state } = await startWizard(pluginId, userId, origin);
  return { sessionId, state };
}

export async function submitStepAction(
  sessionId: string,
  input: unknown,
): Promise<
  | { kind: "continue"; state: import("@tessera/plugin-sdk").WizardState }
  | { kind: "complete"; badgeIds: string[] }
  | { kind: "error"; message: string }
> {
  const userId = await requireUserId();
  const origin = await getOrigin();
  return submitStep(sessionId, userId, origin, input);
}
