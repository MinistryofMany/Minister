import type { Session } from "next-auth";
import type { z } from "zod";

import { requireAdmin } from "@/lib/session";

// Higher-order wrapper shared by every admin server action. It collapses
// the preamble those actions all repeated — admin gate, input parse,
// uniform error extraction — into one place so each action body only
// holds its own logic, audit, and revalidatePath calls.
//
// Authz channel decision: requireAdmin() THROWS on a non-admin / stale /
// banned caller, but admin actions advertise a `{ ok: false }` failure
// contract. We pick the return channel and apply it uniformly here: the
// wrapper catches the authz throw and turns it into
// `{ ok: false, error: "Not authorized" }`, so the contract every client
// caller sees is honest (they all branch on `!result.ok`). The throw is
// never allowed to escape to the client as an unhandled server error.
//
// Error-extraction policy is likewise unified: a Zod failure surfaces the
// first issue's message (falling back to "Invalid input"), replacing the
// two inconsistent styles the actions had before.
export function adminAction<Schema extends z.ZodTypeAny, Result extends { ok: boolean }>(
  schema: Schema,
  handler: (args: { session: Session; input: z.infer<Schema> }) => Promise<Result>,
): (input: z.infer<Schema>) => Promise<Result | { ok: false; error: string }> {
  return async (input) => {
    let session: Session;
    try {
      session = await requireAdmin();
    } catch {
      return { ok: false, error: "Not authorized" };
    }

    const parsed = schema.safeParse(input);
    if (!parsed.success) {
      return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid input" };
    }

    return handler({ session, input: parsed.data });
  };
}
