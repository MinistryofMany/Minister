import { redirect } from "next/navigation";

import { getCurrentSession } from "@/lib/session";
import { listCredentials } from "@/server/credential-actions";

import { CredentialsManager } from "./credentials-manager";

export default async function CredentialsPage() {
  const session = await getCurrentSession();
  if (!session?.user) redirect("/");

  const listing = await listCredentials();

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Credentials</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Manage the emails, passkeys, and linked accounts that can sign in to your account.
          Sensitive changes require a passkey.
        </p>
      </header>

      <CredentialsManager initial={listing} />
    </div>
  );
}
