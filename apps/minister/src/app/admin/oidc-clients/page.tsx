import Link from "next/link";

import { AdminOidcClientActions } from "@/components/admin-oidc-client-actions";
import { AdminOidcCreateForm } from "@/components/admin-oidc-create-form";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { allOidcScopes } from "@/lib/oidc-client-admin";
import { prisma } from "@/lib/prisma";
import { requireAdmin } from "@/lib/session";

export default async function AdminOidcClientsPage() {
  await requireAdmin();

  const clients = await prisma.oidcClient.findMany({
    orderBy: { createdAt: "asc" },
  });

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Register a relying party</CardTitle>
          <CardDescription>
            Any site that speaks OpenID Connect can use these credentials
            for &ldquo;Sign in with Minister&rdquo;. Confidential clients get
            a secret (shown once); public clients are PKCE-only.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AdminOidcCreateForm allScopes={allOidcScopes()} />
        </CardContent>
      </Card>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">
          Clients{" "}
          <span className="text-sm font-normal text-neutral-500">
            ({clients.length})
          </span>
        </h2>

        {clients.length === 0 ? (
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            No relying parties registered yet.
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {clients.map((c) => (
              <li
                key={c.id}
                className="flex flex-col gap-2 rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-950"
              >
                <div className="flex items-center gap-2">
                  <span className="font-medium">{c.name}</span>
                  <TypeChip publicClient={c.clientSecretHash === null} />
                  <span className="ml-auto text-xs text-neutral-500">
                    created {c.createdAt.toLocaleDateString()}
                  </span>
                </div>
                <div className="text-xs text-neutral-500">
                  client_id:{" "}
                  <code className="font-mono text-neutral-700 dark:text-neutral-300">
                    {c.clientId}
                  </code>
                </div>
                <div className="text-xs text-neutral-500">
                  redirects:{" "}
                  {c.redirectUris.map((u) => (
                    <code key={u} className="mr-2 font-mono break-all">
                      {u}
                    </code>
                  ))}
                </div>
                <div className="flex flex-wrap gap-1">
                  {c.allowedScopes.map((s) => (
                    <span
                      key={s}
                      className="inline-flex items-center rounded-full bg-neutral-100 px-2 py-0.5 font-mono text-[10px] text-neutral-600 dark:bg-neutral-900 dark:text-neutral-400"
                    >
                      {s}
                    </span>
                  ))}
                </div>
                <div className="flex items-center gap-2">
                  <Link
                    href={`/admin/oidc-clients/${c.id}`}
                    className="text-xs underline underline-offset-2"
                  >
                    Edit
                  </Link>
                  <AdminOidcClientActions
                    id={c.id}
                    name={c.name}
                    isPublic={c.clientSecretHash === null}
                  />
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function TypeChip({ publicClient }: { publicClient: boolean }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
        publicClient
          ? "bg-sky-50 text-sky-700 dark:bg-sky-900/30 dark:text-sky-400"
          : "bg-neutral-100 text-neutral-500 dark:bg-neutral-900 dark:text-neutral-400"
      }`}
    >
      {publicClient ? "public · PKCE-only" : "confidential"}
    </span>
  );
}
