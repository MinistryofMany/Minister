import Link from "next/link";
import { notFound } from "next/navigation";

import { AdminOidcEditForm } from "@/components/admin-oidc-edit-form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { allOidcScopes } from "@/lib/oidc-client-admin";
import { prisma } from "@/lib/prisma";
import { requireAdmin } from "@/lib/session";

export default async function AdminOidcClientEditPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  await requireAdmin();

  const { id } = await params;
  const client = await prisma.oidcClient.findUnique({ where: { id } });
  if (!client) notFound();

  return (
    <div className="flex flex-col gap-4">
      <Link href="/admin/oidc-clients" className="text-xs underline underline-offset-2">
        ← All clients
      </Link>
      <Card>
        <CardHeader>
          <CardTitle>Edit {client.name}</CardTitle>
          <CardDescription>
            client_id <code className="font-mono">{client.clientId}</code> ·{" "}
            {client.clientSecretHash === null ? "public (PKCE-only)" : "confidential"}. The
            client_id and type can&apos;t change — register a new client for that.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AdminOidcEditForm
            id={client.id}
            initialName={client.name}
            initialRedirectUris={client.redirectUris.join("\n")}
            initialScopes={client.allowedScopes}
            allScopes={allOidcScopes()}
          />
        </CardContent>
      </Card>
    </div>
  );
}
