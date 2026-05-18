import Link from "next/link";

import { BadgeCard } from "@/components/badge-card";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";
import { loadShareLinkByToken } from "@/lib/share-links";

interface PageProps {
  params: Promise<{ token: string }>;
}

export default async function SharePage({ params }: PageProps) {
  const { token } = await params;
  const link = await loadShareLinkByToken(token);

  if (!link) {
    return (
      <Shell title="Link unavailable">
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          This share link doesn&apos;t exist, has been revoked by its
          owner, or has expired.
        </p>
        <Button asChild variant="outline" className="mt-4 self-start">
          <Link href="/">Tessera home</Link>
        </Button>
      </Shell>
    );
  }

  // Account gate: if the owner required it, refuse to render the
  // badges to unauthenticated viewers. We DO still record a (null)
  // view so the owner can see attempted accesses against gated links.
  const session = await getCurrentSession();
  if (link.requiresAccount && !session?.user) {
    // Don't double-count a single attempt — `viewerUserId: null` rows
    // are the "anonymous attempt" signal.
    await prisma.shareLinkView.create({
      data: { shareLinkId: link.id, viewerUserId: null },
    });
    const from = `/share/${encodeURIComponent(token)}`;
    return (
      <Shell title="Sign-in required">
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          The sender requires viewers to have a Tessera account. Sign
          in and the link will load.
        </p>
        <Button asChild className="mt-4 self-start">
          <Link href={`/?from=${encodeURIComponent(from)}`}>Sign in</Link>
        </Button>
      </Shell>
    );
  }

  // Record the view. Anonymous viewers (link doesn't require account
  // AND no session) get `viewerUserId: null`.
  await prisma.shareLinkView.create({
    data: {
      shareLinkId: link.id,
      viewerUserId: session?.user?.id ?? null,
    },
  });

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          Shared Tessera badges
        </h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          {link.badges.length} verifiable credential
          {link.badges.length === 1 ? "" : "s"}, valid until{" "}
          <time dateTime={link.expiresAt.toISOString()}>
            {link.expiresAt.toLocaleString()}
          </time>
          .
        </p>
      </header>

      {link.badges.length === 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Nothing here</CardTitle>
            <CardDescription>
              The shared badges have been deleted since this link was
              created.
            </CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <ul className="flex flex-col gap-3">
          {link.badges.map((b) => (
            <li key={b.id}>
              <BadgeCard
                badge={{
                  id: b.id,
                  type: b.type,
                  attributes: b.attributes,
                  issuer: "",
                  issuedAt: new Date(),
                  expiresAt: null,
                  isPublic: true,
                  sortOrder: 0,
                  importedFrom: null,
                  pluginId: null,
                  meta: {
                    type: b.type,
                    label: b.label,
                    description: b.description,
                    iconKey: b.iconKey,
                  },
                }}
                editable={false}
              />
            </li>
          ))}
        </ul>
      )}

      <p className="text-xs text-neutral-500">
        Each badge above is backed by a JWT-VC signed by Tessera —
        verifiers can replay them against{" "}
        <code>/.well-known/jwks.json</code>.
      </p>
    </div>
  );
}

function Shell({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mx-auto flex max-w-md flex-col gap-6 px-4 py-12">
      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col">{children}</CardContent>
      </Card>
    </div>
  );
}

