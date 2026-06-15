import { notFound } from "next/navigation";

import { BadgeCard } from "@/components/badge-card";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { loadPublicBadges } from "@/lib/badges";
import { prisma } from "@/lib/prisma";

interface PageProps {
  params: Promise<{ userId: string }>;
}

export default async function PublicProfile({ params }: PageProps) {
  const { userId } = await params;

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, displayName: true, name: true, image: true, avatarUrl: true },
  });
  if (!user) notFound();

  const badges = await loadPublicBadges(userId);
  const name = user.displayName ?? user.name ?? "Minister user";

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="flex items-center gap-4">
        {(user.avatarUrl ?? user.image) ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            src={user.avatarUrl ?? user.image ?? undefined}
            alt=""
            className="h-12 w-12 rounded-full border border-neutral-200 object-cover dark:border-neutral-800"
          />
        ) : (
          <div aria-hidden className="h-12 w-12 rounded-full bg-neutral-200 dark:bg-neutral-800" />
        )}
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{name}</h1>
          <p className="text-sm text-neutral-500">
            Minister profile · {badges.length} public badge
            {badges.length === 1 ? "" : "s"}
          </p>
        </div>
      </header>

      {badges.length === 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Nothing public</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              This user hasn&apos;t made any badges public.
            </p>
          </CardContent>
        </Card>
      ) : (
        <ul className="flex flex-col gap-3">
          {badges.map((badge) => (
            <li key={badge.id}>
              <BadgeCard badge={badge} editable={false} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
