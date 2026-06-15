import Link from "next/link";
import { redirect } from "next/navigation";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getCurrentSession } from "@/lib/session";
import { listPlugins } from "@/plugins/registry";

export default async function BadgePluginsList() {
  const session = await getCurrentSession();
  if (!session?.user) redirect("/");

  const plugins = listPlugins();

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Add a badge</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Pick a plugin. Each one walks you through proving a different fact about yourself.
        </p>
      </header>

      <ul className="flex flex-col gap-3">
        {plugins.map((plugin) => (
          <li key={plugin.manifest.id}>
            <Link
              href={`/badges/new/${plugin.manifest.id}`}
              className="block transition-colors hover:[&>div]:border-neutral-400 dark:hover:[&>div]:border-neutral-600"
            >
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{plugin.manifest.name}</CardTitle>
                  <CardDescription>{plugin.manifest.description}</CardDescription>
                </CardHeader>
                <CardContent className="text-xs text-neutral-500">
                  Issues:{" "}
                  {plugin.manifest.badgeTypes
                    .map((t) => <code key={t}>{t}</code>)
                    .reduce<
                      React.ReactNode[]
                    >((acc, el, i) => (i === 0 ? [el] : [...acc, ", ", el]), [])}
                  {plugin.manifest.requiresExtension ? (
                    <span className="ml-2 rounded-full bg-amber-50 px-2 py-0.5 font-medium text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
                      Requires extension
                    </span>
                  ) : null}
                </CardContent>
              </Card>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
