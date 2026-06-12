import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { ConsentScreen } from "@/components/consent-screen";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { loadUserBadges, type DisplayBadge } from "@/lib/badges";
import {
  buildErrorRedirect,
  validateAuthorizeRequest,
} from "@/lib/oidc-authorize";
import { signOidcRequest } from "@/lib/oidc-request-token";
import { clientIpFrom, oidcAuthorizeLimiter } from "@/lib/rate-limit";
import { getCurrentSession } from "@/lib/session";

interface PageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function OidcAuthorizePage({ searchParams }: PageProps) {
  // Middleware already gates this route — but call getCurrentSession
  // ourselves so we have the session id, and for the same defense-in-
  // depth reason every other protected page uses it.
  const session = await getCurrentSession();
  if (!session?.user) redirect("/");

  const limit = oidcAuthorizeLimiter.check(clientIpFrom(await headers()));
  if (!limit.allowed) {
    return (
      <FatalError
        title="Too many requests"
        description={`Slow down — try again in about ${limit.retryAfterSeconds}s.`}
      />
    );
  }

  const sp = await searchParams;
  const raw = new URLSearchParams();
  for (const [k, v] of Object.entries(sp)) {
    if (typeof v === "string") raw.set(k, v);
  }

  const result = await validateAuthorizeRequest(raw);

  if (result.kind === "redirect-error") {
    redirect(
      buildErrorRedirect(
        result.redirectUri,
        result.error,
        result.description,
        result.state,
      ),
    );
  }

  if (result.kind === "fatal") {
    return <FatalError title={result.title} description={result.description} />;
  }

  // result.kind === "ok"
  const { request } = result;
  const requestToken = await signOidcRequest(request);
  const allBadges = await loadUserBadges(session.user.id);
  const badgeChoices = buildBadgeChoices(request.scopes, allBadges);

  return (
    <div className="mx-auto flex max-w-lg flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Approve access</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          <span className="font-medium">{request.clientName}</span> is
          requesting information from your Tessera profile. Pick exactly what
          to disclose.
        </p>
      </header>

      <ConsentScreen
        clientName={request.clientName}
        scopes={request.scopes}
        wantsProfile={request.scopes.includes("profile")}
        badgeChoices={badgeChoices}
        requestToken={requestToken}
      />
    </div>
  );
}

interface BadgeChoiceGroup {
  scope: string;
  badgeType: string;
  description: string;
  badges: Array<{
    id: string;
    label: string;
    summary: string;
  }>;
}

function buildBadgeChoices(
  scopes: string[],
  badges: DisplayBadge[],
): BadgeChoiceGroup[] {
  const groups: BadgeChoiceGroup[] = [];
  for (const scope of scopes) {
    if (!scope.startsWith("badge:")) continue;
    const badgeType = scope.slice("badge:".length);
    const matched = badges.filter((b) => b.type === badgeType);
    groups.push({
      scope,
      badgeType,
      description:
        matched[0]?.meta.description ?? `Badge of type ${badgeType}.`,
      badges: matched.map((b) => ({
        id: b.id,
        label: matched[0]?.meta.label ?? badgeType,
        summary: summarize(b),
      })),
    });
  }
  return groups;
}

function summarize(b: DisplayBadge): string {
  const { attributes, type } = b;
  switch (type) {
    case "email-domain":
      return typeof attributes.domain === "string" ? attributes.domain : "";
    case "email-exact":
      return typeof attributes.email === "string" ? attributes.email : "";
    case "oauth-account": {
      const p = String(attributes.provider ?? "");
      const h = attributes.handle ? `@${attributes.handle}` : "";
      return [p, h].filter(Boolean).join(" · ");
    }
    default:
      if (type.startsWith("age-over-")) {
        return `Over ${type.slice("age-over-".length)}`;
      }
      return JSON.stringify(attributes);
  }
}

function FatalError({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="mx-auto flex max-w-lg flex-col gap-6 px-4 py-12">
      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-neutral-600 dark:text-neutral-400">
          This is a configuration problem with the relying party. Nothing was
          shared; contact the operator of the app that sent you here.
        </CardContent>
      </Card>
    </div>
  );
}
