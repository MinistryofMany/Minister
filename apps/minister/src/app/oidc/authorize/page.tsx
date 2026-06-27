import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { getBadgeType } from "@minister/shared";

import { ConsentScreen } from "@/components/consent-screen";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { holderCountsByType } from "@/lib/anonymity-sets";
import { loadUserBadges, summarizeAttributes, type DisplayBadge } from "@/lib/badges";
import { buildErrorRedirect, validateAuthorizeRequest } from "@/lib/oidc-authorize";
import { grantedRelevantTypes, loadGrant } from "@/lib/oidc-grants";
import {
  buildAlreadyGrantedView,
  buildPolicyConsentView,
  type AlreadyGrantedType,
  type PolicyConsentView,
} from "@/lib/oidc-policy-view";
import type { UserBadge } from "@/lib/oidc-policy";
import { signOidcRequest } from "@/lib/oidc-request-token";
import { prisma } from "@/lib/prisma";
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
      buildErrorRedirect(result.redirectUri, result.error, result.description, result.state),
    );
  }

  if (result.kind === "fatal") {
    return <FatalError title={result.title} description={result.description} />;
  }

  // result.kind === "ok"
  const { request } = result;
  const requestToken = await signOidcRequest(request);
  const allBadges = await loadUserBadges(session.user.id);

  // Phase-3 transparency: the badge TYPES this room requests, and the subset
  // already durably granted to this client AND requested here. These move
  // into the locked "you've already proven these" section (group 2) and are
  // excluded from the new-selection groups (3) so each type appears once.
  // A previously-granted type the room does NOT request is neither shown nor
  // disclosed for this room (F-2(a) — per-room minimal disclosure).
  const requestedBadgeTypes = new Set(
    request.scopes.filter((s) => s.startsWith("badge:")).map((s) => s.slice("badge:".length)),
  );
  const grant = await loadGrant(session.user.id, request.clientId);
  const alreadyGrantedTypes = grantedRelevantTypes(grant, requestedBadgeTypes);
  const alreadyGranted: AlreadyGrantedType[] = buildAlreadyGrantedView(
    alreadyGrantedTypes,
    allBadges,
  );
  // Only types we actually surfaced in the locked section (the user holds a
  // badge for them) are excluded from the new-selection groups.
  const lockedTypes = new Set(alreadyGranted.map((g) => g.type));

  const badgeChoices = buildBadgeChoices(request.scopes, allBadges, lockedTypes);

  // Phase-2: when the RP sent a structured policy, render the requirement
  // as a choice (satisfy one / n of several) with the most-anonymous
  // minimal set pre-selected and a coarse anonymity hint for informed
  // override. Absent ⇒ today's flat per-scope groups.
  let policyView: PolicyConsentView | null = null;
  if (request.policy) {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const userBadges: UserBadge[] = allBadges.map((b) => ({
      id: b.id,
      type: b.type,
      attributes: toScalarAttrs(b.attributes),
      issuedAt: Math.floor(b.issuedAt.getTime() / 1000),
    }));
    policyView = buildPolicyConsentView(
      request.policy,
      allBadges,
      userBadges,
      await holderCountsByType(),
      nowSeconds,
      lockedTypes,
    );
  }

  // The curated profile values previewed beside the name/avatar toggles, so
  // the user sees the real data they'd disclose. Only the user-curated
  // fields — never the upstream auth identity. Plain object across the RSC
  // boundary.
  const profileUser = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { displayName: true, avatarUrl: true },
  });
  const profilePreview = {
    displayName: profileUser?.displayName ?? null,
    avatarUrl: profileUser?.avatarUrl ?? null,
  };

  return (
    <div className="mx-auto flex max-w-lg flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Approve access</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          <span className="font-medium">{request.clientName}</span> is requesting information from
          your Minister profile. Pick exactly what to disclose.
        </p>
      </header>

      <ConsentScreen
        clientName={request.clientName}
        wantsProfile={request.scopes.includes("profile")}
        profilePreview={profilePreview}
        badgeChoices={badgeChoices}
        alreadyGranted={alreadyGranted}
        policyView={policyView}
        requestToken={requestToken}
      />
    </div>
  );
}

// Narrow display-badge attributes to policy scalars for selection. Mirrors
// oidc-consent-minimize.coerceAttrs (kept local to avoid importing a
// "use server"-adjacent module into the page).
function toScalarAttrs(
  attributes: Record<string, unknown>,
): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  for (const [k, v] of Object.entries(attributes)) {
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") out[k] = v;
  }
  return out;
}

interface BadgeChoiceGroup {
  scope: string;
  // Human-readable badge-type name (registry label), falling back to the
  // raw slug only for unknown types. Drives the group heading.
  typeLabel: string;
  // One-line human description from the @minister/shared registry.
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
  // Phase-3: badge types shown in the locked "already proven" section are
  // excluded here so each type appears in exactly one group.
  excludeTypes: ReadonlySet<string> = new Set(),
): BadgeChoiceGroup[] {
  const groups: BadgeChoiceGroup[] = [];
  for (const scope of scopes) {
    if (!scope.startsWith("badge:")) continue;
    const badgeType = scope.slice("badge:".length);
    if (excludeTypes.has(badgeType)) continue;
    // Pull name + description from the registry directly so they render
    // even when the user holds no badge of this type (the request is for
    // a *type*; the user may or may not have one).
    const meta = getBadgeType(badgeType);
    const matched = badges.filter((b) => b.type === badgeType);
    groups.push({
      scope,
      typeLabel: meta?.label ?? badgeType,
      description: meta?.description ?? `Badge of type ${badgeType}.`,
      badges: matched.map((b) => ({
        id: b.id,
        label: b.meta.label,
        // Human summary of the badge's key attributes — never raw JSON.
        summary: summarizeAttributes(b.type, b.attributes),
      })),
    });
  }
  return groups;
}

function FatalError({ title, description }: { title: string; description: string }) {
  return (
    <div className="mx-auto flex max-w-lg flex-col gap-6 px-4 py-12">
      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-neutral-600 dark:text-neutral-400">
          This is a configuration problem with the relying party. Nothing was shared; contact the
          operator of the app that sent you here.
        </CardContent>
      </Card>
    </div>
  );
}
