import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { getBadgeType } from "@minister/shared";
import { issuanceMonthStartSeconds } from "@minister/vc";

import { ConsentScreen } from "@/components/consent-screen";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { holderCountsByType } from "@/lib/anonymity-sets";
import { loadUserBadges, summarizeAttributes, type DisplayBadge } from "@/lib/badges";
import { buildErrorRedirect, validateAuthorizeRequest } from "@/lib/oidc-authorize";
import { grantedRelevantBadgeIds, loadGrant } from "@/lib/oidc-grants";
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

  // Phase-3 transparency: the badge TYPES this room requests, and the
  // specific badge INSTANCES already disclosed to this client AND requested
  // here (audit W1 — instances, not whole types). These move into the locked
  // "you've already proven these" section (group 2); their ids are excluded
  // from the new-selection groups so a locked instance is not also pickable.
  // A sibling instance of the same type the user never disclosed stays
  // PICKABLE (default off) — it is no longer force-locked. A previously-
  // granted instance the room does NOT request is neither shown nor disclosed
  // for this room (F-2(a) — per-room minimal disclosure).
  const requestedBadgeTypes = new Set(
    request.scopes.filter((s) => s.startsWith("badge:")).map((s) => s.slice("badge:".length)),
  );
  const grant = await loadGrant(session.user.id, request.clientId);
  const grantedBadgeIds = grantedRelevantBadgeIds(grant, requestedBadgeTypes, allBadges);
  const alreadyGranted: AlreadyGrantedType[] = buildAlreadyGrantedView(grantedBadgeIds, allBadges);
  // The specific instance ids surfaced in the locked section — excluded (by
  // id) from the pickable groups so each badge appears once.
  const lockedIds = new Set(alreadyGranted.flatMap((g) => g.badges.map((b) => b.id)));
  // The types fully covered by the locked section drive the structured-policy
  // picker's per-type exclusion (unchanged for the policy path, which
  // minimizes disclosure to one instance per leaf regardless).
  const lockedTypes = new Set(alreadyGranted.map((g) => g.type));

  const badgeChoices = buildBadgeChoices(request.scopes, allBadges, lockedIds);

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
      // COARSE issuance clock (issuance-month start), mirroring
      // oidc-consent-minimize.toPolicyUserBadge: the picker preview must
      // evaluate maxAgeDays exactly as the authoritative minimize step and
      // the relying party do (the RP only ever sees the coarse
      // `issuanceMonth` claim), or the preselection could offer a set the
      // RP's gate then rejects.
      issuedAt: issuanceMonthStartSeconds(b.issuedAt),
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
  // Phase-3 / audit W1: specific badge instance ids shown in the locked
  // "already proven" section are excluded here (by id) so each instance
  // appears once. A non-locked sibling instance of the same type stays
  // pickable.
  excludeIds: ReadonlySet<string> = new Set(),
): BadgeChoiceGroup[] {
  const groups: BadgeChoiceGroup[] = [];
  for (const scope of scopes) {
    if (!scope.startsWith("badge:")) continue;
    const badgeType = scope.slice("badge:".length);
    // Pull name + description from the registry directly so they render
    // even when the user holds no badge of this type (the request is for
    // a *type*; the user may or may not have one).
    const meta = getBadgeType(badgeType);
    const held = badges.filter((b) => b.type === badgeType);
    const pickable = held.filter((b) => !excludeIds.has(b.id));
    // If the user holds badges of this type but every one is already locked
    // into the "already proven" section, don't render an empty pickable
    // group (it would misleadingly say "you hold none"). A type the user
    // holds nothing of still renders (the request is for a type).
    if (held.length > 0 && pickable.length === 0) continue;
    groups.push({
      scope,
      typeLabel: meta?.label ?? badgeType,
      description: meta?.description ?? `Badge of type ${badgeType}.`,
      badges: pickable.map((b) => ({
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
