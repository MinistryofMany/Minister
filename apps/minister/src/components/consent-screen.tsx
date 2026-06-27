"use client";

import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { PolicyConsentView } from "@/lib/oidc-policy-view";
import { approveConsent, denyConsent } from "@/server/oidc-actions";

interface BadgeChoice {
  id: string;
  label: string;
  summary: string;
}

interface BadgeChoiceGroup {
  scope: string;
  typeLabel: string;
  description: string;
  badges: BadgeChoice[];
}

interface Props {
  clientName: string;
  wantsProfile: boolean;
  badgeChoices: BadgeChoiceGroup[];
  // Present when the RP sent a structured minister_policy: render the
  // requirement as a choice instead of flat independent groups.
  policyView: PolicyConsentView | null;
  requestToken: string;
}

export function ConsentScreen({
  clientName,
  wantsProfile,
  badgeChoices,
  policyView,
  requestToken,
}: Props) {
  // Defaults: opt-in for everything. Each disclosure requires an explicit
  // toggle from off → on — EXCEPT the structured-policy path, which
  // pre-selects the most-anonymous minimal satisfying set (the user can
  // override to another satisfying choice).
  const [profileAllowed, setProfileAllowed] = useState(false);
  const [selectedBadges, setSelectedBadges] = useState<Record<string, boolean>>(() =>
    policyView ? Object.fromEntries(policyView.preselectedBadgeIds.map((id) => [id, true])) : {},
  );
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  function toggleBadge(id: string) {
    setSelectedBadges((m) => ({ ...m, [id]: !m[id] }));
  }

  // Radio semantics for a "satisfy one of" group: selecting an option in
  // the group clears every other option in that group so the user can
  // never disclose two satisfying branches at once. (The server minimizes
  // authoritatively regardless; this is the UX guard.)
  function selectExclusive(groupIds: string[], id: string) {
    setSelectedBadges((m) => {
      const next = { ...m };
      for (const gid of groupIds) next[gid] = gid === id;
      return next;
    });
  }

  function submitApprove() {
    setError(null);
    const approvedBadgeIds = Object.entries(selectedBadges)
      .filter(([, v]) => v)
      .map(([id]) => id);

    startTransition(async () => {
      const result = await approveConsent({
        requestToken,
        approvedBadgeIds,
        approveProfile: profileAllowed,
      });
      if (result?.error) setError(result.error);
    });
  }

  function submitDeny() {
    setError(null);
    startTransition(async () => {
      await denyConsent({ requestToken });
    });
  }

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/30 dark:text-red-400">
          {error}
        </div>
      ) : null}

      {wantsProfile ? (
        <Card>
          <CardContent className="flex items-start gap-3 py-4">
            <input
              id="scope-profile"
              type="checkbox"
              className="mt-1 h-4 w-4"
              checked={profileAllowed}
              onChange={(e) => setProfileAllowed(e.target.checked)}
            />
            <label htmlFor="scope-profile" className="flex-1 text-sm">
              <span className="block font-medium">Display name and avatar</span>
              <span className="text-neutral-600 dark:text-neutral-400">
                Share your Minister display name (or fall back to your email) and avatar with{" "}
                {clientName}.
              </span>
            </label>
          </CardContent>
        </Card>
      ) : null}

      {policyView ? (
        <PolicyChoice
          view={policyView}
          clientName={clientName}
          selected={selectedBadges}
          onExclusive={selectExclusive}
          onToggle={toggleBadge}
        />
      ) : (
        badgeChoices.map((group) => (
          <Card key={group.scope}>
            <CardContent className="space-y-3 py-4">
              <div>
                <h3 className="text-sm font-semibold">{group.typeLabel}</h3>
                <p className="text-sm text-neutral-600 dark:text-neutral-400">
                  {group.description}
                </p>
              </div>

              {group.badges.length === 0 ? (
                <p className="rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-300">
                  You don&apos;t hold any badges of this type. {clientName} will receive nothing for
                  this scope.
                </p>
              ) : (
                <ul className="flex flex-col gap-2">
                  {group.badges.map((b) => (
                    <li
                      key={b.id}
                      className="flex items-start gap-3 rounded-md border border-neutral-200 p-2 dark:border-neutral-800"
                    >
                      <input
                        id={`badge-${b.id}`}
                        type="checkbox"
                        className="mt-1 h-4 w-4"
                        checked={Boolean(selectedBadges[b.id])}
                        onChange={() => toggleBadge(b.id)}
                      />
                      <label htmlFor={`badge-${b.id}`} className="flex-1 text-sm">
                        <span className="block font-medium">{b.label}</span>
                        {b.summary ? (
                          <span className="text-neutral-600 dark:text-neutral-400">
                            {b.summary}
                          </span>
                        ) : null}
                      </label>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        ))
      )}

      <div className="flex justify-end gap-2 pt-2">
        <Button type="button" variant="outline" disabled={pending} onClick={submitDeny}>
          Deny
        </Button>
        <Button type="button" disabled={pending} onClick={submitApprove}>
          {pending ? "Working…" : "Approve and continue"}
        </Button>
      </div>

      <p className="text-xs text-neutral-500">
        Only the badges you tick will be disclosed. Declining a scope sends nothing for it — the
        relying party gets whatever you approve, no more.
      </p>
    </div>
  );
}

function PolicyChoice({
  view,
  clientName,
  selected,
  onExclusive,
  onToggle,
}: {
  view: PolicyConsentView;
  clientName: string;
  selected: Record<string, boolean>;
  onExclusive: (groupIds: string[], id: string) => void;
  onToggle: (id: string) => void;
}) {
  const { group } = view;
  // The full set of option ids across every leaf of this group — used to
  // enforce radio exclusivity for a "satisfy one of" requirement.
  const groupIds = group.leaves.flatMap((leaf) => leaf.options.map((o) => o.id));

  const heading =
    group.kind === "one-of"
      ? "Satisfy any one of these"
      : group.kind === "n-of"
        ? `Satisfy any ${group.required} of these`
        : group.kind === "all-of"
          ? "All of these are required"
          : "Required";

  return (
    <Card>
      <CardContent className="space-y-3 py-4">
        <div>
          <h3 className="text-sm font-semibold">{heading}</h3>
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            {clientName} accepts this requirement. The most private choice is pre-selected; you can
            switch to another that also qualifies.
          </p>
        </div>

        {!view.satisfiable ? (
          <p className="rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-300">
            You don&apos;t hold a badge that satisfies this requirement
            {view.gaps.length > 0 ? ` (missing: ${view.gaps.join(", ")})` : ""}. You can still
            approve what you hold, but {clientName} may reject it.
          </p>
        ) : null}

        <ul className="flex flex-col gap-3">
          {group.leaves.map((leaf, i) => (
            <li
              key={`${leaf.type}-${i}`}
              className="rounded-md border border-neutral-200 p-2 dark:border-neutral-800"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">{leaf.typeLabel}</span>
                <span
                  className="text-xs text-neutral-500"
                  data-anonymity-bucket={leaf.anonymityBucket}
                >
                  {leaf.anonymityLabel}
                </span>
              </div>
              <p className="text-xs text-neutral-600 dark:text-neutral-400">{leaf.description}</p>

              {leaf.options.length === 0 ? (
                <p className="mt-1 text-xs text-amber-700 dark:text-amber-400">
                  You don&apos;t hold a qualifying badge for this.
                </p>
              ) : (
                <ul className="mt-2 flex flex-col gap-2">
                  {leaf.options.map((o) => (
                    <li key={o.id} className="flex items-start gap-3">
                      <input
                        id={`policy-badge-${o.id}`}
                        type={group.kind === "one-of" ? "radio" : "checkbox"}
                        name={group.kind === "one-of" ? "policy-one-of" : undefined}
                        className="mt-1 h-4 w-4"
                        checked={Boolean(selected[o.id])}
                        onChange={() =>
                          group.kind === "one-of" ? onExclusive(groupIds, o.id) : onToggle(o.id)
                        }
                      />
                      <label htmlFor={`policy-badge-${o.id}`} className="flex-1 text-sm">
                        <span className="block font-medium">{o.label}</span>
                        {o.summary ? (
                          <span className="text-neutral-600 dark:text-neutral-400">
                            {o.summary}
                          </span>
                        ) : null}
                      </label>
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
