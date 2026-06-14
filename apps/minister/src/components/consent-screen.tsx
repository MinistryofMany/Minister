"use client";

import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { approveConsent, denyConsent } from "@/server/oidc-actions";

interface BadgeChoice {
  id: string;
  label: string;
  summary: string;
}

interface BadgeChoiceGroup {
  scope: string;
  badgeType: string;
  description: string;
  badges: BadgeChoice[];
}

interface Props {
  clientName: string;
  scopes: string[];
  wantsProfile: boolean;
  badgeChoices: BadgeChoiceGroup[];
  requestToken: string;
}

export function ConsentScreen({
  clientName,
  wantsProfile,
  badgeChoices,
  requestToken,
}: Props) {
  // Defaults: opt-in for everything. Each disclosure requires an
  // explicit toggle from off → on. Matches Minister's "private by
  // default" stance and forces the user to engage with each scope.
  const [profileAllowed, setProfileAllowed] = useState(false);
  const [selectedBadges, setSelectedBadges] = useState<Record<string, boolean>>({});
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  function toggleBadge(id: string) {
    setSelectedBadges((m) => ({ ...m, [id]: !m[id] }));
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
                Share your Minister display name (or fall back to your email)
                and avatar with {clientName}.
              </span>
            </label>
          </CardContent>
        </Card>
      ) : null}

      {badgeChoices.map((group) => (
        <Card key={group.scope}>
          <CardContent className="space-y-3 py-4">
            <div>
              <h3 className="text-sm font-semibold">{group.badgeType}</h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                {group.description}
              </p>
            </div>

            {group.badges.length === 0 ? (
              <p className="rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-300">
                You don&apos;t hold any badges of this type. {clientName} will
                receive nothing for this scope.
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
      ))}

      <div className="flex justify-end gap-2 pt-2">
        <Button
          type="button"
          variant="outline"
          disabled={pending}
          onClick={submitDeny}
        >
          Deny
        </Button>
        <Button type="button" disabled={pending} onClick={submitApprove}>
          {pending ? "Working…" : "Approve and continue"}
        </Button>
      </div>

      <p className="text-xs text-neutral-500">
        Only the badges you tick will be disclosed. Declining a scope sends
        nothing for it — the relying party gets whatever you approve, no more.
      </p>
    </div>
  );
}
