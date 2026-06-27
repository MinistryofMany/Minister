"use client";

import { useMemo, useState, useTransition } from "react";

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

// One row of the locked "you've already proven these to this platform"
// section: a badge type already disclosed to this client AND requested by
// this room, with the user's holdings. Rendered auto-checked and disabled.
interface AlreadyGrantedType {
  type: string;
  typeLabel: string;
  description: string;
  badges: BadgeChoice[];
}

interface Props {
  clientName: string;
  wantsProfile: boolean;
  // The user's current curated profile values, shown as a live preview so
  // the user sees the real data they'd disclose, not just a label. `null`
  // means the user has not set that value — there is nothing to share.
  profilePreview: {
    displayName: string | null;
    avatarUrl: string | null;
  };
  badgeChoices: BadgeChoiceGroup[];
  // Phase-3 transparency: badge types already disclosed to this client AND
  // requested by this room. Rendered in a separate locked section, auto-
  // checked and disabled (cannot be unticked). The server independently
  // forces these into the candidate disclosure, so the lock is a UX
  // affordance, not the security boundary.
  alreadyGranted: AlreadyGrantedType[];
  // Present when the RP sent a structured minister_policy: render the
  // requirement as a choice instead of flat independent groups.
  policyView: PolicyConsentView | null;
  requestToken: string;
}

export function ConsentScreen({
  clientName,
  wantsProfile,
  profilePreview,
  badgeChoices,
  alreadyGranted,
  policyView,
  requestToken,
}: Props) {
  // Defaults: opt-in for everything. Each disclosure requires an explicit
  // toggle from off → on — EXCEPT the structured-policy path, which
  // pre-selects the most-anonymous minimal satisfying set (the user can
  // override to another satisfying choice). The `profile` scope is split
  // into independent name/avatar grants, each default OFF.
  // Locked ids: every badge in the "already proven" section. These seed the
  // selection as `true` and can never be toggled off (transparency: re-hiding
  // an already-disclosed type from the same client buys no privacy). The
  // server forces them in regardless, so this is purely a UX affordance.
  const lockedIds = useMemo(
    () => new Set(alreadyGranted.flatMap((g) => g.badges.map((b) => b.id))),
    [alreadyGranted],
  );

  const [nameAllowed, setNameAllowed] = useState(false);
  const [avatarAllowed, setAvatarAllowed] = useState(false);
  const [selectedBadges, setSelectedBadges] = useState<Record<string, boolean>>(() => {
    const seed: Record<string, boolean> = {};
    if (policyView) for (const id of policyView.preselectedBadgeIds) seed[id] = true;
    // Locked (already-granted) badges start selected and stay selected.
    for (const g of alreadyGranted) for (const b of g.badges) seed[b.id] = true;
    return seed;
  });
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  function toggleBadge(id: string) {
    if (lockedIds.has(id)) return; // locked: cannot uncheck
    setSelectedBadges((m) => ({ ...m, [id]: !m[id] }));
  }

  // Radio semantics for a "satisfy one of" group: selecting an option in
  // the group clears every other option in that group so the user can
  // never disclose two satisfying branches at once. (The server minimizes
  // authoritatively regardless; this is the UX guard.) Locked ids are never
  // part of a pickable group, so exclusivity never clears them.
  function selectExclusive(groupIds: string[], id: string) {
    if (lockedIds.has(id)) return;
    setSelectedBadges((m) => {
      const next = { ...m };
      for (const gid of groupIds) {
        if (lockedIds.has(gid)) continue;
        next[gid] = gid === id;
      }
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
        approveName: nameAllowed,
        approveAvatar: avatarAllowed,
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
          <CardContent className="space-y-3 py-4">
            <div>
              <h3 className="text-sm font-semibold">Profile</h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Choose what {clientName} receives. Each is shared only if you tick it.
              </p>
            </div>

            <label
              htmlFor="scope-profile-name"
              className="flex items-start gap-3 rounded-md border border-neutral-200 p-2 dark:border-neutral-800"
            >
              <input
                id="scope-profile-name"
                type="checkbox"
                className="mt-1 h-4 w-4"
                checked={nameAllowed}
                onChange={(e) => setNameAllowed(e.target.checked)}
              />
              <span className="flex-1 text-sm">
                <span className="block font-medium">Display name</span>
                <span className="text-neutral-600 dark:text-neutral-400">
                  {profilePreview.displayName === null ? (
                    <>Name: (none set) — nothing to share</>
                  ) : (
                    <>Name: {profilePreview.displayName}</>
                  )}
                </span>
              </span>
            </label>

            <label
              htmlFor="scope-profile-avatar"
              className="flex items-start gap-3 rounded-md border border-neutral-200 p-2 dark:border-neutral-800"
            >
              <input
                id="scope-profile-avatar"
                type="checkbox"
                className="mt-1 h-4 w-4"
                checked={avatarAllowed}
                onChange={(e) => setAvatarAllowed(e.target.checked)}
              />
              <span className="flex-1 text-sm">
                <span className="block font-medium">Avatar</span>
                <span className="flex items-center gap-2 text-neutral-600 dark:text-neutral-400">
                  {profilePreview.avatarUrl === null ? (
                    <>Avatar: (none set) — nothing to share</>
                  ) : (
                    <>
                      {/* eslint-disable-next-line @next/next/no-img-element -- user-supplied avatar URL; next/image would need per-host remotePatterns config */}
                      <img
                        src={profilePreview.avatarUrl}
                        alt="Your avatar"
                        className="h-8 w-8 rounded-full object-cover"
                      />
                      <span>This avatar</span>
                    </>
                  )}
                </span>
              </span>
            </label>
          </CardContent>
        </Card>
      ) : null}

      {alreadyGranted.length > 0 ? (
        <Card className="border-neutral-300 bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-900/40">
          <CardContent className="space-y-3 py-4">
            <div>
              <h3 className="text-sm font-semibold">
                You&apos;ve already proven these to {clientName}
              </h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Already shared with this platform — included automatically when this room needs it.
              </p>
            </div>
            <ul className="flex flex-col gap-2">
              {alreadyGranted.map((g) => (
                <li
                  key={g.type}
                  className="rounded-md border border-neutral-200 p-2 dark:border-neutral-800"
                >
                  <span className="block text-sm font-medium">{g.typeLabel}</span>
                  <ul className="mt-1 flex flex-col gap-2">
                    {g.badges.map((b) => (
                      <li key={b.id} className="flex items-start gap-3">
                        <input
                          id={`granted-${b.id}`}
                          type="checkbox"
                          className="mt-1 h-4 w-4"
                          checked
                          disabled
                          readOnly
                          data-already-granted="true"
                        />
                        <label htmlFor={`granted-${b.id}`} className="flex-1 text-sm">
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
                </li>
              ))}
            </ul>
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
