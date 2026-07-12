"use client";

import { useMemo, useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import type { AnonymityBucket, AnonymityHint } from "@/lib/anonymity-hint";
import type { PolicyConsentView } from "@/lib/oidc-policy-view";
import { approveConsent, denyConsent } from "@/server/oidc-actions";

// P2-U3: honest, bucket-derived phrasing for "how many other accounts share
// this account-strength level" — the anonymity set for THIS disclosure, not
// the anonymity set of any one badge type.
const GROUP_SIZE_PHRASE: Record<AnonymityBucket, string> = {
  "very-small": "a very small group",
  small: "a small group",
  medium: "a medium-sized group",
  large: "a large group",
};

interface BadgeChoice {
  id: string;
  label: string;
  summary: string;
  // True ⇒ disclosing this badge also discloses a per-RP Sybil nullifier
  // (crypto-core M5): an anonymous, per-site, persistent credential tag. Drives
  // the per-badge marker and the one-time notice below.
  carriesNullifier: boolean;
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
  // The EFFECTIVE persona seed for this RP: the per-RP override when set, else
  // the global curated default (matching the disclosure resolver's per-field
  // precedence). Pre-fills the inline name/avatar inputs so the user edits the
  // current persona rather than starting blank. `null` means nothing is set
  // for that field — the input starts empty. Only user-curated values; never
  // the upstream auth identity.
  profilePreview: {
    displayName: string | null;
    avatarUrl: string | null;
  };
  // Whether the user has EVER disclosed name/avatar to this client (from the
  // durable OidcGrant). On re-login a previously-shared field comes back
  // pre-checked with its current persona editable, so the user is asked to
  // update it or untick to stop. A field never shared with this client stays
  // default OFF - "always unselected by default" applies to new disclosures.
  previouslyShared: { name: boolean; avatar: boolean };
  // Whether the RP requested the `sybil-score` scope this round. When false the
  // account-strength card is not rendered.
  wantsSybilScore: boolean;
  // The coarse account-strength bucket (0-4) previewed on the card, or null
  // when it could not be computed (the numeral is then dropped). Advisory only;
  // consent-approve recomputes the authoritative snapshot server-side.
  sybilBucketPreview: number | null;
  // P2-U3: a live anonymity hint for the previewed bucket, sourced from the
  // materialized BucketStat (how many users currently score this same
  // bucket — the anonymity set for THIS disclosure). Null when stats aren't
  // computed yet, the preview bucket is unknown, or the lookup failed — the
  // card renders with no extra line in that case (fail soft).
  sybilBucketAnonymityHint: AnonymityHint | null;
  // Whether the user has EVER disclosed their account-strength bucket to this
  // client (durable grant). Re-login pre-checks it, mirroring name/avatar.
  previouslySybilScore: boolean;
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
  previouslyShared,
  wantsSybilScore,
  sybilBucketPreview,
  sybilBucketAnonymityHint,
  previouslySybilScore,
  badgeChoices,
  alreadyGranted,
  policyView,
  requestToken,
}: Props) {
  // Defaults: opt-in for everything. Each disclosure requires an explicit
  // toggle from off → on — EXCEPT the structured-policy path, which
  // pre-selects the most-anonymous minimal satisfying set (the user can
  // override to another satisfying choice). The `profile` scope is split
  // into independent name/avatar grants, each default OFF for a field never
  // shared with this client; a field the user previously disclosed (per the
  // durable grant) comes back pre-checked so re-login asks them to update it
  // or untick to stop.
  // Locked ids: every badge in the "already proven" section. These seed the
  // selection as `true` and can never be toggled off (transparency: re-hiding
  // an already-disclosed type from the same client buys no privacy). The
  // server forces them in regardless, so this is purely a UX affordance.
  const lockedIds = useMemo(
    () => new Set(alreadyGranted.flatMap((g) => g.badges.map((b) => b.id))),
    [alreadyGranted],
  );

  // H-1: only ever pre-check from the durable grant when the RP actually
  // requested `profile` this round. A badge-only re-login never renders the
  // profile card, so a stale previouslyShared flag must not seed these true
  // (the server masks too, but keep the UI truthful).
  const [nameAllowed, setNameAllowed] = useState(wantsProfile && previouslyShared.name);
  const [avatarAllowed, setAvatarAllowed] = useState(wantsProfile && previouslyShared.avatar);
  // Account-strength disclosure. Default OFF for a client the user never shared
  // it with; pre-checked only on a re-login where they previously did (mirrors
  // the name/avatar re-login default).
  const [sybilScoreAllowed, setSybilScoreAllowed] = useState(
    wantsSybilScore && previouslySybilScore,
  );
  // Editable per-RP persona (snapshot per app), seeded from the effective
  // value (override ?? global). Only sent for a field whose toggle is on.
  const [nameValue, setNameValue] = useState(profilePreview.displayName ?? "");
  const [avatarValue, setAvatarValue] = useState(profilePreview.avatarUrl ?? "");
  const [avatarBroken, setAvatarBroken] = useState(false);
  const [selectedBadges, setSelectedBadges] = useState<Record<string, boolean>>(() => {
    const seed: Record<string, boolean> = {};
    if (policyView) for (const id of policyView.preselectedBadgeIds) seed[id] = true;
    // Locked (already-granted) badges start selected and stay selected.
    for (const g of alreadyGranted) for (const b of g.badges) seed[b.id] = true;
    return seed;
  });
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  // crypto-core M5: which badge ids carry a per-RP Sybil nullifier, across
  // every place a badge can be shown (flat groups, the already-proven locked
  // section, and the structured-policy picker). The one-time notice appears
  // when any SELECTED badge carries one.
  const nullifierBadgeIds = useMemo(() => {
    const m = new Set<string>();
    for (const g of badgeChoices) for (const b of g.badges) if (b.carriesNullifier) m.add(b.id);
    for (const g of alreadyGranted) for (const b of g.badges) if (b.carriesNullifier) m.add(b.id);
    if (policyView) {
      for (const leaf of policyView.group.leaves)
        for (const o of leaf.options) if (o.carriesNullifier) m.add(o.id);
    }
    return m;
  }, [badgeChoices, alreadyGranted, policyView]);

  const anySelectedCarriesNullifier = useMemo(
    () => Object.entries(selectedBadges).some(([id, on]) => on && nullifierBadgeIds.has(id)),
    [selectedBadges, nullifierBadgeIds],
  );

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
        // Account-strength disclosure. The server re-gates on the requested
        // scope and computes the bucket itself; this is only the user's choice.
        approveSybilScore: sybilScoreAllowed,
        // The per-RP persona text. Only meaningful (and only persisted) for a
        // field whose toggle is on; the server re-gates on approveName/Avatar.
        nameValue,
        avatarValue,
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
                Sharing your name or avatar is optional — you can share neither. Nothing here is
                sent unless you tick it.
              </p>
            </div>

            <div className="rounded-md border border-neutral-200 p-2 dark:border-neutral-800">
              <label htmlFor="scope-profile-name" className="flex items-start gap-3">
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
                    {previouslyShared.name
                      ? `You currently share a display name with ${clientName}. Edit to update it, or untick to stop sharing.`
                      : `Share a display name with ${clientName}.`}
                  </span>
                </span>
              </label>
              {nameAllowed ? (
                <div className="mt-2 pl-7">
                  <Input
                    aria-label="Display name to share"
                    value={nameValue}
                    onChange={(e) => setNameValue(e.target.value)}
                    maxLength={80}
                    placeholder="e.g. Ada Lovelace"
                  />
                </div>
              ) : null}
            </div>

            <div className="rounded-md border border-neutral-200 p-2 dark:border-neutral-800">
              <label htmlFor="scope-profile-avatar" className="flex items-start gap-3">
                <input
                  id="scope-profile-avatar"
                  type="checkbox"
                  className="mt-1 h-4 w-4"
                  checked={avatarAllowed}
                  onChange={(e) => setAvatarAllowed(e.target.checked)}
                />
                <span className="flex-1 text-sm">
                  <span className="block font-medium">Avatar</span>
                  <span className="text-neutral-600 dark:text-neutral-400">
                    {previouslyShared.avatar
                      ? `You currently share an avatar with ${clientName}. Edit to update it, or untick to stop sharing.`
                      : `Share an avatar image with ${clientName}.`}
                  </span>
                </span>
              </label>
              {avatarAllowed ? (
                <div className="mt-2 flex items-center gap-3 pl-7">
                  {avatarValue && !avatarBroken ? (
                    // eslint-disable-next-line @next/next/no-img-element -- user-supplied avatar URL; next/image would need per-host remotePatterns config
                    <img
                      src={avatarValue}
                      alt="Your avatar"
                      onError={() => setAvatarBroken(true)}
                      onLoad={() => setAvatarBroken(false)}
                      className="h-10 w-10 shrink-0 rounded-full border border-neutral-200 object-cover dark:border-neutral-800"
                    />
                  ) : (
                    <div
                      aria-hidden
                      className="h-10 w-10 shrink-0 rounded-full bg-neutral-200 dark:bg-neutral-800"
                    />
                  )}
                  <Input
                    aria-label="Avatar URL to share"
                    value={avatarValue}
                    onChange={(e) => {
                      setAvatarValue(e.target.value);
                      setAvatarBroken(false);
                    }}
                    maxLength={2048}
                    placeholder="https://example.com/avatar.png"
                    className="flex-1"
                  />
                </div>
              ) : null}
            </div>

            <p className="text-xs text-neutral-500 dark:text-neutral-400">
              This name and avatar are used only for {clientName} and override your global default.
              You can change or remove them anytime in Settings → Connected apps.
            </p>
          </CardContent>
        </Card>
      ) : null}

      {wantsSybilScore ? (
        <Card>
          <CardContent className="space-y-3 py-4">
            <div>
              <h3 className="text-sm font-semibold">Account strength</h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                {sybilBucketPreview !== null
                  ? `Share your account-strength level: ${sybilBucketPreview} of 4.`
                  : "Share your account-strength level."}{" "}
                This shows how hard your account is to fake. It does not reveal which badges you
                have.
              </p>
              {sybilBucketAnonymityHint ? (
                <p
                  className="text-xs text-neutral-500 dark:text-neutral-400"
                  data-anonymity-bucket={sybilBucketAnonymityHint.bucket}
                >
                  Roughly: {sybilBucketAnonymityHint.label} — you&apos;d be in{" "}
                  {GROUP_SIZE_PHRASE[sybilBucketAnonymityHint.bucket]} of accounts sharing this
                  strength level.
                </p>
              ) : null}
            </div>

            <div className="rounded-md border border-neutral-200 p-2 dark:border-neutral-800">
              <label htmlFor="scope-sybil-score" className="flex items-start gap-3">
                <input
                  id="scope-sybil-score"
                  type="checkbox"
                  className="mt-1 h-4 w-4"
                  checked={sybilScoreAllowed}
                  onChange={(e) => setSybilScoreAllowed(e.target.checked)}
                />
                <span className="flex-1 text-sm">
                  <span className="block font-medium">Account-strength level</span>
                  <span className="text-neutral-600 dark:text-neutral-400">
                    {previouslySybilScore
                      ? `You currently share your account-strength level with ${clientName}. Untick to stop sharing.`
                      : `Share your account-strength level with ${clientName}.`}
                  </span>
                </span>
              </label>
            </div>
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
                          {b.carriesNullifier ? <NullifierMarker /> : null}
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
                        {b.carriesNullifier ? <NullifierMarker /> : null}
                      </label>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        ))
      )}

      {anySelectedCarriesNullifier ? <NullifierNotice clientName={clientName} /> : null}

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

// Per-badge inline marker: this badge discloses a persistent per-site tag.
function NullifierMarker() {
  return (
    <span
      className="mt-1 block text-xs text-amber-700 dark:text-amber-400"
      data-nullifier-marker="true"
    >
      Includes an anonymous, per-site tag for this credential.
    </span>
  );
}

// The one-time §2.5 notice, shown when any SELECTED badge carries a nullifier.
// Honest framing: one credential, not one person; per-site and unlinkable
// across sites; persists across account delete/re-create.
function NullifierNotice({ clientName }: { clientName: string }) {
  return (
    <div
      className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-200"
      data-nullifier-notice="true"
    >
      <p className="font-medium">This includes an anonymous credential tag</p>
      <p className="mt-1 text-amber-800 dark:text-amber-300">
        {clientName} receives an anonymous, per-site tag derived from the credential behind the
        badge(s) you&apos;re sharing — not your identity. The same tag appears if any account proves
        the same credential to {clientName}, and it persists even if you delete and re-create your
        Minister account, so {clientName} can recognize the credential as one it has seen before.
        Other sites receive a different, unlinkable tag. It proves one credential, not one person.
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
                        {o.carriesNullifier ? <NullifierMarker /> : null}
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
