// Initial checked-state defaults for the OIDC consent screen (pure, no I/O, so
// the privacy contract for what starts pre-ticked is auditable + testable in one
// place). The consent screen seeds its toggles from this.
//
// Contract:
//   * Identifying disclosures (display name, avatar, and every specific badge)
//     default OFF on a FIRST disclosure to a client. A profile field the user
//     previously shared with THIS client (durable grant) comes back pre-checked
//     so re-login asks them to update it or untick to stop.
//   * The coarse account-strength bucket (`sybil-score`) is NON-identifying (a
//     0-4 bucket that never reveals which badges you hold) and a gating RP needs
//     it, so it defaults CHECKED whenever the scope is requested — on first
//     consent too, mirroring how a structured minister_policy pre-selects the
//     minimal satisfying set. The user can still untick it.

export interface ConsentDefaultInput {
  // Whether the RP requested the `profile` scope this round.
  wantsProfile: boolean;
  // Whether the user has EVER disclosed name/avatar to this client (durable grant).
  previouslyShared: { name: boolean; avatar: boolean };
  // Whether the RP requested the `sybil-score` scope this round.
  wantsSybilScore: boolean;
}

export interface ConsentDefaults {
  name: boolean;
  avatar: boolean;
  sybilScore: boolean;
}

export function initialConsentDefaults(input: ConsentDefaultInput): ConsentDefaults {
  return {
    // H-1: never pre-check from a durable grant unless `profile` was actually
    // requested this round (a badge-only re-login never renders the profile card).
    name: input.wantsProfile && input.previouslyShared.name,
    avatar: input.wantsProfile && input.previouslyShared.avatar,
    // Default-checked whenever requested, whether or not a prior grant exists.
    sybilScore: input.wantsSybilScore,
  };
}
