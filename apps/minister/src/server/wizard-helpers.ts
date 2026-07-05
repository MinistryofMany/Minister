import type { WizardState, WizardStep } from "@minister/plugin-sdk";

// Pure helpers used by the wizard runtime and the OIDC server actions.
// Extracted so the logic is unit-testable without standing up Prisma.

// Resolve the indexed `pendingToken` for the current step, if any.
// Three step kinds use it:
//   - magic-link:       payload.expectedToken            (email link)
//   - redirect:         payload.expectedState            (OAuth state)
//   - extension-action: payload.expectedSubmissionToken  (TLSN submit)
// All three land in the same column because callback / submit routes
// resolve their session the same way: by token == pendingToken.
export function pendingTokenFor(state: WizardState): string | null {
  const step = state.currentStep;
  switch (step.kind) {
    case "magic-link":
      return step.payload.expectedToken ?? null;
    case "redirect":
      return step.payload.expectedState ?? null;
    case "extension-action":
      return step.payload.expectedSubmissionToken ?? null;
    default:
      return null;
  }
}

// Strip every pending-token-class SECRET from a step's payload before the
// wizard state crosses the RSC/server-action boundary to the browser.
//
// A server action's return value is serialized to the client IN FULL — the
// React renderer ignoring a field does NOT keep it off the wire. Three step
// kinds carry a token that is ALSO lifted into WizardSession.pendingToken (see
// pendingTokenFor) and accepted by the resume/callback routes as proof of
// possession:
//   - magic-link:       expectedToken            (proves inbox control)
//   - redirect:         expectedState            (OAuth CSRF/correlation state)
//   - extension-action: expectedSubmissionToken  (TLSN submit correlation)
// Returning any of them to the initiating browser defeats capture-at-verify:
// for the email plugins it hands an attacker the very token the verify route
// treats as inbox proof (anchor-squat / false-attestation, build-plan §2.3).
// The token still exists where it MUST — the DB column and (for magic-link) the
// emailed URL — so this only removes the illegitimate client copy.
function stripStepSecrets(step: WizardStep): WizardStep {
  switch (step.kind) {
    case "magic-link":
      return { ...step, payload: { ...step.payload, expectedToken: undefined } };
    case "redirect":
      return { ...step, payload: { ...step.payload, expectedState: undefined } };
    case "extension-action":
      return { ...step, payload: { ...step.payload, expectedSubmissionToken: undefined } };
    default:
      return step;
  }
}

// Build the client-safe view of a wizard state to return from a server action.
// Drops both the pending-token secrets (above) AND `data` — `WizardState.data`
// is documented server-side-only accumulator (the email plugins stash the raw
// lowercased address there across the round trip), so it must never ride the
// wire. The FULL state is still persisted to the DB by the runtime; this copy
// is display-only and is never sent back by the client.
export function toClientState(state: WizardState): WizardState {
  return {
    ...state,
    currentStep: stripStepSecrets(state.currentStep),
    data: {},
  };
}

// Reduce the requested OIDC scope set to what the user actually agreed
// to disclose on the consent screen. Three rules:
//   - `openid` is always preserved (it's the bootstrapping scope and
//     consent has already happened by the time we get here).
//   - `profile` is preserved only if the user ticked the profile-card
//     toggle.
//   - `badge:<type>` is preserved only if at least one badge of that
//     type was actually disclosed.
// Any unknown scope is dropped defensively (validation should have
// caught it upstream, but belt + suspenders).
export interface EffectiveScopesInput {
  approveProfile: boolean;
  approvedBadgeIds: string[];
  userBadges: Array<{ id: string; type: string }>;
}

export function effectiveScopes(requestedScopes: string[], input: EffectiveScopesInput): string[] {
  const out: string[] = [];
  for (const scope of requestedScopes) {
    if (scope === "openid") {
      out.push(scope);
      continue;
    }
    if (scope === "profile") {
      if (input.approveProfile) out.push(scope);
      continue;
    }
    if (scope.startsWith("badge:")) {
      const type = scope.slice("badge:".length);
      const anyApproved = input.userBadges.some(
        (b) => b.type === type && input.approvedBadgeIds.includes(b.id),
      );
      if (anyApproved) out.push(scope);
      continue;
    }
    // Unknown scope: drop (validation upstream should have rejected
    // it already).
  }
  return out;
}
