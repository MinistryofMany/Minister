import type { WizardState } from "@tessera/plugin-sdk";

// Pure helpers used by the wizard runtime and the OIDC server actions.
// Extracted so the logic is unit-testable without standing up Prisma.

// Resolve the indexed `pendingToken` for the current step, if any.
// Two step kinds use it:
//   - magic-link: payload.expectedToken  (carried in the email link)
//   - redirect:   payload.expectedState  (carried in the OAuth state)
// Both land in the same column because callback routes resolve their
// session the same way: by token/state == pendingToken.
export function pendingTokenFor(state: WizardState): string | null {
  const step = state.currentStep;
  switch (step.kind) {
    case "magic-link":
      return step.payload.expectedToken ?? null;
    case "redirect":
      return step.payload.expectedState ?? null;
    default:
      return null;
  }
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

export function effectiveScopes(
  requestedScopes: string[],
  input: EffectiveScopesInput,
): string[] {
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
