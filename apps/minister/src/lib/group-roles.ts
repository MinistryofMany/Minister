// Group role ordering + the group-membership badge slug. Pure, no DB — imported
// by the server actions, the permission helper, and the disclosure path alike.

import { type GroupRole } from "@minister/shared";

export type { GroupRole };

// The single badge type groups issue. Kept as a named constant so the disclosure
// re-check and the issuance path agree without a stray string literal.
export const GROUP_MEMBERSHIP_BADGE_TYPE = "group-membership";

// Total order: owner outranks admin outranks member. A `minRole` gate is
// `roleAtLeast(actorRole, minRole)`.
const RANK: Record<GroupRole, number> = { member: 1, admin: 2, owner: 3 };

export function roleRank(role: GroupRole): number {
  return RANK[role];
}

export function roleAtLeast(role: GroupRole, floor: GroupRole): boolean {
  return RANK[role] >= RANK[floor];
}
