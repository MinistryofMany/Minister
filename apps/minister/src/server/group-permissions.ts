// The ONE place group authorization is decided. Every group server action
// funnels its permission check through `requireGroupRole` so the RBAC rules
// (and the admin-coup guards layered on top of it in group-actions.ts) live in
// a single, testable seam rather than scattered inline checks.
//
// Plain module (NOT "use server"): a "use server" file may export only async
// actions, and this helper must be importable by the actions without becoming a
// callable server action itself.

import { type GroupRole, roleAtLeast } from "@/lib/group-roles";
import { prisma } from "@/lib/prisma";

// A caller lacks the required role for a group action. Carries a
// user-presentable message; the actions map it to `{ ok: false, error }`. The
// same error is used for "not a member" and "not a member OF a group that may
// not exist" so a non-member cannot probe group existence.
export class GroupPermissionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GroupPermissionError";
  }
}

export interface GroupRoleContext {
  // The acting user's role in the group.
  role: GroupRole;
  group: { id: string; slug: string; ownerUserId: string };
}

// Resolve and gate the acting user's role in a group. Throws
// GroupPermissionError when the user is not a member or does not meet `minRole`.
// Returns the acting role + the group's identifying fields (slug for the badge
// claim, ownerUserId for owner-specific guards) so callers avoid a second read.
export async function requireGroupRole(
  groupId: string,
  userId: string,
  minRole: GroupRole,
): Promise<GroupRoleContext> {
  const membership = await prisma.groupMembership.findUnique({
    where: { groupId_userId: { groupId, userId } },
    select: {
      role: true,
      group: { select: { id: true, slug: true, ownerUserId: true } },
    },
  });
  if (!membership) {
    throw new GroupPermissionError("You are not a member of this group.");
  }
  const role = membership.role as GroupRole;
  if (!roleAtLeast(role, minRole)) {
    throw new GroupPermissionError(
      "You do not have permission to perform this action on this group.",
    );
  }
  return { role, group: membership.group };
}
