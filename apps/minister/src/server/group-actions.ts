"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { Prisma } from "@/generated/prisma";
import { audit } from "@/lib/audit";
import { GROUP_MEMBERSHIP_BADGE_TYPE, type GroupRole } from "@/lib/group-roles";
import { prisma } from "@/lib/prisma";
import { isReservedGroupSlug } from "@/lib/reserved-slugs";
import { requireSession } from "@/lib/session";
import { groupMembershipAnchor, revokeStatusAnchor } from "@/lib/status-list";
import { loadGroupConfig } from "@/lib/sybil-config";
import { computeUserSybilBucket } from "@/lib/user-sybil-bucket";
import { type BadgeToIssue, issueBadge } from "@/server/issue-badge";
import { GroupPermissionError, requireGroupRole } from "@/server/group-permissions";

// ---------------------------------------------------------------------------
// Result shape + input schemas
// ---------------------------------------------------------------------------

export type GroupActionResult = { ok: true } | { ok: false; error: string };
export type CreateGroupResult =
  { ok: true; groupId: string; slug: string } | { ok: false; error: string };

// Canonical slug: lowercase [a-z0-9] with single internal hyphens (no leading/
// trailing/double hyphen). Kept in lockstep with GroupMembershipClaims.group.
const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const SlugSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(3, "Group name must be at least 3 characters.")
  .max(32, "Group name must be at most 32 characters.")
  .regex(SLUG_RE, "Use lowercase letters, numbers, and single hyphens only.");

const CreateGroupInput = z.object({
  slug: SlugSchema,
  displayName: z.string().trim().min(1, "A display name is required.").max(80),
  description: z.string().trim().max(500).optional(),
});

const GroupIdInput = z.object({ groupId: z.string().cuid() });
const RenameGroupInput = z.object({
  groupId: z.string().cuid(),
  displayName: z.string().trim().min(1, "A display name is required.").max(80),
});
const EditGroupInput = z.object({
  groupId: z.string().cuid(),
  description: z.string().trim().max(500).nullable(),
});

// Roles an add/role-change may target. `owner` is excluded: a group has exactly
// one owner, set at founding and moved only by (future) ownership transfer.
const AssignableRole = z.enum(["admin", "member"]);
const AddMemberInput = z.object({
  groupId: z.string().cuid(),
  targetUserId: z.string().cuid(),
  role: AssignableRole,
});
const MemberTargetInput = z.object({
  groupId: z.string().cuid(),
  targetUserId: z.string().cuid(),
});
const SetMemberRoleInput = z.object({
  groupId: z.string().cuid(),
  targetUserId: z.string().cuid(),
  role: AssignableRole,
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function firstZodError(err: z.ZodError): string {
  return err.issues[0]?.message ?? "Invalid input.";
}

// Build the group-membership badge for (slug, role, groupId). `attributes` and
// `claims` are the same object: {group, role, groupId} is entirely
// non-sensitive, and the disclosure re-check reads `attributes.groupId`.
function groupMembershipBadge(slug: string, role: GroupRole, groupId: string): BadgeToIssue {
  const claim = { group: slug, role, groupId };
  return { type: GROUP_MEMBERSHIP_BADGE_TYPE, attributes: claim, claims: claim };
}

// ---------------------------------------------------------------------------
// Founding
// ---------------------------------------------------------------------------

// Found a group. Gated on the acting user's anti-sybil bucket (>= the config
// floor) AND their owned-group quota, with a reserved-slug denylist and slug
// uniqueness. Creates the Group, the owner's GroupMembership, and the owner's
// group-membership badge in ONE transaction, then audits.
export async function createGroup(input: unknown): Promise<CreateGroupResult> {
  const session = await requireSession();
  const userId = session.user.id;

  const parsed = CreateGroupInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: firstZodError(parsed.error) };
  const { slug, displayName, description } = parsed.data;

  if (isReservedGroupSlug(slug)) {
    return { ok: false, error: "That group name is reserved and can't be used." };
  }

  // Cheap uniqueness pre-check (the @unique index is the authoritative guard,
  // enforced by the P2002 catch below on the create).
  const existing = await prisma.group.findUnique({ where: { slug }, select: { id: true } });
  if (existing) return { ok: false, error: "That group name is already taken." };

  // Founding gate — config-driven, never hardcoded.
  let config: { foundingMinBucket: number; maxOwnedGroups: number };
  try {
    config = await loadGroupConfig();
  } catch {
    // Fail-closed: an unseeded/absent config blocks founding rather than
    // defaulting to a permissive floor.
    return { ok: false, error: "Group founding is temporarily unavailable. Try again later." };
  }

  const ownedCount = await prisma.group.count({ where: { ownerUserId: userId } });
  if (ownedCount >= config.maxOwnedGroups) {
    return {
      ok: false,
      error: `You already own the maximum of ${config.maxOwnedGroups} groups. Delete or transfer one to free a slot.`,
    };
  }

  let bucket: number;
  try {
    bucket = await computeUserSybilBucket(userId);
  } catch {
    // Fail-closed: if the score can't be computed, block rather than assume 0.
    return { ok: false, error: "Couldn't verify your account strength. Try again later." };
  }
  if (bucket < config.foundingMinBucket) {
    return {
      ok: false,
      error: `Founding a group needs a stronger account (strength ${config.foundingMinBucket}+). Add more verifications first.`,
    };
  }

  try {
    const groupId = await prisma.$transaction(async (tx) => {
      const group = await tx.group.create({
        data: {
          slug,
          displayName,
          description: description ?? null,
          ownerUserId: userId,
          verified: false,
        },
      });
      const membership = await tx.groupMembership.create({
        data: { groupId: group.id, userId, role: "owner", addedBy: userId },
      });
      await issueBadge({
        userId,
        pluginId: null,
        badge: groupMembershipBadge(group.slug, "owner", group.id),
        // Anchor the revocable badge on the membership FACT (§5.1), so a later
        // removal flips the one bit every RP watches.
        statusAnchor: groupMembershipAnchor(membership.id),
        tx,
      });
      await audit(userId, "group.created", { groupId: group.id, slug: group.slug }, tx);
      return group.id;
    });
    revalidatePath("/groups");
    return { ok: true, groupId, slug };
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
      return { ok: false, error: "That group name is already taken." };
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Owner-only group lifecycle
// ---------------------------------------------------------------------------

// Delete a group. Owner only. The Group delete cascades its GroupMembership
// rows; members' badges then disclose nothing on their next disclosure (the
// live-row re-check finds no row). Existing group badges are left in place —
// they lapse at disclosure — matching the "badges lapse on next disclosure"
// design; the group-management UI (out of scope) can hide dead ones.
export async function deleteGroup(input: unknown): Promise<GroupActionResult> {
  const session = await requireSession();
  const parsed = GroupIdInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: firstZodError(parsed.error) };
  const { groupId } = parsed.data;

  try {
    await requireGroupRole(groupId, session.user.id, "owner");
    await prisma.$transaction(async (tx) => {
      // Revoke every member's badge BEFORE the cascade deletes the membership
      // rows (§7.1): the anchor is "gm:<membershipId>", so we must read the ids
      // while they still exist. This reaches entitlements RPs already derived; the
      // cascade only stops NEW disclosures. BadgeStatusEntry is keyed on the
      // anchor STRING (no FK to GroupMembership), so the queued bits survive the
      // cascade and stay set forever (monotonic).
      const memberships = await tx.groupMembership.findMany({
        where: { groupId },
        select: { id: true },
      });
      for (const m of memberships) {
        await revokeStatusAnchor({
          anchor: groupMembershipAnchor(m.id),
          reason: "group.deleted",
          actorUserId: session.user.id,
          client: tx,
        });
      }
      await tx.group.delete({ where: { id: groupId } });
      await audit(session.user.id, "group.deleted", { groupId }, tx);
    });
    revalidatePath("/groups");
    return { ok: true };
  } catch (err) {
    if (err instanceof GroupPermissionError) return { ok: false, error: err.message };
    throw err;
  }
}

// Rename a group's human-facing display name. Owner only. The slug (the badge
// gating key) is deliberately immutable in v1.
export async function renameGroup(input: unknown): Promise<GroupActionResult> {
  const session = await requireSession();
  const parsed = RenameGroupInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: firstZodError(parsed.error) };
  const { groupId, displayName } = parsed.data;

  try {
    await requireGroupRole(groupId, session.user.id, "owner");
    await prisma.$transaction(async (tx) => {
      await tx.group.update({ where: { id: groupId }, data: { displayName } });
      await audit(session.user.id, "group.renamed", { groupId, displayName }, tx);
    });
    revalidatePath("/groups");
    return { ok: true };
  } catch (err) {
    if (err instanceof GroupPermissionError) return { ok: false, error: err.message };
    throw err;
  }
}

// Edit a group's description. Owner only. Pass null to clear it.
export async function editGroup(input: unknown): Promise<GroupActionResult> {
  const session = await requireSession();
  const parsed = EditGroupInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: firstZodError(parsed.error) };
  const { groupId, description } = parsed.data;

  try {
    await requireGroupRole(groupId, session.user.id, "owner");
    await prisma.$transaction(async (tx) => {
      await tx.group.update({ where: { id: groupId }, data: { description } });
      await audit(session.user.id, "group.edited", { groupId }, tx);
    });
    revalidatePath("/groups");
    return { ok: true };
  } catch (err) {
    if (err instanceof GroupPermissionError) return { ok: false, error: err.message };
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Membership management (admin+ with owner-only guards on admin-of-admins)
// ---------------------------------------------------------------------------

// Add a member and issue their group-membership badge, atomically. Baseline is
// admin+, but granting the `admin` role is OWNER-ONLY (creating an admin is an
// admin-of-admins action — the coup guard). A member can only be added as
// `member` by an admin.
export async function addMember(input: unknown): Promise<GroupActionResult> {
  const session = await requireSession();
  const parsed = AddMemberInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: firstZodError(parsed.error) };
  const { groupId, targetUserId, role } = parsed.data;
  const actorId = session.user.id;

  try {
    const ctx = await requireGroupRole(groupId, actorId, "admin");
    if (role === "admin" && ctx.role !== "owner") {
      return { ok: false, error: "Only the group owner can grant the admin role." };
    }

    const targetUser = await prisma.user.findUnique({
      where: { id: targetUserId },
      select: { id: true },
    });
    if (!targetUser) return { ok: false, error: "No such user." };

    const already = await prisma.groupMembership.findUnique({
      where: { groupId_userId: { groupId, userId: targetUserId } },
      select: { id: true },
    });
    if (already) return { ok: false, error: "That user is already a member of this group." };

    await prisma.$transaction(async (tx) => {
      const membership = await tx.groupMembership.create({
        data: { groupId, userId: targetUserId, role, addedBy: actorId },
      });
      await issueBadge({
        userId: targetUserId,
        pluginId: null,
        badge: groupMembershipBadge(ctx.group.slug, role, groupId),
        statusAnchor: groupMembershipAnchor(membership.id),
        tx,
      });
      await audit(actorId, "group.member_added", { groupId, targetUserId, role }, tx);
    });
    revalidatePath("/groups");
    return { ok: true };
  } catch (err) {
    if (err instanceof GroupPermissionError) return { ok: false, error: err.message };
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
      return { ok: false, error: "That user is already a member of this group." };
    }
    throw err;
  }
}

// Remove a member (deletes the GroupMembership row; the badge lapses at the
// member's next disclosure). Baseline admin+, with coup guards: the owner can
// never be removed here, and removing an ADMIN is owner-only.
export async function removeMember(input: unknown): Promise<GroupActionResult> {
  const session = await requireSession();
  const parsed = MemberTargetInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: firstZodError(parsed.error) };
  const { groupId, targetUserId } = parsed.data;
  const actorId = session.user.id;

  try {
    const ctx = await requireGroupRole(groupId, actorId, "admin");
    const target = await prisma.groupMembership.findUnique({
      where: { groupId_userId: { groupId, userId: targetUserId } },
      select: { id: true, role: true },
    });
    if (!target) return { ok: false, error: "That user is not a member of this group." };
    const targetRole = target.role as GroupRole;

    if (targetRole === "owner") {
      return {
        ok: false,
        error: "The group owner can't be removed. Transfer ownership or delete the group.",
      };
    }
    if (targetRole === "admin" && ctx.role !== "owner") {
      return { ok: false, error: "Only the group owner can remove an admin." };
    }

    await prisma.$transaction(async (tx) => {
      await tx.groupMembership.delete({
        where: { groupId_userId: { groupId, userId: targetUserId } },
      });
      // Layer 2: reach the entitlement RPs already derived from a pre-kick
      // disclosure. Layer 1 (the disclosure-time live-row re-check) already stops
      // NEW disclosures once the row is gone. Same tx so the row delete and the
      // bit-queue commit together.
      await revokeStatusAnchor({
        anchor: groupMembershipAnchor(target.id),
        reason: "group.member_removed",
        actorUserId: actorId,
        client: tx,
      });
      await audit(actorId, "group.member_removed", { groupId, targetUserId, targetRole }, tx);
    });
    revalidatePath("/groups");
    return { ok: true };
  } catch (err) {
    if (err instanceof GroupPermissionError) return { ok: false, error: err.message };
    throw err;
  }
}

// Change a member's role between `member` and `admin`. Owner-only: every such
// change either creates or destroys an admin (admin-of-admins), which the coup
// guard reserves to the owner. The owner's own role can't be changed here.
export async function setMemberRole(input: unknown): Promise<GroupActionResult> {
  const session = await requireSession();
  const parsed = SetMemberRoleInput.safeParse(input);
  if (!parsed.success) return { ok: false, error: firstZodError(parsed.error) };
  const { groupId, targetUserId, role } = parsed.data;
  const actorId = session.user.id;

  try {
    await requireGroupRole(groupId, actorId, "owner");
    const target = await prisma.groupMembership.findUnique({
      where: { groupId_userId: { groupId, userId: targetUserId } },
      select: { role: true },
    });
    if (!target) return { ok: false, error: "That user is not a member of this group." };
    const targetRole = target.role as GroupRole;

    if (targetRole === "owner") {
      return { ok: false, error: "The owner's role can't be changed here." };
    }
    if (targetRole === role) return { ok: true }; // no-op

    await prisma.$transaction(async (tx) => {
      await tx.groupMembership.update({
        where: { groupId_userId: { groupId, userId: targetUserId } },
        data: { role },
      });
      await audit(
        actorId,
        "group.member_role_changed",
        { groupId, targetUserId, from: targetRole, to: role },
        tx,
      );
    });
    revalidatePath("/groups");
    return { ok: true };
  } catch (err) {
    if (err instanceof GroupPermissionError) return { ok: false, error: err.message };
    throw err;
  }
}
