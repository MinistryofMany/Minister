import type { CredentialStatusEntry } from "@minister/vc";

import { oidcIssuerUrl } from "@/lib/oidc-config";

// Status anchors (§5.1) — the revocable FACT underneath a badge, Ministry-internal
// and never disclosed. Keyed on the fact (not the badge row) so a 1-year renewal
// inherits the same per-RP handles.

// A group-membership badge anchors on its GroupMembership row incarnation. A
// kick-then-re-add makes a NEW membership row -> new anchor -> new index; the old
// bit stays set forever (monotonic).
export function groupMembershipAnchor(membershipId: string): string {
  return `gm:${membershipId}`;
}

// Generic revocable badge (fraud/compromise recall). Anchored on the badge id.
export function genericBadgeAnchor(badgeId: string): string {
  return `badge:${badgeId}`;
}

// The public URL of a status list. `listId` is the opaque StatusList.id (a cuid),
// NOT derived from clientId — the URL is a weak capability only Ministry and the
// owning RP know. Built from Minister's own public origin (AUTH_URL), never a
// client-supplied Host header.
export function statusListUrl(listId: string): string {
  return `${oidcIssuerUrl()}/status/${listId}`;
}

// The W3C BitstringStatusListEntry a disclosed VC carries for (listId, bitIndex).
export function credentialStatusFor(listId: string, bitIndex: number): CredentialStatusEntry {
  const url = statusListUrl(listId);
  return {
    id: `${url}#${bitIndex}`,
    type: "BitstringStatusListEntry",
    statusPurpose: "revocation",
    statusListIndex: String(bitIndex),
    statusListCredential: url,
  };
}
