-- Badge-revocation hardening (docs/groups-revocation-design.md).

-- W1: durable per-ANCHOR revocation tombstone. Written by revokeStatusAnchor
-- independently of any per-RP BadgeStatusEntry, so an entry allocated AFTER a kick
-- is born revoked (closes the permanently-un-revocable-handle race).
CREATE TABLE "StatusAnchorRevocation" (
    "statusAnchor" TEXT NOT NULL,
    "revokedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reason" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "StatusAnchorRevocation_pkey" PRIMARY KEY ("statusAnchor")
);

-- W5: group slug tombstone. Written by deleteGroup; createGroup refuses to
-- re-found a slug tombstoned within the cooldown window.
CREATE TABLE "GroupSlugTombstone" (
    "slug" TEXT NOT NULL,
    "deletedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "GroupSlugTombstone_pkey" PRIMARY KEY ("slug")
);
