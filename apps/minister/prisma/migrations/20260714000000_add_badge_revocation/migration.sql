-- Badge revocation: per-RP Bitstring Status Lists
-- (docs/groups-revocation-design.md).

-- AlterTable: the revocation anchor (the fact underneath a revocable badge).
ALTER TABLE "Badge" ADD COLUMN "statusAnchor" TEXT;

-- CreateTable: one sharded bitstring per relying party.
CREATE TABLE "StatusList" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "shardNo" INTEGER NOT NULL,
    "sizeBits" INTEGER NOT NULL DEFAULT 8192,
    "version" INTEGER NOT NULL DEFAULT 0,
    "bits" BYTEA NOT NULL,
    "signedJwt" TEXT NOT NULL DEFAULT '',
    "publishedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "StatusList_pkey" PRIMARY KEY ("id")
);

-- CreateTable: the per-(fact, RP) revocation handle.
CREATE TABLE "BadgeStatusEntry" (
    "id" TEXT NOT NULL,
    "statusAnchor" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "listId" TEXT NOT NULL,
    "bitIndex" INTEGER NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "revealAfter" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BadgeStatusEntry_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "StatusList_clientId_shardNo_key" ON "StatusList"("clientId", "shardNo");

-- CreateIndex: one handle per (fact, RP).
CREATE UNIQUE INDEX "BadgeStatusEntry_statusAnchor_clientId_key" ON "BadgeStatusEntry"("statusAnchor", "clientId");

-- CreateIndex: no bit index is ever reused within a list.
CREATE UNIQUE INDEX "BadgeStatusEntry_listId_bitIndex_key" ON "BadgeStatusEntry"("listId", "bitIndex");

-- CreateIndex: the publisher scans revoked-but-eligible entries by list.
CREATE INDEX "BadgeStatusEntry_listId_revokedAt_idx" ON "BadgeStatusEntry"("listId", "revokedAt");
