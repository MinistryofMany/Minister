-- CreateTable
CREATE TABLE "BadgeStat" (
    "id" TEXT NOT NULL,
    "badgeType" TEXT NOT NULL,
    "attributeKey" TEXT NOT NULL,
    "attributeValue" TEXT NOT NULL,
    "count" INTEGER NOT NULL,
    "computedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BadgeStat_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CohortStatDef" (
    "id" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "numeratorFilter" JSONB NOT NULL,
    "denominatorFilter" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CohortStatDef_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CohortStat" (
    "defId" TEXT NOT NULL,
    "numerator" INTEGER NOT NULL,
    "denominator" INTEGER NOT NULL,
    "computedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CohortStat_pkey" PRIMARY KEY ("defId")
);

-- CreateTable
CREATE TABLE "BucketStat" (
    "bucket" INTEGER NOT NULL,
    "count" INTEGER NOT NULL,
    "computedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BucketStat_pkey" PRIMARY KEY ("bucket")
);

-- CreateTable
CREATE TABLE "StatsRun" (
    "id" TEXT NOT NULL DEFAULT 'singleton',
    "computedAt" TIMESTAMP(3) NOT NULL,
    "durationMs" INTEGER NOT NULL,

    CONSTRAINT "StatsRun_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "BadgeStat_badgeType_idx" ON "BadgeStat"("badgeType");

-- CreateIndex
CREATE UNIQUE INDEX "BadgeStat_badgeType_attributeKey_attributeValue_key" ON "BadgeStat"("badgeType", "attributeKey", "attributeValue");

-- AddForeignKey
ALTER TABLE "CohortStat" ADD CONSTRAINT "CohortStat_defId_fkey" FOREIGN KEY ("defId") REFERENCES "CohortStatDef"("id") ON DELETE CASCADE ON UPDATE CASCADE;
