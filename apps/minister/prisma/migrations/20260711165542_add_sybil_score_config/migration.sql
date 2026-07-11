-- AlterTable
ALTER TABLE "OidcAccessToken" ADD COLUMN     "sybilBucket" INTEGER,
ADD COLUMN     "sybilScore" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "OidcAuthorizationCode" ADD COLUMN     "sybilBucket" INTEGER,
ADD COLUMN     "sybilScore" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "BadgeWeight" (
    "badgeType" TEXT NOT NULL,
    "qualifier" TEXT NOT NULL,
    "sybilWeight" INTEGER NOT NULL,
    "recoveryWeight" INTEGER NOT NULL,
    "category" TEXT NOT NULL,
    "allowSoloRecovery" BOOLEAN NOT NULL DEFAULT false,
    "pendingRecoveryWeight" INTEGER,
    "recoveryEffectiveAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BadgeWeight_pkey" PRIMARY KEY ("badgeType","qualifier")
);

-- CreateTable
CREATE TABLE "SybilCategory" (
    "name" TEXT NOT NULL,
    "cap" INTEGER NOT NULL,

    CONSTRAINT "SybilCategory_pkey" PRIMARY KEY ("name")
);

-- CreateTable
CREATE TABLE "SybilBucketConfig" (
    "id" TEXT NOT NULL DEFAULT 'singleton',
    "bucket1Raw" INTEGER NOT NULL,
    "bucket2Raw" INTEGER NOT NULL,
    "bucket3Raw" INTEGER NOT NULL,
    "bucket4Raw" INTEGER NOT NULL,
    "bucket3MinCats" INTEGER NOT NULL,
    "bucket4MinCats" INTEGER NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SybilBucketConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RecoveryConfig" (
    "id" TEXT NOT NULL DEFAULT 'singleton',
    "threshold" INTEGER NOT NULL,
    "pendingThreshold" INTEGER,
    "thresholdEffectiveAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RecoveryConfig_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "BadgeWeight_category_idx" ON "BadgeWeight"("category");
