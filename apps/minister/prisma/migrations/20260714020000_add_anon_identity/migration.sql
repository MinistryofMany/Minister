-- AlterTable
ALTER TABLE "OidcClient" ADD COLUMN     "anonAppId" TEXT;

-- CreateTable
CREATE TABLE "AnonSeedEnrollment" (
    "userId" TEXT NOT NULL,
    "enrollmentEpoch" INTEGER NOT NULL DEFAULT 1,
    "seedGeneratedAt" TIMESTAMP(3),
    "backupConfirmedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AnonSeedEnrollment_pkey" PRIMARY KEY ("userId")
);

-- CreateTable
CREATE TABLE "AnonSeedBlob" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "ciphertext" BYTEA NOT NULL,
    "iv" BYTEA NOT NULL,
    "wrapVersion" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AnonSeedBlob_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "AnonSeedBlob_userId_credentialId_key" ON "AnonSeedBlob"("userId", "credentialId");

-- CreateIndex
CREATE UNIQUE INDEX "OidcClient_anonAppId_key" ON "OidcClient"("anonAppId");

-- AddForeignKey
ALTER TABLE "AnonSeedEnrollment" ADD CONSTRAINT "AnonSeedEnrollment_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AnonSeedBlob" ADD CONSTRAINT "AnonSeedBlob_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

