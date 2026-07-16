-- CreateTable
CREATE TABLE "AnonPairSession" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "state" TEXT NOT NULL DEFAULT 'waiting',
    "sealedPayload" TEXT,
    "creatorSecretHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "creatorIp" TEXT,
    "creatorUa" TEXT,
    "creatorCountry" TEXT,
    "creatorCity" TEXT,
    "sealerIp" TEXT,
    "sealerUa" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AnonPairSession_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AnonPairSession_userId_idx" ON "AnonPairSession"("userId");

-- AddForeignKey
ALTER TABLE "AnonPairSession" ADD CONSTRAINT "AnonPairSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
