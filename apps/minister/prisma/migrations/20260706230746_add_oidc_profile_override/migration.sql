-- CreateTable
CREATE TABLE "OidcProfileOverride" (
    "userId" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "displayName" TEXT,
    "avatarUrl" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OidcProfileOverride_pkey" PRIMARY KEY ("userId","clientId")
);

-- CreateIndex
CREATE INDEX "OidcProfileOverride_userId_idx" ON "OidcProfileOverride"("userId");

-- AddForeignKey
ALTER TABLE "OidcProfileOverride" ADD CONSTRAINT "OidcProfileOverride_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
