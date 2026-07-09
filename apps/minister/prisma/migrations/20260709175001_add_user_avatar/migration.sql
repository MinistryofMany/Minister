-- CreateTable
CREATE TABLE "UserAvatar" (
    "userId" TEXT NOT NULL,
    "publicId" TEXT NOT NULL,
    "data" BYTEA NOT NULL,
    "contentType" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserAvatar_pkey" PRIMARY KEY ("userId"),
    -- Defense in depth against a non-app writer poisoning the table: the byte
    -- cap mirrors MAX_AVATAR_BYTES (512 KB) and the type allowlist mirrors
    -- ALLOWED_AVATAR_TYPES, so the serve route can never hand out an oversize or
    -- unexpected-type blob even if some path other than uploadAvatarAction wrote
    -- the row.
    CONSTRAINT "UserAvatar_data_size_check" CHECK (octet_length("data") <= 524288),
    CONSTRAINT "UserAvatar_contentType_check" CHECK ("contentType" IN ('image/png', 'image/jpeg', 'image/webp'))
);

-- CreateIndex
CREATE UNIQUE INDEX "UserAvatar_publicId_key" ON "UserAvatar"("publicId");

-- AddForeignKey
ALTER TABLE "UserAvatar" ADD CONSTRAINT "UserAvatar_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
