-- Onboarding gate: null until the forced /welcome setup guide is finished. The
-- session loader reads it off the row it already loads and bounces an unfinished
-- user to /welcome before any gated page.

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "setupCompletedAt" TIMESTAMP(3);
