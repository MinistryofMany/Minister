import { PrismaClient } from "@/generated/prisma";

// Cache the Prisma client across hot reloads in dev. Without this, every
// HMR cycle leaks another connection pool.
const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

export const prisma = globalForPrisma.prisma ?? new PrismaClient();

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}
