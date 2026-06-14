FROM node:20-alpine

WORKDIR /app

# pnpm via corepack (uses packageManager from root package.json).
RUN corepack enable

# Manifests first for layer caching.
COPY pnpm-workspace.yaml package.json .npmrc ./
COPY apps/minister/package.json apps/minister/
COPY apps/demo-client/package.json apps/demo-client/
COPY packages/vc/package.json packages/vc/
COPY packages/plugin-sdk/package.json packages/plugin-sdk/
COPY packages/shared/package.json packages/shared/

# No lockfile committed yet during Stage 0 — install without freezing.
# Skip lifecycle scripts on this layer: apps/minister's `postinstall` runs
# `prisma generate`, which needs prisma/schema.prisma — and we haven't
# COPYed it yet. We run `prisma generate` explicitly below.
RUN pnpm install --filter "@minister/app..." --ignore-scripts

COPY . .

RUN cd apps/minister && pnpm prisma generate

WORKDIR /app/apps/minister
EXPOSE 3000

# Stage 0 uses `prisma db push` rather than migrations — the schema is still
# evolving and there's no production data to migrate. Switch to
# `prisma migrate deploy` and committed migration SQL in Stage 1.
CMD ["sh", "-c", "pnpm prisma db push --skip-generate && pnpm dev"]
