# Copyright (c) 2026 Eduardo Emiliano Alaniz - AllSafe Security Solutions
# SPDX-License-Identifier: AGPL-3.0-only

# Stage 1: build frontend
FROM node:22-alpine AS frontend-builder
RUN corepack enable && corepack prepare pnpm@9 --activate
WORKDIR /app
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN rm -f pnpm-workspace.yaml
RUN pnpm run build

# Stage 2: backend runtime
FROM node:20-alpine
WORKDIR /app
COPY backend/package*.json ./
RUN npm ci --production --silent
COPY backend/ ./
COPY --from=frontend-builder /app/dist ./public
EXPOSE 3006
CMD ["node", "server.js"]
