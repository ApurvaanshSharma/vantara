# Three stages: deps (install once, cached), builder (compile), runner
# (final lean image — only the standalone output + static assets, not the
# full node_modules or source tree).

FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-slim AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Baked in at build time — Next.js inlines NEXT_PUBLIC_* vars into the
# client bundle during build, not read at container runtime like the
# backend's env vars are. Must be passed as a build arg, not just a
# docker-compose environment: entry, or the frontend will build against
# whatever default was set here regardless of docker-compose.yml.
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
RUN npm run build

FROM node:22-slim AS runner
WORKDIR /app
ENV NODE_ENV=production

# node:22-slim already ships a non-root 'node' user at UID 1000 — the
# official Node image convention, specifically so images like this one
# don't need to create their own. Unlike the backend's python:3.12-slim
# (no pre-made user), useradd here would collide with it.
COPY --from=builder /app/public ./public
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static

USER node
EXPOSE 3000
CMD ["node", "server.js"]
