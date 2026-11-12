# syntax=docker/dockerfile:1.7

# ---- node deps ----
FROM node:22-alpine AS deps
WORKDIR /app
# Toolchain for native modules (better-sqlite3) in case no musl prebuild
# matches this Node version.
RUN apk add --no-cache python3 make g++
COPY package.json package-lock.json ./
# Four dependencies install from vendored tarballs (file: specs in
# package.json), so they must be in place before npm ci.
COPY vendor/npm-offline ./vendor/npm-offline
RUN npm ci

# ---- node builder ----
FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# Build-info.json — same shape /app/build-info.json the standalone bundle
# emits, so getBuildInfo() resolves identically across both deploy paths.
# Pass --build-arg GIT_SHA=$(git rev-parse HEAD) to stamp the commit; falls
# back to "unknown" so a CI build that forgets the arg still succeeds.
ARG GIT_SHA=unknown
ARG BUILD_TIMESTAMP=
ENV BUILD_GIT_SHA=${GIT_SHA}
ENV BUILD_TS=${BUILD_TIMESTAMP}
RUN node -e "                                                                  \
const fs = require('fs');                                                      \
const pkg = require('./package.json');                                         \
const v = require('./versions.json');                                          \
const builtAt = process.env.BUILD_TS || new Date().toISOString();              \
fs.writeFileSync('/app/build-info.json', JSON.stringify({                      \
  buildKind: 'docker',                                                         \
  appVersion: pkg.version,                                                     \
  builtAt,                                                                     \
  gitSha: process.env.BUILD_GIT_SHA,                                           \
  nodeVersion: process.version,                                                \
  pins: {                                                                      \
    'mcp-server': v['mcp-server'],                                             \
  },                                                                           \
}, null, 2) + '\n');                                                           \
console.log(fs.readFileSync('/app/build-info.json', 'utf8'));                  \
"

# ---- runner ----
FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs \
 && adduser --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
# build-info.json — read by getBuildInfo() at process.cwd() = /app.
COPY --from=builder --chown=nextjs:nodejs /app/build-info.json ./build-info.json

# Project and third-party license notices.
COPY --chown=nextjs:nodejs LICENSE NOTICE.md ./
COPY --chown=nextjs:nodejs licenses ./licenses

USER nextjs
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

CMD ["node", "server.js"]
