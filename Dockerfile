# Lightning Piggy notification watcher.
# Multi-stage: build (with toolchain for better-sqlite3 if no prebuilt binary)
# -> slim runtime with production deps only. Runs non-root and works with a
# read-only root filesystem (writes only to /data).
ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${NODE_IMAGE} AS build
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM ${NODE_IMAGE}
ENV NODE_ENV=production \
    WATCHER_DB_PATH=/data/watcher.db \
    WATCHER_HEALTH_BIND=0.0.0.0:8080
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
RUN mkdir -p /data && chown 65532:65532 /data && chmod 700 /data
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD ["node", "dist/index.js", "healthcheck"]
ENTRYPOINT ["node", "dist/index.js"]
