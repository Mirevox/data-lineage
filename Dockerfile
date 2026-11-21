# Multi-stage production image for the data-lineage demo HTTP sidecar.
# Library consumers should prefer `npm install @mirevox/data-lineage` — this
# image is for one-command local/demo standup via docker compose.

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY config ./config
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
WORKDIR /app

ENV NODE_ENV=production \
    MIREVOX_LINEAGE_HOST=0.0.0.0 \
    MIREVOX_LINEAGE_PORT=3847 \
    MIREVOX_LINEAGE_CORS_ORIGIN=*

# Non-root runtime user
RUN addgroup -S mirevox && adduser -S -G mirevox mirevox

COPY --from=build --chown=mirevox:mirevox /app/package.json ./
COPY --from=build --chown=mirevox:mirevox /app/node_modules ./node_modules
COPY --from=build --chown=mirevox:mirevox /app/dist ./dist
COPY --from=build --chown=mirevox:mirevox /app/config ./config

USER mirevox
EXPOSE 3847

# Liveness via built-in fetch (no curl/wget dependency)
HEALTHCHECK --interval=10s --timeout=3s --start-period=8s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.MIREVOX_LINEAGE_PORT||3847)+'/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server/main.js"]
