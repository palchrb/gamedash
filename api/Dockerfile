# syntax=docker/dockerfile:1.6

# ---- builder ---------------------------------------------------------------
FROM node:22-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npx tsc

# Drop dev deps for the runtime image
RUN npm prune --omit=dev

# ---- runtime ---------------------------------------------------------------
FROM node:22-alpine AS runtime

# docker CLI + unzip (for world uploads) + tini (proper signal handling)
RUN apk add --no-cache docker-cli unzip tini

WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY package.json ./
COPY public ./public
COPY pwa ./pwa
COPY locales ./locales

USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/healthz || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/server.js"]
