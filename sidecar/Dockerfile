# syntax=docker/dockerfile:1.6

# Minimal privileged sidecar — exposes an HTTP API for host-level
# firewall (ufw) and connection (ss/conntrack) operations. Runs
# Node.js directly on Alpine; no build step needed.

FROM node:22-alpine

WORKDIR /app
COPY server.js .

USER root
EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost:9090/healthz || exit 1

CMD ["node", "server.js"]
