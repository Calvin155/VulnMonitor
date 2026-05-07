# ── Build stage ───────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM node:20-alpine
WORKDIR /app

# Production deps only
COPY package*.json ./
RUN npm ci --omit=dev

# Built frontend + server
COPY --from=builder /app/dist ./dist
COPY server.js ./

# Certs mounted at runtime via volume — not baked in
RUN mkdir -p /app/certs

EXPOSE 443 3001

ENV NODE_ENV=production

CMD ["node", "server.js"]
