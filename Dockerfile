# Multi-stage production build for Solana x402 Intelligence API
FROM node:22-alpine AS builder

WORKDIR /app

# Install build dependencies
COPY package.json package-lock.json ./
RUN npm install

# Copy source code and build config
COPY tsconfig.json ./
COPY src/ ./src/
COPY packages/ ./packages/

# Compile TypeScript
RUN npm run build

# Stage 2: Production runtime image
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=4020

# Install production dependencies only
COPY package.json package-lock.json ./
RUN npm install --omit=dev && npm cache clean --force

# Copy compiled assets from builder
COPY --from=builder /app/dist ./dist

# Use non-root node user for container security
USER node

EXPOSE 4020

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:4020/api/health || exit 1

CMD ["node", "dist/server/index.js"]
