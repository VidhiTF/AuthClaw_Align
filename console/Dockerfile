FROM node:22.23.1-alpine3.23@sha256:8516dce0483394d5708d4b2ee6cacb79fb1d617ea4e2787c2120bcca92ce372e AS base

FROM base AS deps
WORKDIR /app
RUN apk add --no-cache libc6-compat
COPY package.json package-lock.json ./
COPY scripts ./scripts
RUN npm ci

FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ARG NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
ARG NEXT_PUBLIC_GATEWAY_URL=http://localhost:8080
ARG NEXT_PUBLIC_SITE_URL=https://authclaw.ai
ARG NEXT_PUBLIC_AUTHCLAW_DEMO_MODE=false
ARG NEXT_PUBLIC_ENABLE_EXPERIMENTAL_SURFACES=false
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
ENV NEXT_PUBLIC_GATEWAY_URL=${NEXT_PUBLIC_GATEWAY_URL}
ENV NEXT_PUBLIC_SITE_URL=${NEXT_PUBLIC_SITE_URL}
ENV NEXT_PUBLIC_AUTHCLAW_DEMO_MODE=${NEXT_PUBLIC_AUTHCLAW_DEMO_MODE}
ENV NEXT_PUBLIC_ENABLE_EXPERIMENTAL_SURFACES=${NEXT_PUBLIC_ENABLE_EXPERIMENTAL_SURFACES}
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3001
ENV HOSTNAME=0.0.0.0
ENV AUTHCLAW_SESSION_STORE_PATH=/app/.authclaw/sessions.json

RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 nextjs \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
    && mkdir -p /app/.authclaw \
    && chown nextjs:nodejs /app/.authclaw

COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3001
CMD ["node", "server.js"]
