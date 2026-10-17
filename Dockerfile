FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json Makefile ./
COPY src ./src
COPY test ./test
COPY web ./web
RUN npm run build:all && npm prune --omit=dev

FROM node:22-bookworm-slim
ENV NODE_ENV=production
ENV TRUSTTRACE_HOST=127.0.0.1
ENV PORT=8787
ENV TRUSTTRACE_DB_PATH=/app/data/trusttrace.db
WORKDIR /app
COPY --from=build /app/package.json /app/package-lock.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/dist-web ./dist-web
RUN mkdir -p /app/data && chown -R node:node /app
USER node
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD node -e "fetch('http://127.0.0.1:8787/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"
CMD ["node", "dist/src/server.js"]
