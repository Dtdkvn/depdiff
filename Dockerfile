# syntax=docker/dockerfile:1.7
FROM node:20.20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM node:20.20-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S depdiff && adduser -S -G depdiff -h /app depdiff
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY fixtures ./fixtures
RUN mkdir -p /work /reports && chown -R depdiff:depdiff /app /work /reports
USER depdiff
WORKDIR /work
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["--help"]
