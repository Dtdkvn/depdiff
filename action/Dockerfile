# syntax=docker/dockerfile:1.7
FROM node:20.20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,id=depdiff-action-build-npm,target=/root/.npm,sharing=locked \
    --mount=type=secret,id=depdiff_ca,required=false \
    if [ -f /run/secrets/depdiff_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/depdiff_ca; fi; \
    npm ci --ignore-scripts --no-audit --no-fund \
    && test -x node_modules/.bin/tsc
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM node:20.20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,id=depdiff-action-runtime-npm,target=/root/.npm,sharing=locked \
    --mount=type=secret,id=depdiff_ca,required=false \
    if [ -f /run/secrets/depdiff_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/depdiff_ca; fi; \
    npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && node -e "for (const name of ['@babel/parser','commander','minimatch','picocolors','tar','yaml']) require.resolve(name)"
COPY --from=build /app/dist ./dist
COPY scripts/action-entrypoint.mjs ./scripts/action-entrypoint.mjs
ENTRYPOINT ["node", "/app/scripts/action-entrypoint.mjs"]
