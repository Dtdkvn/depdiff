# syntax=docker/dockerfile:1.7
FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS build
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

FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43
ENV NODE_ENV=production
WORKDIR /app
RUN --mount=type=secret,id=depdiff_ca,required=false \
    if [ -f /run/secrets/depdiff_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/depdiff_ca > /tmp/depdiff-ca-bundle.pem; \
      export SSL_CERT_FILE=/tmp/depdiff-ca-bundle.pem; \
    fi; \
    apk upgrade --no-cache \
    && rm -f /tmp/depdiff-ca-bundle.pem
COPY package.json package-lock.json ./
RUN --mount=type=cache,id=depdiff-action-runtime-npm,target=/root/.npm,sharing=locked \
    --mount=type=secret,id=depdiff_ca,required=false \
    if [ -f /run/secrets/depdiff_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/depdiff_ca; fi; \
    npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && node -e "for (const name of ['@babel/parser','commander','minimatch','picocolors','tar','yaml']) require.resolve(name)" \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg
COPY --from=build /app/dist ./dist
COPY scripts/action-entrypoint.mjs ./scripts/action-entrypoint.mjs
ENTRYPOINT ["node", "/app/scripts/action-entrypoint.mjs"]
