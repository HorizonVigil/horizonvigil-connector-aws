# syntax=docker/dockerfile:1
FROM node:22-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && update-ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json ./
# npm's own git-dependency resolver (hosted-git-info) has been unreliable in
# this build environment (anonymous GitHub access getting rejected), so this
# clones the pinned tag directly with an authenticated URL (GH_PAT is a
# read-only token scoped to just this one public repo, mounted via
# --mount=type=secret rather than --build-arg so it never lands in image
# layer history; fine-grained GitHub PATs require the literal username
# "x-access-token") and installs the built package straight into
# node_modules, the same end state npm's own git installer would reach.
RUN --mount=type=secret,id=gh_pat \
    git clone --depth 1 --branch v1.0.14 https://x-access-token:$(cat /run/secrets/gh_pat)@github.com/kknr8367/cloudops-shared-lib.git /tmp/shared-lib \
    && cd /tmp/shared-lib && npm install && npm run build && rm -rf node_modules
RUN node -e "const p=require('./package.json'); delete p.dependencies['@horizonvigil/shared-lib']; require('fs').writeFileSync('./package.json', JSON.stringify(p, null, 2));" \
    && npm install \
    && mkdir -p node_modules/@horizonvigil/shared-lib \
    && cp -r /tmp/shared-lib/dist /tmp/shared-lib/package.json node_modules/@horizonvigil/shared-lib/ \
    && rm -rf /tmp/shared-lib
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json ./
# Reuse the shared-lib package already built in the `build` stage above --
# no need to clone+build it a second time (and NODE_ENV=production here
# would skip the typescript devDependency that build needs anyway). The
# shared-lib copy happens AFTER npm install, not before -- with no
# package-lock.json present, npm reconciles node_modules against
# package.json and prunes anything it doesn't recognize, which silently
# deleted this exact directory when it was copied in first.
RUN node -e "const p=require('./package.json'); delete p.dependencies['@horizonvigil/shared-lib']; require('fs').writeFileSync('./package.json', JSON.stringify(p, null, 2));" \
    && npm install --omit=dev
COPY --from=build /app/node_modules/@horizonvigil/shared-lib ./node_modules/@horizonvigil/shared-lib
COPY --from=build /app/dist ./dist
RUN useradd -r -u 10001 -g node appuser && chown -R appuser:node /app
USER appuser
EXPOSE 8080
CMD ["npm", "run", "start"]
