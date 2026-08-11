# syntax=docker/dockerfile:1
FROM node:22-slim AS build
ARG GH_PAT
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && update-ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json ./
# npm's own git-dependency resolver (hosted-git-info) has been unreliable in
# this build environment (anonymous GitHub access getting rejected), so this
# clones the pinned tag directly with an authenticated URL (GH_PAT is a
# read-only token scoped to just this one public repo, passed in via
# --build-arg from a Cloud Build secret -- never committed; fine-grained
# GitHub PATs require the literal username "x-access-token") and installs
# the built package straight into node_modules, the same end state npm's
# own git installer would reach.
RUN git clone --depth 1 --branch v1.0.11 https://x-access-token:${GH_PAT}@github.com/kknr8367/cloudops-shared-lib.git /tmp/shared-lib \
    && cd /tmp/shared-lib && npm install && npm run build && rm -rf node_modules
RUN node -e "const p=require('./package.json'); delete p.dependencies['@cloudops360/shared-lib']; require('fs').writeFileSync('./package.json', JSON.stringify(p, null, 2));" \
    && npm install \
    && mkdir -p node_modules/@cloudops360/shared-lib \
    && cp -r /tmp/shared-lib/dist /tmp/shared-lib/package.json node_modules/@cloudops360/shared-lib/ \
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
RUN node -e "const p=require('./package.json'); delete p.dependencies['@cloudops360/shared-lib']; require('fs').writeFileSync('./package.json', JSON.stringify(p, null, 2));" \
    && npm install --omit=dev
COPY --from=build /app/node_modules/@cloudops360/shared-lib ./node_modules/@cloudops360/shared-lib
COPY --from=build /app/dist ./dist
EXPOSE 8080
CMD ["npm", "run", "start"]
