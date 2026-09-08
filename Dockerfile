# syntax=docker/dockerfile:1
FROM node:22-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && update-ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json ./
# The shared-lib version is whatever package.json says, and nothing else.
#
# This used to `git clone --branch <hardcoded tag>` and then DELETE
# @horizonvigil/shared-lib from package.json before installing, which made the
# Dockerfile the real source of truth and package.json decorative. That is not
# a style problem: the deploy workflow's build-and-test job installs the
# package.json version, so bumping the dependency turned CI green while the
# deployed image kept building an older library. Two shared-lib rollouts
# (deny-by-default resource scope, then server-side scope isolation) were
# merged, passed CI, and reported a successful deploy without the new code ever
# reaching production.
#
# npm resolves the git dependency itself now. The earlier workaround existed
# because ANONYMOUS GitHub access was being rejected in this build environment;
# the ~/.netrc below authenticates instead. This is byte-for-byte the pattern
# connector-gcp and connector-azure have always used, and the same thing
# build-and-test does, so it is proven in this exact environment. GH_PAT is
# read-only and mounted via --mount=type=secret rather than --build-arg, so it
# never lands in image layer history (fine-grained GitHub PATs require the
# literal username "x-access-token").
RUN --mount=type=secret,id=gh_pat \
    git config --global url."https://github.com/".insteadOf "ssh://git@github.com/"; \
    if [ -f /run/secrets/gh_pat ]; then \
      printf "machine github.com\nlogin x-access-token\npassword %s\n" "$(cat /run/secrets/gh_pat)" > ~/.netrc && chmod 600 ~/.netrc; \
    fi && \
    npm install && rm -f ~/.netrc
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && update-ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json ./
RUN --mount=type=secret,id=gh_pat \
    git config --global url."https://github.com/".insteadOf "ssh://git@github.com/"; \
    if [ -f /run/secrets/gh_pat ]; then \
      printf "machine github.com\nlogin x-access-token\npassword %s\n" "$(cat /run/secrets/gh_pat)" > ~/.netrc && chmod 600 ~/.netrc; \
    fi; \
    npm install --omit=dev; status=$?; rm -f ~/.netrc; exit $status
COPY --from=build /app/dist ./dist
RUN useradd -r -u 10001 -g node appuser && chown -R appuser:node /app
USER appuser
EXPOSE 8080
CMD ["npm", "run", "start"]
