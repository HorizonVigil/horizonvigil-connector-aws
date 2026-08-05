# syntax=docker/dockerfile:1
FROM node:22-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && update-ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json ./
RUN --mount=type=secret,id=gh_pat \
    git config --global url."https://github.com/".insteadOf "ssh://git@github.com/"; \
    if [ -f /run/secrets/gh_pat ]; then \
      printf "machine github.com\nlogin x-access-token\npassword %s\n" "$(cat /run/secrets/gh_pat)" > ~/.netrc && chmod 600 ~/.netrc; \
    fi && \
    npm install
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
EXPOSE 8080
CMD ["npm", "run", "start"]
