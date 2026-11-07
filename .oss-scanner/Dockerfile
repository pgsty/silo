# Copyright 2026 PGSTY contributors.
# SPDX-License-Identifier: AGPL-3.0-or-later

FROM golang:1.27.3-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    MINIO_API_REQUESTS_MAX=10000

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq openssl python3 procps \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies in the final image: subsequent analysis runs offline.
# Honor go.mod's PGSTY replacements and leave the module files unchanged.
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . /src

# Keep normal Go debug information; the release Makefile strips it.
RUN go build -tags kqueue -o /usr/local/bin/silo . \
    && silo --version

# Compile test packages while online, including the server and internal code.
# Retain both the module and build caches so new reproducers work offline.
RUN go test -tags kqueue,dev -run '^$' -timeout=10m ./cmd ./internal/...

ENV GOPROXY=off \
    GOSUMDB=off

CMD ["bash"]
