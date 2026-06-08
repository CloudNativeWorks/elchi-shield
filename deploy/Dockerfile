# syntax=docker/dockerfile:1.7
#
# From-source multi-stage build → a minimal, static, non-root distroless image.
# Used for local `make docker` and as the reproducible reference build. The
# release pipeline instead bundles a prebuilt binary via Dockerfile-release-binary
# (no Go toolchain), reusing the exact artifact attached to the GitHub Release.
#
# The default image is the LEAN binary (no Coraza/ClickHouse/OTEL): ~16 MB. To
# include the WAF / remote sinks, pass their build tags, e.g.:
#   docker build -f deploy/Dockerfile --build-arg TAGS="coraza" -t elchi-shield:coraza .
#   docker build -f deploy/Dockerfile --build-arg TAGS="coraza clickhouse otel" .
#
# The binary is fully static (CGO disabled) even with every heavy tag, so the
# distroless static base (no libc) is sufficient.

FROM golang:1.26 AS build
WORKDIR /src

# Cache module downloads separately from the source for faster rebuilds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TAGS=""
ARG APP_VERSION=dev
ARG COMMIT=""
RUN CGO_ENABLED=0 go build \
        -trimpath \
        -buildvcs=true \
        -tags "${TAGS}" \
        -ldflags "-s -w -X main.version=${APP_VERSION} -X main.commit=${COMMIT}" \
        -o /elchi-shield ./cmd/elchi-shield

# Distroless static (no shell, no package manager), running as a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot

ARG APP_VERSION=dev
LABEL org.opencontainers.image.title="elchi-shield" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.source="https://github.com/cloudnativeworks/elchi-shield"

COPY --from=build /elchi-shield /elchi-shield

# The ext_proc UDS and config dir live under /etc/elchi/elchi-shield; mount them
# as volumes shared with Envoy (the socket dir must be writable by uid 65532).
# 9001 is the loopback health/metrics port (exposed only with --allow-non-loopback).
EXPOSE 9001
USER 65532:65532
ENTRYPOINT ["/elchi-shield"]
