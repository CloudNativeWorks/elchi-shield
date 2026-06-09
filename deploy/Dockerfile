# syntax=docker/dockerfile:1.7
#
# From-source multi-stage build → a minimal, static, non-root distroless image.
# Used for local `make docker` and as the reproducible reference build. The
# release pipeline instead bundles a prebuilt binary via Dockerfile-release-binary
# (no Go toolchain), reusing the exact artifact attached to the GitHub Release.
#
# The image is a single full binary — every engine (incl. the Coraza WAF with the
# embedded OWASP CRS) and audit sink (ClickHouse/OTEL) is compiled in. The binary
# is fully static (CGO disabled), so the distroless static base (no libc) suffices.

FROM golang:1.26 AS build
WORKDIR /src

# Cache module downloads separately from the source for faster rebuilds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG APP_VERSION=dev
ARG COMMIT=""
RUN CGO_ENABLED=0 go build \
        -trimpath \
        -buildvcs=true \
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
