GO        ?= go
PKG       ?= ./...
BIN_DIR   ?= bin
BINARY    ?= elchi-shield
CMD       ?= ./cmd/elchi-shield
# VERSION is the single source of truth (also consumed by create-release.yml).
VERSION   ?= $(shell cat VERSION 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DOCKER_IMAGE ?= elchi-shield
LDFLAGS   := -s -w -X main.version=v$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all build run test race bench loadtest loadtest-real profile cover vet lint tidy clean fmt fuzz vuln docker e2e

all: vet test build

# -trimpath + -buildvcs stamp a reproducible binary; version/commit come from the
# VERSION file + git (read back into build_info, the startup log, and /configz).
# The build is a single full binary — every engine and audit sink is compiled in.
build:
	$(GO) build -trimpath -buildvcs=true -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD)

# Local from-source image (the release pipeline instead bundles the prebuilt
# binary via deploy/Dockerfile-release-binary).
docker:
	docker build -f deploy/Dockerfile \
		--build-arg APP_VERSION=v$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		-t $(DOCKER_IMAGE):v$(VERSION) -t $(DOCKER_IMAGE):latest .

run: build
	$(BIN_DIR)/$(BINARY)

test:
	$(GO) test $(PKG)

race:
	$(GO) test -race $(PKG)

# Hot-path micro-benchmarks (matchers, resolver, pipeline).
bench:
	$(GO) test -run=^$$ -bench=. -benchmem $(PKG)

# End-to-end gRPC throughput over an in-memory transport (header + body paths).
loadtest:
	$(GO) test -run=^$$ -bench=BenchmarkProcess -benchmem ./internal/server/extproc/

# Real-traffic load test: a REAL Envoy proxies sustained HTTP through elchi-shield
# to an echo upstream; a closed-loop driver reports req/s + p50/p99 latency for
# passthrough / header-only / body-inspecting paths. Needs a real Envoy (func-e or
# ENVOY=...). Tunables: DURATION, CONNS, WARMUP.
loadtest-real:
	bash test/loadtest/run.sh

# Full end-to-end smoke: a REAL Envoy proxies HTTP through elchi-shield to an echo
# upstream and asserts allow(200)/block(403)/rate-limit(429). Needs a real Envoy
# (auto-fetched via func-e, or set ENVOY=/path/to/envoy).
e2e:
	bash test/e2e/run.sh

# CPU + alloc profiles of the load path.
profile:
	$(GO) test -run=^$$ -bench=BenchmarkProcessHeaderChecks -benchmem \
		-cpuprofile=cpu.prof -memprofile=mem.prof ./internal/server/extproc/
	@echo "profiles written: cpu.prof mem.prof (view with: go tool pprof cpu.prof)"

cover:
	$(GO) test -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out | tail -n 1

vet:
	$(GO) vet $(PKG)

lint:
	golangci-lint run

tidy:
	$(GO) mod tidy

fmt:
	$(GO) fmt $(PKG)

# Short fuzz smoke over the security-critical parsers/decoders (extend -fuzztime
# for a deeper local run).
fuzz:
	$(GO) test ./internal/config/ -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=30s
	$(GO) test ./internal/matcher/ -run='^$$' -fuzz='^FuzzHostMatch$$' -fuzztime=20s
	$(GO) test ./internal/matcher/ -run='^$$' -fuzz='^FuzzPathMatch$$' -fuzztime=20s
	$(GO) test ./internal/pipeline/stages/ -run='^$$' -fuzz='^FuzzDecodeBody$$' -fuzztime=30s

# Scan for known vulnerabilities in deps and the stdlib (reachable-call analysis).
vuln:
	govulncheck ./...

clean:
	rm -rf $(BIN_DIR) coverage.out
