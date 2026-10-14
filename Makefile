MODULE     := egressa
BIN_DIR    := bin
GO         := go

GIT_TAG    := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X '$(MODULE)/internal/buildinfo.Version=$(GIT_TAG)' \
           -X '$(MODULE)/internal/buildinfo.Commit=$(GIT_COMMIT)' \
           -X '$(MODULE)/internal/buildinfo.BuildTime=$(BUILD_TIME)'

BINARIES := egressa client gateway controller vpnctl

.PHONY: all
all: build

.PHONY: build
build: ## Build all cmd/ binaries into bin/
	@mkdir -p $(BIN_DIR)
	@for bin in $(BINARIES); do \
		if [ -d cmd/$$bin ]; then \
			echo "==> building $$bin"; \
			$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$$bin ./cmd/$$bin || exit 1; \
		fi; \
	done

.PHONY: test
test: ## Run all tests
	$(GO) test ./...

.PHONY: test-race
test-race: ## Run all tests with the race detector (required before any migration/ PR)
	$(GO) test -race -count=1 ./...

.PHONY: bench
bench: ## Run benchmarks with allocation reporting
	$(GO) test ./... -run '^$$' -bench . -benchmem

.PHONY: fuzz
fuzz: ## Run the wire-format fuzz test for 30s (extend -fuzztime for a real campaign)
	$(GO) test ./pkg/wire/ -fuzz FuzzSessionHeader_RoundTrip -fuzztime 30s

.PHONY: vet
vet: ## go vet
	$(GO) vet ./...

# Every Go file except vendor/, which is third-party code kept exactly as
# published (some of it is not gofmt-formatted) and must never be rewritten.
GO_FILES = $$(find . -path ./vendor -prune -o -name '*.go' -print)

.PHONY: fmt
fmt: ## Reformat the tree with gofmt (vendor/ excluded)
	gofmt -w $(GO_FILES)

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-formatted, or if gofmt is missing (what CI runs)
	@command -v gofmt >/dev/null 2>&1 || { echo "gofmt not found on PATH — is Go installed?"; exit 1; }
	@unformatted=$$(gofmt -l $(GO_FILES)); \
	if [ -n "$$unformatted" ]; then \
		echo "The following files are not gofmt-formatted:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

.PHONY: lint
lint: ## Run golangci-lint if installed; otherwise skip with a warning (not a failure)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed locally; CI still runs it. Skipping."; \
	fi

.PHONY: ci
ci: fmt-check vet test-race build ## What CI runs, in order: fastest/cheapest checks first

.PHONY: run-client
run-client: build
	./$(BIN_DIR)/client

.PHONY: run-gateway
run-gateway: build
	./$(BIN_DIR)/gateway

.PHONY: run-controller
run-controller: build
	./$(BIN_DIR)/controller

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)

# --- Observability (deploy/observability) -----------------------------------

COMPOSE = docker compose -f deploy/observability/docker-compose.yml

.PHONY: observability-up
observability-up: ## Start Prometheus and Grafana on 127.0.0.1 (needs GRAFANA_ADMIN_PASSWORD; GRAFANA_PORT=3300)
	$(COMPOSE) up -d
	@echo "Grafana: http://127.0.0.1:$${GRAFANA_PORT:-3300} (admin)   Prometheus: http://127.0.0.1:9090"

.PHONY: observability-down
observability-down: ## Stop Prometheus and Grafana (data volumes stay)
	$(COMPOSE) down

# Local testbed (deploy/local): network namespaces on this machine

SUDO     ?= $(shell [ "$$(id -u)" -eq 0 ] || echo sudo)
GATEWAYS ?= 2
BACKEND  ?= auto
FIREWALL ?= 0
TESTBED_LOCAL = $(SUDO) env BIN_DIR=$(CURDIR)/$(BIN_DIR) GATEWAYS=$(GATEWAYS) BACKEND=$(BACKEND) FIREWALL=$(FIREWALL) deploy/local/testbed.sh

.PHONY: testbed-local-up
testbed-local-up: build ## Bring the local testbed up (root via sudo; GATEWAYS=2|3, BACKEND=auto|wireguard|ipsec, FIREWALL=1)
	$(TESTBED_LOCAL) up

.PHONY: testbed-local-down
testbed-local-down: ## Take the local testbed down, also after a failed up
	$(TESTBED_LOCAL) down

.PHONY: testbed-local-status
testbed-local-status: ## Show the local testbed's processes and health
	$(TESTBED_LOCAL) status

.PHONY: testbed-local-smoke
testbed-local-smoke: ## Smoke-test the local testbed, also behind the VPS firewall (root, or user namespaces)
	$(GO) test -count=1 -run '^TestLocalTestbed(Firewall)?$$' -v ./internal/e2e/

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*## "}{printf "  %-14s %s\n", $$1, $$2}'