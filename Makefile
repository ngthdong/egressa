MODULE     := egressa
BIN_DIR    := bin
GO         := go

GIT_TAG    := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X '$(MODULE)/internal/buildinfo.Version=$(GIT_TAG)' \
           -X '$(MODULE)/internal/buildinfo.Commit=$(GIT_COMMIT)' \
           -X '$(MODULE)/internal/buildinfo.BuildTime=$(BUILD_TIME)'

BINARIES := client gateway controller vpnctl

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

.PHONY: fmt
fmt: ## Reformat the tree with gofmt
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-formatted, or if gofmt is missing (what CI runs)
	@command -v gofmt >/dev/null 2>&1 || { echo "gofmt not found on PATH — is Go installed?"; exit 1; }
	@unformatted=$$(gofmt -l .); \
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

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*## "}{printf "  %-14s %s\n", $$1, $$2}'