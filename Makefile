MODULE     := github.com/ngthdong/egressa
BIN_DIR    := bin
GO         := go

GIT_TAG    := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# The commit's time, not the clock's: the same commit builds the same
# binary, so a second `make testbed-up` installs nothing new.
BUILD_TIME := $(shell TZ=UTC0 git show -s --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ HEAD 2>/dev/null || echo unknown)

# Reproducible: no local paths, no VCS stamp (the -X flags carry it).
BUILD_FLAGS := -trimpath -buildvcs=false

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
			$(GO) build $(BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$$bin ./cmd/$$bin || exit 1; \
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
	rm -rf $(BIN_DIR) $(DIST_DIR)

# Cross-compiled binaries for the VPS testbed

DIST_DIR   := dist
CROSS_ARCH := amd64 arm64

.PHONY: cross
cross: ## Build the Linux binaries Ansible installs, into dist/linux-<arch>/
	@for arch in $(CROSS_ARCH); do \
		echo "==> linux/$$arch"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build $(BUILD_FLAGS) -ldflags "$(LDFLAGS)" \
			-o $(DIST_DIR)/linux-$$arch/ ./cmd/controller ./cmd/gateway ./cmd/egressa ./cmd/vpnctl || exit 1; \
	done

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

# --- VPS testbed (deploy/ansible) -------------------------------------------

INVENTORY ?= inventory.ini
ANSIBLE    = cd deploy/ansible && ansible-playbook -i $(INVENTORY)

.PHONY: check-inventory
check-inventory:
	@test -f deploy/ansible/$(INVENTORY) || { echo "No deploy/ansible/$(INVENTORY): copy deploy/ansible/inventory.example.ini and fill it in."; exit 1; }

.PHONY: testbed-up
testbed-up: check-inventory cross ## Deploy the VPS testbed with Ansible (INVENTORY=inventory.ini)
	$(ANSIBLE) site.yml

.PHONY: testbed-down
testbed-down: check-inventory ## Remove egressa from the VPS testbed
	$(ANSIBLE) teardown.yml

.PHONY: testbed-status
testbed-status: check-inventory ## Health of every VPS testbed process
	$(ANSIBLE) status.yml

.PHONY: scenario
scenario: check-inventory ## Run a netem scenario on the VPS testbed: make scenario S=a|b|c
	@test -n "$(S)" || { echo "usage: make scenario S=a|b|c"; exit 1; }
	$(ANSIBLE) scenario.yml -e S=$(S)

# --- Observability (deploy/observability) -----------------------------------

COMPOSE = docker compose -f deploy/observability/docker-compose.yml

.PHONY: observability-targets
observability-targets: check-inventory ## Write Prometheus targets for the VPS testbed from the inventory
	python3 deploy/observability/gen_targets.py deploy/ansible/$(INVENTORY) > deploy/observability/targets/vps.json

.PHONY: observability-up
observability-up: ## Start Prometheus and Grafana on 127.0.0.1 (needs GRAFANA_ADMIN_PASSWORD; GRAFANA_PORT=3300)
	$(COMPOSE) up -d
	@echo "Grafana: http://127.0.0.1:$${GRAFANA_PORT:-3300} (admin)   Prometheus: http://127.0.0.1:9090"

.PHONY: observability-down
observability-down: ## Stop Prometheus and Grafana (data volumes stay)
	$(COMPOSE) down

PROMETHEUS_IMAGE = prom/prometheus:v3.5.0

.PHONY: deploy-check
deploy-check: ## Static checks of deploy/: shellcheck, promtool, compose, ansible syntax and lint
	shellcheck deploy/local/testbed.sh deploy/ansible/roles/tls/files/gen-tls.sh
	@tls=$$(mktemp -d) && trap 'rm -rf "$$tls"' EXIT && \
		test "$$(deploy/ansible/roles/tls/files/gen-tls.sh $$tls/t 192.0.2.10)" = changed && \
		test "$$(deploy/ansible/roles/tls/files/gen-tls.sh $$tls/t 192.0.2.10)" = unchanged && \
		openssl verify -CAfile $$tls/t/ca.crt $$tls/t/controller.crt && \
		openssl x509 -in $$tls/t/controller.crt -noout -ext subjectAltName | grep -q 'IP Address:192.0.2.10' && \
		echo "gen-tls.sh: issues once, then changes nothing"
	docker run --rm --entrypoint promtool -v "$(CURDIR)/deploy/observability/prometheus:/etc/prometheus:ro" \
		$(PROMETHEUS_IMAGE) check config /etc/prometheus/prometheus.yml
	GRAFANA_ADMIN_PASSWORD=check $(COMPOSE) config -q
	python3 deploy/observability/gen_targets.py deploy/ansible/inventory.example.ini > /dev/null
	cd deploy/ansible && for pb in site.yml teardown.yml scenario.yml status.yml; do \
		ansible-playbook -i inventory.example.ini --syntax-check $$pb || exit 1; done
	@if command -v ansible-lint >/dev/null 2>&1; then \
		cd deploy/ansible && ansible-lint --offline site.yml teardown.yml scenario.yml status.yml; \
	else echo "ansible-lint not installed; CI runs it. Skipping."; fi
	$(GO) test -count=1 -run 'TestDashboard|TestDocs' ./internal/telemetry/

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*## "}{printf "  %-22s %s\n", $$1, $$2}'