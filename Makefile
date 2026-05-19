# Build and packaging for beacon, the PharosVPN relay.
#
# `make build` produces a static, dependency-free binary — beacon has no
# cgo dependencies, so CGO_ENABLED=0 yields a single file that runs on any
# Linux host. Cross-compile for a deployment target with the standard Go
# environment variables, e.g.:
#
#     GOOS=linux GOARCH=amd64 make build

BINARY  := beacon
CMD     := ./cmd/beacon
DIST    := dist

# VERSION is stamped into the binary (see internal/cli.version). It comes
# from git, falling back to "dev" outside a checkout.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/PharosVPN/beacon/internal/cli.version=$(VERSION)

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build the static beacon binary into dist/
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY) $(CMD)

.PHONY: test
test: ## Run the test suite with the race detector
	go test -race ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt
fmt: ## Report files that need gofmt
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: check
check: fmt vet test lint ## Run every quality gate (matches CI)

.PHONY: clean
clean: ## Remove build output
	rm -rf $(DIST)

.PHONY: help
help: ## List targets
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | \
		awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
