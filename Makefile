GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

# Pinned lint tool versions (run with go run, not module dependencies).
STATICCHECK_VERSION ?= v0.8.2
GOSEC_VERSION ?= v2.29.0
GOVULNCHECK_VERSION ?= v1.9.0

.PHONY: build test fuzz lint harness bench image

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/phparmor ./cmd/phparmor

test:
	$(GO) test -race ./...

lint:
	$(GO) vet ./...
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -quiet ./...
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

FUZZTIME ?= 60s

# Each target runs on its own: go test allows one -fuzz target per package run.
fuzz:
	$(GO) test ./internal/inspect/query -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME)
	$(GO) test ./internal/inspect/headers -run '^$$' -fuzz '^FuzzStripCookies$$' -fuzztime $(FUZZTIME)
	$(GO) test ./internal/inspect/multipart -run '^$$' -fuzz '^FuzzCanonicalize$$' -fuzztime $(FUZZTIME)
	$(GO) test ./internal/inspect/multipart -run '^$$' -fuzz '^FuzzBoundary$$' -fuzztime $(FUZZTIME)
	$(GO) test ./internal/inspect/multipart -run '^$$' -fuzz '^FuzzParseDisposition$$' -fuzztime $(FUZZTIME)

harness:
	@echo "harness: PHP equivalence harness lands in M6"

bench:
	@echo "bench: k6/vegeta benchmarks land in M6"

IMAGE ?= phparmor:dev

image:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(IMAGE) .
