# Variables
APP_NAME := pfxhttp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf 'dev')
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
PREFIX := /usr/local
MAN5_DIR := $(PREFIX)/share/man/man5
MAN8_DIR := $(PREFIX)/share/man/man8
BIN_DIR := $(PREFIX)/sbin
GOLANGCI_NEW_FROM_REV ?= HEAD
GOVULNCHECK ?= govulncheck
GOVULNCHECK_GOFLAGS ?= -mod=vendor
GOVULNCHECK_SCAN ?= package

# Default target
all: build

# Build target
build:
	go build -mod=vendor -trimpath $(LDFLAGS) -o $(APP_NAME)

# Build check target
build-check:
	go build -mod=vendor ./...

# Install target
install: build
	install -d $(DESTDIR)$(BIN_DIR)
	install -m 0755 $(APP_NAME) $(DESTDIR)$(BIN_DIR)/
	install -d $(DESTDIR)$(MAN5_DIR)
	install -m 0644 man/man5/pfxhttp.yml.5 $(DESTDIR)$(MAN5_DIR)/
	install -d $(DESTDIR)$(MAN8_DIR)
	install -m 0644 man/man8/pfxhttp.8 $(DESTDIR)$(MAN8_DIR)/

# Uninstall target
uninstall:
	rm -f $(DESTDIR)$(BIN_DIR)/$(APP_NAME)
	rm -f $(DESTDIR)$(MAN5_DIR)/pfxhttp.yml.5
	rm -f $(DESTDIR)$(MAN8_DIR)/pfxhttp.8

# Clean target
clean:
	rm -f $(APP_NAME)

# Test targets
fix:
	go fix ./...

vet:
	go vet ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found. Install it and rerun make guardrails"; exit 1; }
	golangci-lint run --new-from-rev=$(GOLANGCI_NEW_FROM_REV) ./...

test:
	go test -v ./...

race:
	go test -race -short $$(go list ./... | grep -v /vendor/)

test-release-metadata:
	bash scripts/test-release-semver-metadata.sh
	bash scripts/test-linux-package-layout.sh
	bash scripts/check-release-hardening.sh

test-postfix-interop:
	bash test/e2e/postfix/scripts/run.sh

guardrails: fix vet lint test test-release-metadata race build-check

govulncheck:
	@command -v $(GOVULNCHECK) >/dev/null 2>&1 || { echo "$(GOVULNCHECK) not found. Install it with: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }
	CGO_ENABLED=0 GOFLAGS="$(GOVULNCHECK_GOFLAGS)" $(GOVULNCHECK) -scan=$(GOVULNCHECK_SCAN) ./...

release-guardrails: guardrails govulncheck

# Print version
version:
	@echo $(VERSION)

# Regenerate gRPC stubs from the local Nauthilus AuthService proto mirror.
# Requires protoc and the protoc-gen-go / protoc-gen-go-grpc plugins on PATH.
generate-grpc:
	protoc \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/common/v1/common.proto \
		proto/auth/v1/auth.proto

.PHONY: all build build-check clean version install uninstall fix vet lint test test-release-metadata test-postfix-interop race guardrails govulncheck release-guardrails generate-grpc
