# Variables
APP_NAME := pfxhttp
VERSION := $(shell git describe --tags --always --dirty)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
PREFIX := /usr/local
MAN5_DIR := $(PREFIX)/share/man/man5
MAN8_DIR := $(PREFIX)/share/man/man8
BIN_DIR := $(PREFIX)/sbin

# SQLite configuration
SQLITE_LIB_PATH ?= $(PREFIX)/lib
SQLITE_INCLUDE_PATH ?= $(PREFIX)/include
CGO_ENABLED := 1
CGO_LDFLAGS ?= -L$(SQLITE_LIB_PATH)
CGO_CFLAGS ?= -I$(SQLITE_INCLUDE_PATH)

# Default target
all: build

# Build target
build:
	CGO_ENABLED=$(CGO_ENABLED) CGO_LDFLAGS="$(CGO_LDFLAGS)" CGO_CFLAGS="$(CGO_CFLAGS)" go build $(LDFLAGS) -o $(APP_NAME)

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
test:
	CGO_ENABLED=$(CGO_ENABLED) CGO_LDFLAGS="$(CGO_LDFLAGS)" CGO_CFLAGS="$(CGO_CFLAGS)" go test -v ./...

# Test customsql package specifically
test-customsql:
	CGO_ENABLED=$(CGO_ENABLED) CGO_LDFLAGS="$(CGO_LDFLAGS)" CGO_CFLAGS="$(CGO_CFLAGS)" go test -v ./customsql


# Print version
version:
	@echo $(VERSION)

# Print SQLite configuration
sqlite-config:
	@echo "SQLite Configuration:"
	@echo "  CGO_ENABLED: $(CGO_ENABLED)"
	@echo "  CGO_LDFLAGS: $(CGO_LDFLAGS)"
	@echo "  CGO_CFLAGS: $(CGO_CFLAGS)"

.PHONY: all build clean version install uninstall test test-customsql sqlite-config
