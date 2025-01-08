# Variables
APP_NAME := pfxhttp
VERSION := $(shell git describe --tags --always --dirty)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

# Default target
all: build

# Build target
build:
	go build $(LDFLAGS) -o $(APP_NAME)

# Clean target
clean:
	rm -f $(APP_NAME)

# Print version
version:
	@echo $(VERSION)

.PHONY: all build clean version
