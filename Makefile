# Makefile for building the application

# Application name
APP_NAME=wizscan

# Go related variables
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin

# Build related variables
BINARY_LINUX_AMD64=$(APP_NAME)-linux-amd64
BINARY_MACOS_ARM64=$(APP_NAME)-macos-arm64

# Versioning
GIT_COMMIT=$(shell git rev-list -1 HEAD)
VERSION?= $(shell git describe --tags --always || echo "unknown")
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.Commit=$(GIT_COMMIT)"

all: linux-amd64 macos-arm64

# Build binary for Linux AMD64
linux-amd64:
	@echo "  >  Building binary for Linux AMD64..."
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(GOBIN)/$(BINARY_LINUX_AMD64) $(GOBASE)/cmd/wizscan
	@echo "  >  Binary $(BINARY_LINUX_AMD64) created at $(GOBIN)"

# Build binary for macOS ARM64
macos-arm64:
	@echo "  >  Building binary for macOS ARM64..."
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(GOBIN)/$(BINARY_MACOS_ARM64) $(GOBASE)/cmd/wizscan
	@echo "  >  Binary $(BINARY_MACOS_ARM64) created at $(GOBIN)"

# Clean build files
clean:
	@echo "  >  Cleaning build files..."
	@rm -f $(GOBIN)/$(BINARY_LINUX_AMD64) $(GOBIN)/$(BINARY_MACOS_ARM64)

.PHONY: clean linux-amd64 macos-arm64