VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test integration lint vuln all

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/rlsprobe ./cmd/rlsprobe

test:
	go test -race ./...

integration:
	go test -race -tags integration ./...

lint:
	golangci-lint run ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

all: lint test integration build
