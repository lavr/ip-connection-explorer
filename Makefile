VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: build cross test load vet lint integration test-linux integration-build integration-docker

build:
	$(GOBUILD) -o bin/ipcx ./cmd/ipcx

cross:
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o bin/ipcx-linux-amd64 ./cmd/ipcx
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o bin/ipcx-linux-arm64 ./cmd/ipcx

test:
	go test -race ./...

load:
	IPCX_LOAD=1 go test -count=1 -run TestPipelineSustainsRate -v ./internal/collector/

vet:
	go vet ./...
	GOOS=linux go vet ./...

lint:
	staticcheck ./...

GO_IMAGE ?= golang:1.24
DOCKER_GO = docker run --rm -v $(CURDIR):/src -v $(shell go env GOMODCACHE):/go/pkg/mod -w /src $(GO_IMAGE)

test-linux:
	$(DOCKER_GO) go test -race ./...

INTEGRATION_ENV = IPCX_BIN=$(CURDIR)/bin/ipcx IPCX_HELPER=$(CURDIR)/bin/helpers

integration-build:
	CGO_ENABLED=0 go build -o bin/ipcx ./cmd/ipcx
	CGO_ENABLED=0 go build -o bin/helpers ./test/integration/helpers
	go test -c -tags integration -o bin/integration.test ./test/integration

integration: integration-build
	sudo -E $(INTEGRATION_ENV) bin/integration.test -test.v -test.count=1

integration-docker:
	GOOS=linux $(MAKE) integration-build
	docker run --rm --privileged --platform linux/$(shell go env GOARCH) -v $(CURDIR):/src -w /src debian:bookworm-slim sh -c '\
		apt-get update -qq >/dev/null && apt-get install -y -qq iproute2 nftables procps >/dev/null && \
		echo 0123456789abcdef0123456789abcdef > /etc/machine-id && \
		IPCX_BIN=/src/bin/ipcx IPCX_HELPER=/src/bin/helpers bin/integration.test -test.v -test.count=1'
