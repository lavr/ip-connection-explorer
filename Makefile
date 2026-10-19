VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: build cross test vet lint integration test-linux

build:
	$(GOBUILD) -o bin/ipcx ./cmd/ipcx

cross:
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o bin/ipcx-linux-amd64 ./cmd/ipcx
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o bin/ipcx-linux-arm64 ./cmd/ipcx

test:
	go test -race ./...

vet:
	go vet ./...
	GOOS=linux go vet ./...

lint:
	staticcheck ./...

GO_IMAGE ?= golang:1.24
DOCKER_GO = docker run --rm -v $(CURDIR):/src -v $(shell go env GOMODCACHE):/go/pkg/mod -w /src $(GO_IMAGE)

test-linux:
	$(DOCKER_GO) go test -race ./...
