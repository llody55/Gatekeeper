GOSUMDB ?= off
GOPROXY ?= https://goproxy.cn,direct
GOFLAGS ?= -mod=mod

# 版本号: 优先读 VERSION 文件, 缺省回退到 internal/version 默认值。
# 发版流程: 改 VERSION 文件 -> make build 即自动注入到二进制。
VERSION ?= $(shell cat VERSION 2>/dev/null)
LDFLAGS := -s -w $(if $(VERSION),-X gatekeeper/internal/version.VERSION=$(VERSION),)

.PHONY: build build-server build-agent vet test clean docker version cross

version:
	@echo "Gatekeeper $(if $(VERSION),$(VERSION),(unset))"

build: build-server build-agent

build-server:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gatekeeper-server ./cmd/server

build-agent:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gatekeeper-agent ./cmd/agent

# 交叉编译到常见 Linux 架构(混合云场景常用)
cross:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gatekeeper-server-linux-amd64 ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gatekeeper-agent-linux-amd64 ./cmd/agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gatekeeper-server-linux-arm64 ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gatekeeper-agent-linux-arm64 ./cmd/agent

vet:
	go vet ./...

test:
	go test ./...

clean:
	rm -rf bin

run-server: build-server
	./bin/gatekeeper-server -config ./gatekeeper.yaml

run-agent: build-agent
	./bin/gatekeeper-agent -config ./gatekeeper-agent.yaml