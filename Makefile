GOSUMDB ?= off
GOPROXY ?= https://goproxy.cn,direct
GOFLAGS ?= -mod=mod

.PHONY: build build-server build-agent vet test clean docker

build: build-server build-agent

build-server:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/gatekeeper-server ./cmd/server

build-agent:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/gatekeeper-agent ./cmd/agent

# 交叉编译到常见 Linux 架构(混合云场景常用)
cross:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/gatekeeper-server-linux-amd64 ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/gatekeeper-agent-linux-amd64 ./cmd/agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o bin/gatekeeper-server-linux-arm64 ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o bin/gatekeeper-agent-linux-arm64 ./cmd/agent

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