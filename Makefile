.PHONY: run build build-linux build-linux-arm64 build-macos build-macos-amd64 build-all test tidy

export CGO_ENABLED = 0

run:
	go run ./cmd/sentinelnet

build:
	go build -o sentinelnet$(if $(filter Windows_NT,$(OS)),.exe) ./cmd/sentinelnet

build-linux: export GOOS = linux
build-linux: export GOARCH = amd64
build-linux:
	go build -o dist/sentinelnet-linux-amd64 ./cmd/sentinelnet

build-linux-arm64: export GOOS = linux
build-linux-arm64: export GOARCH = arm64
build-linux-arm64:
	go build -o dist/sentinelnet-linux-arm64 ./cmd/sentinelnet

build-macos: export GOOS = darwin
build-macos: export GOARCH = arm64
build-macos:
	go build -o dist/sentinelnet-macos-arm64 ./cmd/sentinelnet

build-macos-amd64: export GOOS = darwin
build-macos-amd64: export GOARCH = amd64
build-macos-amd64:
	go build -o dist/sentinelnet-macos-amd64 ./cmd/sentinelnet

build-all: build build-linux build-linux-arm64 build-macos build-macos-amd64

test:
	go test ./...

tidy:
	go mod tidy
