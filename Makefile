.PHONY: run build test tidy

export CGO_ENABLED = 0

run:
	go run ./cmd/sentinelnet

build:
	go build -o sentinelnet$(if $(filter Windows_NT,$(OS)),.exe) ./cmd/sentinelnet

test:
	go test ./...

tidy:
	go mod tidy
