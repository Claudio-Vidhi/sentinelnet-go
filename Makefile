.PHONY: run build test tidy

run:
	go run ./cmd/sentinelnet

build:
	CGO_ENABLED=0 go build -o sentinelnet ./cmd/sentinelnet

test:
	go test ./...

tidy:
	go mod tidy
