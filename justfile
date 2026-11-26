default:
    @just --list

# Format Go sources in place.
fmt:
    gofmt -w .

# Run every local check: formatting, vet, race tests, build and module tidiness.
check:
    test -z "$(gofmt -l .)"
    go vet ./...
    go test ./... -race -count=1
    go build ./...
    go mod tidy -diff

# Run the checks CI runs.
check-ci: check

# Build the binary into ./bin.
build:
    go build -o bin/expirely ./cmd/expirely
