golangci := "go tool -modfile=tools/golangci-lint/go.mod golangci-lint"
govulncheck := "go tool -modfile=tools/govulncheck/go.mod govulncheck"
goreleaser := "go tool -modfile=tools/goreleaser/go.mod goreleaser"
mint := "npx --yes mint@4.3.96"

default:
    @just --list

# Format Go sources in place.
fmt:
    gofmt -w .

# Run the pinned linters.
lint:
    {{golangci}} run ./...

# Check dependencies against the Go vulnerability database; needs network.
vuln:
    {{govulncheck}} ./...

# Fuzz the target parser; failures are saved under internal/target/testdata as regression inputs.
fuzz time="60s":
    go test ./internal/target/ -run '^$' -fuzz FuzzParse -fuzztime {{time}}

# Run every offline check: formatting, vet, lint, race tests, build and module tidiness.
check:
    test -z "$(gofmt -l .)"
    go vet ./...
    {{golangci}} run ./...
    go test ./... -race -count=1
    go build ./...
    go mod tidy -diff
    for dir in tools/*/; do (cd "$dir" && go mod tidy -diff) || exit 1; done
    {{goreleaser}} check

# Run the checks CI runs: every offline check plus the vulnerability scan.
check-ci: check vuln

# Validate the release configuration.
release-check:
    {{goreleaser}} check

# Build every release archive into ./dist without publishing.
snapshot:
    {{goreleaser}} release --snapshot --clean

# Build the binary into ./bin.
build:
    go build -o bin/expirely ./cmd/expirely

# Serve the docs at http://localhost:3000 with Mintlify; needs Node.js 18 or newer.
docs:
    cd docs && {{mint}} dev --telemetry=false

# Mintlify's checks of the docs: MDX, navigation and broken links; needs Node.js.
docs-check:
    cd docs && {{mint}} validate --telemetry=false && {{mint}} broken-links --telemetry=false
