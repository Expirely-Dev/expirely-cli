golangci := "go tool -modfile=tools/golangci-lint/go.mod golangci-lint"
govulncheck := "go tool -modfile=tools/govulncheck/go.mod govulncheck"
goreleaser := "go tool -modfile=tools/goreleaser/go.mod goreleaser"
actionlint := "go tool -modfile=tools/actionlint/go.mod actionlint"
mint := "npx --yes mint@4.3.96"
release_platforms := "linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

default:
    @just --list

# Format Go sources in place.
fmt:
    gofmt -w .

# Run the pinned linters: golangci-lint on Go, actionlint on the GitHub Actions workflows.
lint:
    {{golangci}} run ./...
    {{actionlint}}

# Check dependencies against the Go vulnerability database; needs network.
vuln:
    {{govulncheck}} ./...

# Fuzz the target parser; failures are saved under internal/target/testdata as regression inputs.
fuzz time="60s":
    go test ./internal/target/ -run '^$' -fuzz FuzzParse -fuzztime {{time}}

# Run every offline check: formatting, vet, lint, workflow lint, race tests, build and module tidiness.
check:
    test -z "$(gofmt -l .)"
    go vet ./...
    {{golangci}} run ./...
    {{actionlint}}
    go test ./... -race -count=1
    go build ./...
    go mod tidy -diff
    for dir in tools/*/; do (cd "$dir" && go mod tidy -diff) || exit 1; done
    {{goreleaser}} check
    just licenses-check

# Run the checks CI runs: every offline check plus the vulnerability scan.
check-ci: check vuln

# copy the license, notice and patent files of Go and of each module a release binary links into <dir>/<module>@<version>, which GoReleaser packs under third-party/; fails on a module without a license file or with one outside Apache-2.0, BSD, ISC and MIT
third-party-licenses dir:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="{{dir}}"
    rm -rf "$dir"
    mkdir -p "$dir/go"
    goroot="$(go env GOROOT)"
    for f in LICENSE PATENTS; do
      if [[ -f "$goroot/$f" ]]; then cp "$goroot/$f" "$dir/go/"; elif [[ -f "$goroot/../$f" ]]; then cp "$goroot/../$f" "$dir/go/"; else echo "the Go toolchain at $goroot has no $f" >&2; exit 1; fi
    done
    modules="$(for p in {{ release_platforms }}; do GOOS="${p%/*}" GOARCH="${p#*/}" go list -deps -f '{{{{with .Module}}{{{{if not .Main}}{{{{.Path}}@{{{{.Version}} {{{{.Dir}}{{{{end}}{{{{end}}' ./cmd/expirely; done | sort -u)"
    failed=0
    while read -r module src; do
      [[ -n "$module" ]] || continue
      licenses=0
      for file in "$src"/*; do
        name="$(basename "$file")"
        shopt -s nocasematch
        if [[ "$name" =~ ^(LICEN[CS]E|COPYING)(\.(txt|md))?$ ]]; then
          shopt -u nocasematch
          licenses=$((licenses + 1))
          if grep -qiE 'GNU (Affero |Lesser )?General Public|Mozilla Public License|Server Side Public|Business Source License|Commons Clause' "$file"; then
            echo "$module: $name is a license outside Apache-2.0, BSD, ISC and MIT" >&2; failed=1
          elif ! { grep -q 'Apache License' "$file" && grep -q 'Version 2.0' "$file"; } && ! grep -qE 'Permission is hereby granted, free of charge|Redistribution and use in source and binary forms|Permission to use, copy, modify, and(/or)? distribute this software' "$file"; then
            echo "$module: $name is not Apache-2.0, BSD, ISC or MIT; review it before adding the dependency" >&2; failed=1
          fi
        elif [[ ! "$name" =~ ^(NOTICE|PATENTS)(\.(txt|md))?$ ]]; then
          shopt -u nocasematch
          continue
        fi
        shopt -u nocasematch
        mkdir -p "$dir/$module"
        cp "$file" "$dir/$module/"
      done
      if [[ "$licenses" -eq 0 ]]; then echo "$module has no license file" >&2; failed=1; fi
    done <<< "$modules"
    exit "$failed"

# the license files of every module a release binary links are present and allowed
licenses-check:
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT; just third-party-licenses "$tmp/third-party"

# Check that every commit title in RANGE follows Conventional Commits, which release-please reads to choose the next version.
commit-check range:
    #!/usr/bin/env bash
    set -euo pipefail
    pattern='^(feat|fix|perf|revert|docs|build|ci|chore|refactor|test)(\([a-z0-9-]+\))?!?: [^A-Z].*$'
    failed=0
    while IFS= read -r line; do
      sha="${line%% *}"; title="${line#* }"
      [[ "$title" == Merge\ * ]] && continue
      if [[ ! "$title" =~ $pattern ]]; then
        echo "$sha: \"$title\" is not <type>(<scope>): <summary> with a lowercase summary" >&2; failed=1
      elif (( ${#title} > 80 )); then
        echo "$sha: \"$title\" is longer than 80 characters" >&2; failed=1
      fi
    done < <(git log --format='%h %s' "{{range}}")
    exit "$failed"

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
