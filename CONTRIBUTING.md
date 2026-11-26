# Contributing

The rules for people and coding agents are in [AGENTS.md](AGENTS.md).

## Develop

Go 1.27 or newer and [just](https://github.com/casey/just):

```sh
just fmt
just check      # offline: gofmt, vet, golangci-lint, race tests, build, tidy, goreleaser check
just check-ci   # what CI runs: check plus govulncheck
just fuzz       # fuzz the target parser for 60s (just fuzz 5m for longer)
just build      # build ./bin/expirely
```

The documentation is a Mintlify site in `docs`, and needs Node.js 18 or newer:

```sh
just docs         # http://localhost:3000
just docs-check   # MDX, navigation and broken links, as the docs workflow runs
```

## Pull requests

Titles follow Conventional Commits: `<type>(<scope>): <summary>`, imperative, lowercase, at most 72 characters. A change to a flag, a JSON field, an exit code or an error code updates `docs/cli/expirely.mdx` or its page under `docs/reference` in the same pull request.

## Release

A release starts with a section for its version in `CHANGELOG.md`, with breaking changes under **Breaking**. Pushing a tag `vX.Y.Z` then runs `.github/workflows/release.yml`: it runs `just check-ci`, then GoReleaser builds the archives and `checksums.txt` and opens a draft GitHub release, which a maintainer reviews and publishes. `just snapshot` builds the same archives into `./dist` without publishing.
