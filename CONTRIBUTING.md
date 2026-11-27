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

Titles follow Conventional Commits: `<type>(<scope>): <summary>`, imperative, lowercase, at most 72 characters, because release-please reads them to choose the next version. A change to a flag, a JSON field, an exit code or an error code updates `docs/cli/expirely.mdx` or its page under `docs/reference` in the same pull request.

## Release

Releases are automated with [release-please](https://github.com/googleapis/release-please). Every push to `main` updates a release pull request that holds the next version and its `CHANGELOG.md` section, both computed from the commit titles since the last release:

- `feat` raises the minor version, `fix` and `perf` the patch version;
- before 1.0, a breaking change (`!` after the type, and a `BREAKING CHANGE:` footer) raises the minor version;
- `docs`, `build`, `ci`, `chore`, `refactor` and `test` release nothing and stay out of the changelog.

Merging the release pull request tags the version and publishes its GitHub release. The same workflow then runs `just check-ci`, collects the third-party licenses and lets GoReleaser attach the archives and `checksums.txt` to that release. `just snapshot` builds the same archives into `./dist` without publishing.

Since commit titles choose the version, CI rejects a title outside `<type>(<scope>): <summary>`; `just commit-check <range>` runs the same check locally.
