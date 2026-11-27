# AGENTS.md

Rules for agents working in this repository. User documentation is the Mintlify site in `docs/` (`docs.json` holds the navigation); the README stays short and points to it. Every page lives under `docs/cli/`, so its URL starts with `/cli/` and stays valid when other expirely products publish documentation on the same site. `expirely` is a read-only CLI: it inspects TLS certificates that other systems serve and reports when they expire.

## Contract

- Exit codes, error codes, flags and JSON field names are a public contract that CI pipelines and agents parse. A change to any of them updates its page under `docs/cli/commands` or `docs/cli/reference` in the same commit, and `just docs-check` passes; tests in `internal/cli` fail when a code or a flag in the usage text is missing there.
- `manifest.json` at the repository root is that contract as data: every command with its flags, the exit codes, the error codes with their cause and remediation, the statuses and the result fields. `TestManifest` in `internal/cli` builds it from the flag sets, the help texts and the code tables, and fails when the file differs, when a command parses a flag its help leaves out, or when the help documents one the command does not parse. After such a change, run `just manifest` and read the diff. The documentation site renders its reference tables from the manifest of the release it documents, so the description of a flag is written once, in the help text.
- Results go to stdout and errors to stderr. Output is JSON when `--json` is set or stdout is not a terminal; text otherwise. In JSON, an error is `{"error":{"message":"...","code":"..."}}`.
- Error codes are snake_case and live in one table in `internal/cli`; every error a command returns carries one of them.
- A value the scan could not read is `null` in JSON and `unknown` in text, never zero or a default date.

## Code

- `cmd/expirely` only wires the real streams and signals; behavior lives in `internal/` and is tested through `cli.Run` with a `Streams` value, asserting stdout, stderr and the exit code.
- Each resource family lives in its own directory under `internal/`: TLS in `internal/tls` (endpoint scan, ACM, Google Cloud, revocation). `internal/cli` holds only routing, flags, error codes and output, and `internal/ui` the text styling.
- Every network call takes a `context.Context` and has a deadline; concurrent scans run through a bounded pool whose goroutines all end before `Run` returns.
- Text for a person goes through `internal/ui`: a layout is written once as plain text and styling only wraps words, so a styled render without its escape codes equals the plain render (`TestWriteTextStyledIsPlainPlusEscapes`), and text from certificates or peers passes through `ui.Clean`. The text output's golden file is `internal/cli/testdata/text.golden`; regenerate it with `go test ./internal/cli -run TestWriteTextGolden -update` and read the diff.
- The tool reads certificates and nothing else: it never writes to a target, never sends credentials, and never handles private keys.
- Tests stay offline: they use local TLS listeners with certificates generated in the test, never the internet.
- The standard library comes first. A new module is pinned to an exact version with `go.sum` committed; each developer tool is pinned in its own `tools/<tool>/go.mod` and runs through the `justfile`. A module the binary links is under Apache-2.0, BSD, ISC or MIT with its license file; `just licenses-check`, part of `just check`, enforces it, and `just third-party-licenses` collects the files each release archive ships under `third-party/`.

## Before handing a change back

```sh
just fmt
just check
```

Commit titles follow Conventional Commits: `<type>(<scope>): <summary>`, imperative, lowercase, at most 72 characters. release-please reads them to choose the next version and write `CHANGELOG.md`: a new capability is `feat`, a defect `fix`, and a breaking change adds `!` and a `BREAKING CHANGE:` footer. `CHANGELOG.md` is written by the release pull request, not by hand.
