# AGENTS.md

Rules for agents working in this repository. User documentation is the Mintlify site in `docs/` (`docs.json` holds the navigation); the README stays short and points to it. `expirely` is a read-only CLI: it inspects TLS certificates that other systems serve and reports when they expire.

## Contract

- Exit codes, error codes, flags and JSON field names are a public contract that CI pipelines and agents parse. A change to any of them updates `docs/cli/expirely.mdx` or its page under `docs/reference` in the same commit, and `just docs-check` passes; tests in `internal/cli` fail when a code or a flag in the usage text is missing there.
- Results go to stdout and errors to stderr. Output is JSON when `--json` is set or stdout is not a terminal; text otherwise. In JSON, an error is `{"error":{"message":"...","code":"..."}}`.
- Error codes are snake_case and live in one table in `internal/cli`; every error a command returns carries one of them.
- A value the scan could not read is `null` in JSON and `unknown` in text, never zero or a default date.

## Code

- `cmd/expirely` only wires the real streams and signals; behavior lives in `internal/` and is tested through `cli.Run` with a `Streams` value, asserting stdout, stderr and the exit code.
- Every network call takes a `context.Context` and has a deadline; concurrent scans run through a bounded pool whose goroutines all end before `Run` returns.
- The tool reads certificates and nothing else: it never writes to a target, never sends credentials, and never handles private keys.
- Tests stay offline: they use local TLS listeners with certificates generated in the test, never the internet.
- The standard library comes first. A new module is pinned to an exact version with `go.sum` committed; each developer tool is pinned in its own `tools/<tool>/go.mod` and runs through the `justfile`.

## Before handing a change back

```sh
just fmt
just check
```

Commit titles follow Conventional Commits: `<type>(<scope>): <summary>`, imperative, lowercase, at most 72 characters.
