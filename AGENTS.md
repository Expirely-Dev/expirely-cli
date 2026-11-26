# AGENTS.md

Rules for agents working in this repository. `expirely` is a read-only CLI: it inspects TLS certificates that other systems serve and reports when they expire.

## Contract

- Exit codes, error codes, flags and JSON field names are a public contract that CI pipelines and agents parse. A change to any of them updates the README tables in the same commit.
- Results go to stdout and errors to stderr. Output is JSON when `--json` is set or stdout is not a terminal; text otherwise. In JSON, an error is `{"error":{"message":"...","code":"..."}}`.
- Error codes are snake_case and live in one table in `internal/cli`; every error a command returns carries one of them.
- A value the scan could not read is `null` in JSON and `unknown` in text, never zero or a default date.

## Code

- `cmd/expirely` only wires the real streams and signals; behavior lives in `internal/` and is tested through `cli.Run` with a `Streams` value, asserting stdout, stderr and the exit code.
- Every network call takes a `context.Context` and has a deadline; concurrent scans run through a bounded pool whose goroutines all end before `Run` returns.
- The tool reads certificates and nothing else: it never writes to a target, never sends credentials, and never handles private keys.
- Tests stay offline: they use local TLS listeners with certificates generated in the test, never the internet.
- The standard library comes first. A new module is pinned to an exact version with `go.sum` committed; developer tools are pinned in `tools/go.mod` and run with `go tool -modfile=tools/go.mod`.

## Before handing a change back

```sh
just fmt
just check
```

Commit titles follow Conventional Commits: `<type>(<scope>): <summary>`, imperative, lowercase, at most 72 characters.
