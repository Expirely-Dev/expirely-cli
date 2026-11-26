# expirely

Find every TLS certificate you serve and when it expires.

Status: scaffolding. The command parses flags and prints its version; scanning is not implemented yet.

## Build

```sh
just build
./bin/expirely --version
```

## Develop

```sh
just fmt
just check      # offline: gofmt, vet, golangci-lint, race tests, build, tidy
just check-ci   # what CI runs: check plus govulncheck
just fuzz       # fuzz the target parser for 60s (just fuzz 5m for longer)
```

The repository rules for people and coding agents are in [AGENTS.md](AGENTS.md).

## Output

Results go to stdout and errors to stderr. Output is JSON when `--json` is set or stdout is not a terminal (a pipe, a file, CI), and text otherwise. `--help` is always text.

In JSON, `--version` prints `{"version":"..."}` and every error is one line on stderr:

```json
{"error":{"code":"invalid_flag","message":"flag provided but not defined: -nope"}}
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, `--help` or `--version` |
| 2 | Usage error: unknown flag, unexpected argument or nothing to do |
| 3 | The command was valid but could not finish |

## Error codes

Scripts and agents match on `code`; a code is never renamed or reused.

| Code | Exit | Meaning |
|---|---|---|
| `invalid_flag` | 2 | A flag is unknown or has a bad value |
| `unexpected_argument` | 2 | A positional argument the command does not accept |
| `missing_arguments` | 2 | No flag or argument was given |
| `output_failed` | 3 | Writing the result to stdout failed, for example a closed pipe |

## License

Apache License 2.0. See [LICENSE](LICENSE).
