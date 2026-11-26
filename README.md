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
just check
```

The repository rules for people and coding agents are in [AGENTS.md](AGENTS.md).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, `--help` or `--version` |
| 2 | Usage error: unknown flag or unexpected argument |
