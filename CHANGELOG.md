# Changelog

Every release of expirely, newest first. Until 1.0, a release can change flags, JSON fields and codes; each change that does is under **Breaking**, with what to do.

## Unreleased

### Added

- `--ca-file PATH` trusts the CA certificates in a PEM file on top of the system roots, so chains from an internal CA are `trusted`. A file that cannot be read or holds no certificate fails with `invalid_ca_file`.

### Fixed

- On macOS, a chain whose root the system does not know is reported as `unknown_authority` (`untrusted issuer` in text) instead of `invalid` (`not trusted`).

## v0.1.0 - 2026-11-26

The first release.

### Scan

- Scan targets given as `host`, `host:port`, `[ipv6]:port`, a bare IP or an `https://` URL, from arguments or from `--file` (one per line, `-` for stdin), with repeats scanned once.
- Read the whole chain a server sends, including expired, untrusted and mismatched chains, after a handshake bounded by `--timeout`, with `--concurrency` targets at once.
- Report each target as `expired`, `expiring` within `--warn-days`, `ok` or `error`, from the earliest `NotAfter` in its chain.
- Name why a chain is not trusted (`self_signed`, `unknown_authority`, `name_mismatch`, `expired`, `invalid`) and why a target failed, in a few words such as `connection refused` or `not a TLS server`.

### Output

- Text in a terminal: one line per target, most urgent first, with color, then the counts and the time the scan took, and a progress spinner on stderr for scans longer than 150 ms.
- JSON when stdout is not a terminal or with `--json`: a report that starts with `schema_version` and `summary`, keeps each result's leaf certificate, and adds the full chain with `--details`.
- AI agents: `AI_AGENT`, `AGENT` and Codex markers get JSON even on a terminal; other agent markers get text without color or spinner; `EXPIRELY_AGENT` turns this on or off; a usage error read by an agent carries the whole help.
- Errors: stable snake_case codes with a declarative `remediation`, and exit codes `0` ok, `1` expired or expiring, `2` usage, `3` a target could not be read.

### Install

- `go install github.com/bycavii/expirely-cli/cmd/expirely@v0.1.0`.
