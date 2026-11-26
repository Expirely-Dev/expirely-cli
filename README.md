# expirely

Find every TLS certificate you serve and when it expires.

```sh
$ expirely example.com expired.badssl.com self-signed.badssl.com wrong.host.badssl.com localhost:1
TARGET                      STATUS   DAYS     EXPIRES               TRUSTED  DETAIL
expired.badssl.com:443      expired  -4246    2015-04-12 23:59 UTC  no       issuer COMODO RSA Domain Validation Secure Server CA
localhost:1                 error    unknown  unknown               unknown  dial localhost:1: dial tcp [::1]:1: connect: connection refused
wrong.host.badssl.com:443   ok       31       2026-12-28 20:02 UTC  no       issuer YR1
example.com:443             ok       88       2027-02-22 23:53 UTC  yes      issuer Cloudflare TLS Issuing ECC CA 3
self-signed.badssl.com:443  ok       727      2028-11-23 21:00 UTC  no       issuer *.badssl.com

5 targets: 1 expired, 0 expiring, 1 unreadable, 3 ok
```

`expirely` connects to each target, completes a TLS handshake, reads the certificate chain and closes the connection. It sends no application data and no credentials. Expired, untrusted and mismatched chains are still read and reported.

## Install

```sh
go install github.com/bycavii/expirely-cli/cmd/expirely@latest
```

The documentation site is at [bycavii.github.io/expirely-cli](https://bycavii.github.io/expirely-cli/); its sources are in [`docs/`](docs/) and `just docs` serves them locally.

## Usage

```sh
expirely [flags] [TARGET...]
expirely -f targets.txt
kubectl get ingress -A -o jsonpath='{range .items[*].spec.tls[*].hosts[*]}{@}{"\n"}{end}' | expirely -f -
```

`TARGET` is `host`, `host:port`, `[ipv6]:port`, a bare IP address or an `https://` URL; the port defaults to 443. Other URL schemes, credentials in a URL and ports outside 1-65535 are rejected before anything is scanned.

Targets come from the arguments first, then from each `--file` in order. A file has one target per line; blank lines and lines starting with `#` are skipped, and `-` reads stdin. A target given twice is scanned once, at its first position. An invalid line stops the command before any scan and names the file and line.

| Flag | Default | Meaning |
|---|---|---|
| `--concurrency` | `16` | Targets scanned at once |
| `-f`, `--file` | | Read targets from a file, `-` for stdin; repeatable |
| `--json` | off | Print JSON; also the default when stdout is not a terminal |
| `--timeout` | `10s` | Time allowed per target to connect and complete the handshake |
| `--version` | | Print the version |
| `--warn-days` | `30` | Report certificates expiring within this many days as `expiring` |

A target's expiry is the earliest `NotAfter` in the chain it serves, so an intermediate that expires before the leaf is reported. Trust does not change the status: an untrusted chain that is far from expiry is `ok` with `trusted` false.

## Output

Results go to stdout and errors to stderr. Output is JSON when `--json` is set or stdout is not a terminal (a pipe, a file, CI), and text otherwise. Text output lists the most urgent targets first; JSON keeps the order the targets were given. `--help` is always text.

The JSON report:

| Field | Meaning |
|---|---|
| `scanned_at` | When the scan ran, RFC 3339 UTC |
| `warn_days` | The `--warn-days` value used |
| `summary` | Count of targets per status: `ok`, `expiring`, `expired`, `error` |
| `results[].target` | `host:port` as scanned |
| `results[].status` | `ok`, `expiring`, `expired` or `error` |
| `results[].days_left` | Whole days until `expires_at`, negative once expired; `null` on error |
| `results[].expires_at` | Earliest `NotAfter` in the chain; `null` on error |
| `results[].trusted` | Whether the chain verifies for the host against the system roots; `null` on error |
| `results[].verify_error` | Why the chain does not verify; `null` when it does or on error |
| `results[].leaf` | The leaf certificate: `subject`, `issuer`, `serial` (hex), `not_before`, `not_after`, `dns_names`; `null` on error |
| `results[].chain` | Every certificate the server sent, leaf first, with the same fields as `leaf`; `null` on error |
| `results[].error` | `{"code","message"}` when the target could not be read; `null` otherwise |

In JSON, `--version` prints `{"version":"..."}` and a command error is one line on stderr:

```json
{"error":{"code":"invalid_flag","message":"flag provided but not defined: -nope"}}
```

## Exit codes

When a scan has several outcomes, the lowest non-zero code in this order wins: 1, then 3.

| Code | Meaning |
|---|---|
| 0 | Every target is `ok`, or `--help` or `--version` ran |
| 1 | At least one certificate is `expired` or `expiring` |
| 2 | Usage error: bad flag, invalid target, unreadable `--file` or no targets |
| 3 | At least one target could not be read, or writing the output failed |

## Error codes

Scripts and agents match on `code`; a code is never renamed or reused.

| Code | Exit | Meaning |
|---|---|---|
| `invalid_flag` | 2 | A flag is unknown or has a bad value |
| `invalid_target` | 2 | A target is not a host, host:port or https:// URL |
| `missing_arguments` | 2 | No target was given in the arguments or files |
| `file_unreadable` | 2 | A `--file` could not be opened or read, or has a line over 64 KiB |
| `output_failed` | 3 | Writing the result to stdout failed, for example a closed pipe |
| `dial_failed` | 3 | `results[].error`: the TCP connection to the target failed |
| `handshake_failed` | 3 | `results[].error`: the TLS handshake failed or sent no certificate |

## Develop

```sh
just fmt
just check      # offline: gofmt, vet, golangci-lint, race tests, build, tidy
just check-ci   # what CI runs: check plus govulncheck
just fuzz       # fuzz the target parser for 60s (just fuzz 5m for longer)
just build      # build ./bin/expirely
just snapshot   # build every release archive into ./dist without publishing
```

## Release

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`: it runs `just check-ci`, then GoReleaser builds the archives and `checksums.txt` and creates a draft GitHub release. A maintainer reviews the draft and publishes it.

The repository rules for people and coding agents are in [AGENTS.md](AGENTS.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
