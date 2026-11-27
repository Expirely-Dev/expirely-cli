# expirely CLI

Know which certificate expires next, before your users do.

By 2029 a public TLS certificate lives 47 days at most (CA/Browser Forum ballot SC-081), and the ones renewed by hand are the ones that break. expirely checks your hosts, AWS accounts and Google Cloud projects and tells you what expires, when, and what still serves it.

```sh
expirely tls example.com api.example.com:8443
expirely tls -f hosts.txt
expirely tls aws --profile production
expirely tls gcp --project production
```

It only reads: a TLS handshake, or a few list calls to AWS or Google Cloud, plus a request for the CA's revocation list when `--revocation` asks for one. Exit code `1` means something needs renewing, so the same command gates CI, alerts from cron and gives AI agents JSON.

## Install

```sh
brew install expirely-dev/tap/expirely
```

Or with Go 1.27 or newer:

```sh
go install github.com/expirely-dev/expirely-cli/cmd/expirely@latest
```

Archives for Linux, macOS and Windows are on the [releases](https://github.com/expirely-dev/expirely-cli/releases) page.

## Documentation

The docs live in [`docs`](docs) and run with `just docs`. expirely is in early development; until 1.0 the [changelog](CHANGELOG.md) lists every change to flags, JSON and codes.

## License

[Apache-2.0](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) to contribute.
