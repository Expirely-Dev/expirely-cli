# expirely

Find every TLS certificate you serve and when it expires.

expirely connects to each target, completes a TLS handshake, reads the certificate chain and closes the connection. It reports what is expired, what expires soon and what could not be read, in a table for people and in JSON for CI and agents. It sends no application data, holds no credentials and never touches a private key.

```sh
expirely example.com api.example.com:8443   # scan targets
expirely -f targets.txt --warn-days 21       # read targets from a file
kubectl get ingress -A -o jsonpath='{range .items[*].spec.tls[*].hosts[*]}{@}{"\n"}{end}' | expirely -f -
expirely --json example.com | jq '.results[] | select(.status != "ok")'
```

Exit code 1 means a certificate is expired or expiring, so the same command works as a CI gate or a cron alert.

## Status

expirely is in early development. Until 1.0, flags, JSON fields and codes can change between releases.

## Install

With Go 1.27 or newer:

```sh
go install github.com/bycavii/expirely-cli/cmd/expirely@latest
```

## Documentation

The documentation is at [bycavii.github.io/expirely-cli](https://bycavii.github.io/expirely-cli/). It covers targets and files, CI usage, every flag, the JSON output and every exit and error code. Its sources live in [`docs`](docs) and run locally with `just docs`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

expirely is licensed under [Apache-2.0](LICENSE).
