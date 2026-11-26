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

The documentation lives in [`docs`](docs) and runs locally with [just](https://github.com/casey/just) and Node.js 18 or newer:

```sh
just docs   # http://localhost:3000
```

It covers targets and files, CI and cron, every flag, the JSON output and every exit and error code.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

expirely is licensed under [Apache-2.0](LICENSE).
