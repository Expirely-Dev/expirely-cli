# expirely

Know which certificate expires next, before your users find out.

An expired certificate takes a service down as completely as a crashed server, and it gives no warning: the site works at 23:59 and refuses every connection at 00:00. It is also getting more frequent. Under CA/Browser Forum ballot SC-081, the maximum life of a public TLS certificate falls from 398 days to 47 by 2029, so a certificate renewed once a year today will need renewing about eight times a year. Manual renewal does not survive that, and the certificates nobody automated are the ones that break.

expirely finds them. Point it at hosts, a list or an AWS account, and it answers one question: what expires, when, and what breaks with it.

```sh
expirely api.example.com example.com:8443
expirely -f hosts.txt
expirely aws --profile production --region us-east-1
```

## Why expirely

- It reads the whole chain a server sends. An intermediate that expires before the leaf takes the site down too, and expirely reports the first certificate in the chain to expire, not only the one on top.
- It finds the certificates AWS will never renew. ACM renews what it issues; it never renews an imported certificate. `expirely aws` lists both kinds, says which is which, and counts the resources, such as load balancers and CloudFront distributions, still serving each one that will not renew itself.
- It is the same command for a person, a pipeline and an AI agent. A terminal gets a short list, most urgent first. A pipe, CI or an agent gets JSON with stable codes, and exit code `1` when anything is expired or expiring, so one line gates a deploy or pages someone from cron.
- It only reads. It completes a TLS handshake and hangs up, sends no application data, holds no credentials of its own and never touches a private key. In AWS it calls `acm:ListCertificates` and `acm:DescribeCertificate`, nothing else.
- It is one static binary: no server, no daemon and no account to create.

## Install

With Go 1.27 or newer:

```sh
go install github.com/bycavii/expirely-cli/cmd/expirely@latest
```

Each [release](https://github.com/bycavii/expirely-cli/releases) also has archives for Linux, macOS and Windows on amd64 and arm64, with `checksums.txt`.

## Documentation

The documentation lives in [`docs`](docs) and runs locally with [just](https://github.com/casey/just) and Node.js 18 or newer:

```sh
just docs   # http://localhost:3000
```

It covers targets and files, internal CAs, AWS, CI and cron, every flag, the JSON output and every exit and error code.

## Status

expirely is in early development. Until 1.0, a release can change flags, JSON fields and codes, and the [changelog](CHANGELOG.md) says what to change.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

expirely is licensed under [Apache-2.0](LICENSE).
