# Changelog

Every release of expirely, newest first. From v0.4.0 on, release-please writes this file from the commit titles. Until 1.0, a release can change flags, JSON fields and codes; such a change is listed as breaking, with what to do.

## [0.10.0](https://github.com/Expirely-Dev/expirely-cli/compare/v0.9.0...v0.10.0) (2026-11-27)


### ⚠ BREAKING CHANGES

* **cli:** remove the deprecated aws, gcp and bare-target forms ([#10](https://github.com/Expirely-Dev/expirely-cli/issues/10))
* report certificates without an end date as unknown ([#9](https://github.com/Expirely-Dev/expirely-cli/issues/9))
* **output:** give every json result a common envelope ([#7](https://github.com/Expirely-Dev/expirely-cli/issues/7))

### Added

* **cli:** describe the public contract in manifest.json ([#15](https://github.com/Expirely-Dev/expirely-cli/issues/15)) ([af6605e](https://github.com/Expirely-Dev/expirely-cli/commit/af6605ef45ea288af4ef80d45937a9aeb5f7f196))
* **cli:** remove the deprecated aws, gcp and bare-target forms ([#10](https://github.com/Expirely-Dev/expirely-cli/issues/10)) ([0b776e2](https://github.com/Expirely-Dev/expirely-cli/commit/0b776e2a2d312afbc99bc2dd0e42a19795717d81))
* **output:** give every json result a common envelope ([#7](https://github.com/Expirely-Dev/expirely-cli/issues/7)) ([95f84f7](https://github.com/Expirely-Dev/expirely-cli/commit/95f84f745a95a3e6dc2261fe744ba75ded2bd77a))
* **tls:** check revocation against crls with --revocation ([#11](https://github.com/Expirely-Dev/expirely-cli/issues/11)) ([7b5ce69](https://github.com/Expirely-Dev/expirely-cli/commit/7b5ce69b923ca262cfc6033a05677ab666691a31))


### Fixed

* **cli:** gate revocation on trust, add revoked status, mend help ([#13](https://github.com/Expirely-Dev/expirely-cli/issues/13)) ([fda985f](https://github.com/Expirely-Dev/expirely-cli/commit/fda985fca7c933ee6f2398cac4ea92984dadc3de))
* report certificates without an end date as unknown ([#9](https://github.com/Expirely-Dev/expirely-cli/issues/9)) ([cf65b73](https://github.com/Expirely-Dev/expirely-cli/commit/cf65b73c7f67a314e803f8374f28377c17b0536b))

## [0.9.0](https://github.com/Expirely-Dev/expirely-cli/compare/v0.8.0...v0.9.0) (2026-11-27)


### Added

* move every check under expirely tls ([83ac4a3](https://github.com/Expirely-Dev/expirely-cli/commit/83ac4a3e04a0a70e28eb4ed1a2f4387d0ddfbd28))

## [0.8.0](https://github.com/Expirely-Dev/expirely-cli/compare/v0.7.0...v0.8.0) (2026-11-27)


### ⚠ BREAKING CHANGES

* move to the expirely-dev organization

### Chores

* move to the expirely-dev organization ([3981b89](https://github.com/Expirely-Dev/expirely-cli/commit/3981b8984ef77f0de5d41c63a0dac83d97f9b7c6))

## [0.7.0](https://github.com/bycavii/expirely-cli/compare/v0.6.0...v0.7.0) (2026-11-27)


### Added

* **aws:** read every enabled region with --region all ([cd7f1b3](https://github.com/bycavii/expirely-cli/commit/cd7f1b33c87e3cb173f4285178ad38a671bb8d05))
* write a job summary and annotations in github actions ([cb84576](https://github.com/bycavii/expirely-cli/commit/cb845769c8e769f69824d105715bb63ba8ea9768))


### Fixed

* **aws:** find the enabled regions with ec2:DescribeRegions ([9009144](https://github.com/bycavii/expirely-cli/commit/900914444495dadbe7339c49d0bc7a4232c56a35))
* name unknown flags as typed and suggest the closest one ([2340409](https://github.com/bycavii/expirely-cli/commit/2340409c7f8edbb5697193f2782fd65d7957dbdf))

## [0.6.0](https://github.com/bycavii/expirely-cli/compare/v0.5.0...v0.6.0) (2026-11-27)


### Breaking changes

* JSON results come most urgent first instead of in the order the targets were given; sort on `target` to restore the old order.
* A declared AI agent (`EXPIRELY_AGENT`, `AI_AGENT`, `AGENT` or a Codex marker) now gets `expired`, `expiring` and `error` results by default; pass `--status all` to get every status. The `summary` counts and the exit code still cover every result.

### Added

* add --status, --fields and --limit to every command ([fdc89c7](https://github.com/bycavii/expirely-cli/commit/fdc89c7705bee8bc6a0031e59bd3c04a0ee2bc7f))
* **gcp:** report the regions google cannot reach instead of failing ([fc0b500](https://github.com/bycavii/expirely-cli/commit/fc0b500180403ae4e9b752a5c9899bf0805c669c))
* show a spinner while expirely aws and gcp read the cloud ([4714cad](https://github.com/bycavii/expirely-cli/commit/4714cad51e3dbef7f7a93d9d3209be715c4bc64e))

## [0.5.0](https://github.com/bycavii/expirely-cli/compare/v0.4.0...v0.5.0) (2026-11-27)


### Added

* **gcp:** read certificate manager certificates in every location ([df5d1a0](https://github.com/bycavii/expirely-cli/commit/df5d1a0538fbc599d3ec530a4c63a539f517f3c9))


### Fixed

* **gcp:** report a project with compute or billing disabled ([a96e90a](https://github.com/bycavii/expirely-cli/commit/a96e90aa1a66fd1827f565f64bc5ec9accf10a45))
* stop on ctrl-c and share one command plumbing ([f02c2a7](https://github.com/bycavii/expirely-cli/commit/f02c2a7cd78e610da42ca8f5cb7692c0d746e6ed))

## [0.4.0](https://github.com/bycavii/expirely-cli/compare/v0.3.0...v0.4.0) (2026-11-27)


### Added

* **gcp:** list compute ssl certificates with expirely gcp ([0de7f0a](https://github.com/bycavii/expirely-cli/commit/0de7f0a4d4c6362c2e5b92206a107821efb7ebf9))

## v0.3.0 - 2026-11-26

### Added

- `expirely aws` lists every certificate in AWS Certificate Manager for one account and region, of every key type, with its status, days left and whether ACM renews it: a certificate ACM does not renew, imported or no longer eligible, names how many resources use it, and those in use come first. It reads with `acm:ListCertificates` and `acm:DescribeCertificate` only. New codes: `aws_not_configured`, `aws_access_denied`, `aws_request_failed`.
- Release archives carry the license, notice and patent files of Go and of every module the binary links, under `third-party/`.

## v0.2.0 - 2026-11-26

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
