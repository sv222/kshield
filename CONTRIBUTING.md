# Contributing to kshield

Thanks for your interest. Bug reports, fixes, new checks and docs are welcome.

## Before you start

- Open an issue first for a new check, a new report format or any large change.
- Report security issues privately. See [SECURITY.md](SECURITY.md).

## Setup

- Go: the version in `go.mod` or newer. The release toolchain is pinned in `versions.env` (`GO_VERSION`).
- Lint and security tools, at the versions in `versions.env`:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
```

```bash
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
```

## Build and test

```bash
go build -o kshield ./cmd/kshield
```

```bash
go test ./...
```

`scripts/check.sh` runs the full local check: gofmt, `go vet`, golangci-lint, `go test -race`, govulncheck and a cross-compile for linux, darwin and windows on amd64 and arm64. CI runs the same steps.

```bash
bash scripts/check.sh
```

Other scripts:

- `scripts/evidence-test.sh` builds the binary and runs an end-to-end check of a signed evidence pack.
- `scripts/helm-postrender-check.sh` checks the Helm post-renderer path (needs `helm`).
- `scripts/fetch-crds.sh` refreshes the vendored CRDs in `test/crds/` from the tags in `versions.env`.

## Kind integration tests

The tests in `test/kind/` run against a real API server. They use the build tag `kind` and need Docker and `kind` at `KIND_VERSION` from `versions.env`.

```bash
bash scripts/kind-test.sh
```

The script creates a Kind cluster named `kshield-test-<random>`, runs `go test -tags kind ./test/kind/...` against it and deletes it at the end.

## Test data

- `test/corpus/` holds manifest fixtures. Each case has an `input.yaml` and a hand-written `expected.yaml`.
- Write `expected.yaml` by hand before you look at the scanner output. A mismatch is a bug in the scanner until proven otherwise.
- `test/golden/` holds report golden files. Update them only when the change in output is intended.

## Rules

- Regulation mappings come only from the committed excerpts in `internal/regtext`.
- Pin exact versions of tools, images and actions. No floating tags.
- A security test needs a control that proves it can fail. Without a passing control the result is invalid, not a pass.
- Reports say "supports evidence for". kshield never claims compliance with a regulation.

## Pull requests

- One topic per pull request. Keep it small.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit subjects, for example `feat: add check for ...` or `fix: ...`.
- Add or update tests for every behavior change.
- Update `CHANGELOG.md` under `[Unreleased]`.
- Shell scripts use LF line endings.
- CI must pass.

By contributing you agree that your work is licensed under the Apache License 2.0.
