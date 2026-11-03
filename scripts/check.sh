#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

step() {
    echo "== $* =="
}

step gofmt
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
    echo "$unformatted" >&2
    echo "check: gofmt: files above are not formatted" >&2
    exit 1
fi

step "go vet"
go vet ./...

step "go vet -tags kind"
go vet -tags kind ./...

step golangci-lint
golangci-lint run ./...

step "golangci-lint --build-tags kind"
golangci-lint run --build-tags kind ./...

step "go test -race"
go test -race -count=1 ./...

step govulncheck
govulncheck ./...

step "cross-compile"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
    goos=${target%/*}
    goarch=${target#*/}
    echo "build $goos/$goarch"
    CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -o /dev/null ./cmd/kshield
done

echo "check: OK"
