# Contributing

Thanks for your interest in `mon`! It's a small Go library with no binaries,
shared by `nokkud` and `nk`.

## Prerequisites

- Go 1.x (see `go.mod`)
- [Task](https://taskfile.dev)
- [`golangci-lint`](https://golangci-lint.run)
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)

## Code style

Follow the conventions already in the codebase. Before opening a PR, run:

```bash
task lint
```

which runs `go mod tidy`, `go fmt`, `go vet`, `govulncheck`, the race test
suite, and `golangci-lint run --fix`.

## Tests

```bash
go test ./...
```

or via the lint task above. The TPM tests run against the go-tpm simulator
and skip when it cannot start. Please add tests for new behavior and keep the
existing suite green.

## Consumers

Every change here ships in both `nokkud` and `nk`. Exported API is their
contract, so treat a breaking change like one in any other library.

To try a change in the binaries before tagging, use a `go.work` in the parent
directory that points at your local `mon`. The protos README covers the
workflow and what CI sees. Check each consumer with `GOWORK=off go build
./...` once it pins the new version.

Never change a registered salt (see the README). It silently rotates every
machine identity derived from it.

## Releases

Releases are version tags (`vX.Y.Z`). Consumers pick them up with:

```bash
go get github.com/nokku-sh/mon@vX.Y.Z
```

## Submitting changes

1. Fork the repo and create a branch off `main`.
2. Make focused changes and run `task lint`.
3. Open a pull request describing what and why.

Keep changes small and scoped. If a change alters behavior, update the README
accordingly. Prefix commits with `feat:`, `fix:`, and so on.
