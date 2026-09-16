# mon

mon is the shared primitives library for the Nokku binaries: machine signing
identities (`tpm`), DPoP proofing (`dpop`) and the authenticated connect
client stack (`dpopclient`), atomic file helpers (`fsutil`), and small id
utilities (`id`). It is consumed by nokkud and nk, not by nokku. The
ecosystem is five sibling repos: `nokku` (backend), `nokkud` (edge daemon),
`nk` (CLI), `mon` (this one), and `protos` (proto source). Read
`../nokku/docs/PRODUCT.md` before cross-repo work.

## Commands

```bash
task lint     # tidy, fmt, vet, govulncheck, test -race -cover, golangci-lint
task update   # go get -u ./...
```

Plain `go test ./...` works. CI lives in `.github/workflows/`.

## Layout

- `tpm` - machine signing identities: TPM-backed key or machine-wrapped
  software key, identity-change policies.
- `dpop` - DPoP (RFC 9449) proof creation.
- `dpopclient` - connect interceptor stack: proofing client, HTTP/2 client
  factory, nonce learning, and `NewProofer` wiring a tpm signer to a proofer.
- `fsutil` - atomic writes (`WriteFile`, `WriteIfChanged`) and JSON state
  helpers (`LoadJSON`, `SaveJSON`).
- `id` - small identity utilities.

## Conventions

- The salt registry is a convention documented in `README.md`
  (`nokku-daemon`, `nokku-daemon-host`, `nokku-cli`, `nokku-cli-ssh`). A new
  purpose needs a new salt, two purposes sharing a salt share an identity.
- Breaking changes need a version bump and both consumers (nokkud, nk)
  updated in the same change set.
- No product logic here. Primitives only. If it answers may-X or knows about
  targets, it belongs in an app repo.
- No generated code, no buf dependency.

## Danger points

- Never change a registered salt. It would silently rotate every machine
  identity derived from it.
