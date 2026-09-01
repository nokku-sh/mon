# mon

Shared Go libraries for the [Nokku](https://github.com/nokku-sh) products.
`mon` (門, gate) holds the security primitives every Nokku binary shares so
they cannot drift apart: the daemon (`nokkud`) and the CLI (`nk`) both derive
their identities from the same machine TPM, so the crypto that does this must
have exactly one implementation.

## Packages

- **dpop** - client-side DPoP (RFC 9449) proof signing. Signs compact
  `dpop+jwt` proofs with an ECDSA P-256 signer, embedding the public JWK so
  the server can bind a session to the key thumbprint without pre-registration.
- **id** - stable machine fingerprint from the hardware machine ID
  (hostname fallback), HMAC'd so the raw identifier is never exposed. Used
  only as the software signing key's wrap password.
- **tpm** - machine-bound ECDSA P-256 signing identities:
  - `Key`: a deterministic TPM 2.0 primary key. The same salt on the same TPM
    always reproduces the same key pair; the private key never leaves the TPM.
  - `Signer`: a persisted machine identity, TPM-backed when available with a
    machine-wrapped software fallback. Salt options namespace keys per binary
    and per purpose.

## Salts

`tpm` is generic and knows nothing about products: every binary that uses it
defines its own salt constants and passes them into `OpenKey`, `NewKey` or
`NewSigner`. When one machine runs several Nokku binaries, their salts must
differ per purpose or two binaries would silently derive the same identity
from the same TPM. The salt registry is therefore a convention, not code:
each binary owns its constants, and new purposes get new constants there.

## Testing

The TPM tests run against the
[go-tpm simulator](https://github.com/google/go-tpm/tree/master/tpm2/transport/simulator)
(`go run github.com/google/go-tpm-tools/simulator` or a swtpm socket) and skip
when it is unreachable.

## License

Apache License 2.0
