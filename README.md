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
- **dpopclient** - the DPoP-authenticated connect client stack (interceptors,
  nonce and canonical-URL learning, one retry on a stale nonce) and the
  HTTP/2-only TLS 1.3 transport both binaries share.
- **fsutil** - atomic file writes: temp file, fsync, rename, parent-directory
  fsync, plus `WriteIfChanged` and `FileExists`.
- **id** - stable machine fingerprint from the hardware machine ID
  (hostname fallback), HMAC'd so the raw identifier is never exposed. Used
  only as the software signing key's wrap password.
- **tpm** - machine-bound ECDSA P-256 signing identities. `Signer` is a
  persisted identity, TPM-backed when a TPM 2.0 is usable with a
  machine-wrapped software fallback otherwise. `NewSigner` loads or creates
  it and `SignerOptions.Salt` namespaces the key per binary and purpose.

## Salts

`tpm` is generic and knows nothing about products: every binary that uses it
defines its own salt constants and passes them to `NewSigner`. When one
machine runs several Nokku binaries, their salts must differ per purpose or
two binaries would silently derive the same identity from the same TPM. The
salt registry is therefore a convention, not code: each binary owns its
constants, and new purposes get new constants there.

## Machine identity trust model

A TPM-backed identity cannot be extracted: the private key never leaves the
device. The primary is created without an auth value or PCR policy, so any
process that can open the TPM device (typically `/dev/tpmrm0`) can use the
identity. Restrict the device to the owning daemon's uid. A stored auth value
would have to live beside the caller's state file and buys nothing, and PCR
sealing breaks on kernel and firmware updates.

The software fallback wraps the key with a key derived from the machine's
public fingerprint (`id.MachineID`). That stops a key file copied to another
machine from working; it is not encryption against anyone who can read the
file on the machine itself. Set `SignerOptions.OnIdentityChange` to
`FailOnIdentityChange` where the identity is bound to a server-side
registration, so a TPM clear or a re-image makes the caller re-enroll instead
of silently presenting a new key.

## Testing

The TPM tests run against the in-process
[go-tpm simulator](https://github.com/google/go-tpm/tree/master/tpm2/transport/simulator)
and skip when it cannot start. `tpm.SignerOptions.OpenTPM` is the seam that
injects it.

## License

Apache License 2.0
