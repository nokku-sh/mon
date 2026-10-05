// Package tpm provides a machine-bound signing identity backed by a TPM 2.0,
// with a machine-wrapped software fallback for machines without one.
//
// [NewSigner] loads or creates the identity: a deterministic TPM-resident
// ECDSA P-256 key when the TPM is usable, otherwise a software P-256 key
// wrapped to the machine fingerprint. The private key never leaves the TPM
// in the first case and never leaves the machine in the second. Every caller
// namespaces its identity with [SignerOptions.Salt].
package tpm

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/google/go-tpm/tpm2/transport"
)

const (
	// MethodTPM identifies a TPM-backed signing key.
	MethodTPM = "tpm"
	// MethodSoft identifies a software signing key wrapped to the machine.
	MethodSoft = "soft"
)

// ErrIdentityChanged signals that the machine's signing identity changed
// since the key was created, so the caller must register the new public key.
var ErrIdentityChanged = errors.New("tpm: machine identity changed since the key was created")

// Signer is a machine-bound signing identity and a [crypto.Signer]. The TPM
// key template pins SHA-256, so sign SHA-256 digests.
type Signer interface {
	crypto.Signer
	io.Closer

	// Method reports the signing method, MethodTPM or MethodSoft.
	Method() string
	// PEM returns the PKIX PEM encoding of the public key.
	PEM() []byte
}

// SignerOptions configures [NewSigner].
type SignerOptions struct {
	// Salt namespaces the key derivation. Two purposes sharing a salt on one
	// machine share an identity, so every caller keeps its own constant.
	Salt []byte
	// StatePath is where the identity state is persisted. Only public
	// material is stored for TPM keys, software keys also carry their
	// wrapped private key.
	StatePath string
	// RequireTPM refuses the software fallback.
	RequireTPM bool
	// Recreate replaces the key and its state when the persisted identity no
	// longer matches the machine, instead of failing with
	// [ErrIdentityChanged]. Interactive callers set it so a re-image does not
	// brick them, and must then invalidate anything derived from the old
	// public key, such as certificates. Leave it unset where the identity is
	// bound to a server-side registration.
	Recreate bool
	// OpenTPM opens the TPM transport, defaulting to the platform device.
	// Tests inject a simulator. The signer owns the returned closer.
	OpenTPM func() (transport.TPMCloser, error)
}

// NewSigner loads or creates the machine's signing identity: a TPM key when
// one is usable, otherwise a machine-wrapped software key (an error when
// RequireTPM is set). The method is persisted, so an existing software
// identity is never silently upgraded to a TPM later.
func NewSigner(opts SignerOptions) (Signer, error) {
	if len(opts.Salt) == 0 {
		return nil, errors.New("tpm: salt is required")
	}
	if opts.StatePath == "" {
		return nil, errors.New("tpm: state path is required")
	}

	st, err := loadState(opts.StatePath)
	if err != nil && !errors.Is(err, errNoState) {
		return nil, err
	}

	if st != nil {
		switch st.Method {
		case MethodTPM:
			return openTPMIdentity(opts, st)
		case MethodSoft:
			if opts.RequireTPM {
				return nil, errors.New(
					"tpm: require-tpm is set but the machine is enrolled with a software key",
				)
			}
			return openSoft(opts, st)
		default:
			return nil, fmt.Errorf("tpm: unknown signer method %q", st.Method)
		}
	}

	s, tpmErr := openTPMIdentity(opts, nil)
	if tpmErr == nil {
		return s, nil
	}
	if opts.RequireTPM {
		return nil, fmt.Errorf("tpm: no TPM available: %w", tpmErr)
	}
	slog.Warn("no usable TPM, using a machine-wrapped software key", "error", tpmErr)
	fallback, softErr := openSoft(opts, nil)
	if softErr != nil {
		return nil, errors.Join(fmt.Errorf("tpm: no TPM available: %w", tpmErr), softErr)
	}
	return fallback, nil
}

// IdentityMethod reports the signing method persisted at statePath
// (MethodTPM or MethodSoft) without loading or creating any key material.
// It returns "" when no identity exists yet.
func IdentityMethod(statePath string) string {
	st, err := loadState(statePath)
	if err != nil || st == nil {
		return ""
	}
	return st.Method
}

// openTPMIdentity opens the TPM device and derives the signing key for
// opts.Salt, verifying it against the persisted public half when st exists.
func openTPMIdentity(opts SignerOptions, st *state) (Signer, error) {
	open := opts.OpenTPM
	if open == nil {
		open = openTPMDevice
	}
	dev, err := open()
	if err != nil {
		return nil, err
	}
	s, err := newTPMSigner(dev, opts.Salt)
	if err != nil {
		_ = dev.Close()
		return nil, err
	}

	// The persisted public half detects a TPM clear or replacement: the
	// derived key changes even though nothing was stored.
	if st != nil && st.PubKey != "" && st.PubKey != string(s.pem) {
		if !opts.Recreate {
			_ = s.Close()
			return nil, fmt.Errorf(
				"%w: the TPM key changed (TPM cleared or replaced), re-enroll to register the new key",
				ErrIdentityChanged,
			)
		}
		slog.Warn("tpm: TPM identity changed since last use, registering the new key")
	}
	if st == nil || st.PubKey != string(s.pem) {
		if err = saveState(opts.StatePath, &state{Method: MethodTPM, PubKey: string(s.pem)}); err != nil {
			_ = s.Close()
			return nil, err
		}
	}
	return s, nil
}

// pemEncodePublicKey returns the PKIX PEM encoding of pub.
func pemEncodePublicKey(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("tpm: encode public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
