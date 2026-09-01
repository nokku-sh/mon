// Package tpm provides machine-bound signing identities backed by a TPM 2.0,
// with a machine-wrapped software fallback for machines without one.
//
// Two layers:
//
//   - [Key] is a deterministic TPM-resident ECDSA P-256 key ([crypto.Signer]).
//     OpenKey/NewKey create it directly for callers that manage their own
//     lifecycle, such as an SSH host key.
//   - [Signer] is a persisted machine identity ([crypto.Signer] plus
//     [io.Closer]): TPM-backed when a TPM is available, otherwise a software
//     key wrapped to the machine identity. NewSigner loads or creates it.
package tpm

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

const (
	// MethodTPM identifies a TPM-backed signing key.
	MethodTPM = "tpm"
	// MethodSoft identifies a software signing key wrapped to the machine.
	MethodSoft = "soft"
)

// Signer is a machine-bound signing identity. It is a [crypto.Signer]: sign
// SHA-256 digests with [Signer.Sign]; the TPM key template pins SHA-256.
type Signer interface {
	crypto.Signer
	io.Closer

	// Method reports the signing method: MethodTPM or MethodSoft.
	Method() string
	// PEM returns the PKIX PEM encoding of the public key.
	PEM() []byte
}

// SignerOptions configures [NewSigner].
type SignerOptions struct {
	// Salt namespaces the key derivation. Use one of the Salt* constants:
	// two purposes sharing a salt on the same machine share an identity.
	Salt []byte
	// Store persists the identity state. Only public material is stored for
	// TPM keys; software keys additionally carry their wrapped private key.
	Store Store
	// MachineID returns the stable machine identity used to wrap the
	// software fallback key, typically id.MachineID.
	MachineID func() string
	// RequireTPM refuses the software fallback: a missing TPM is an error.
	RequireTPM bool
	// RecoverIdentity recreates the signing key when the persisted identity
	// no longer matches the machine (TPM cleared or replaced, machine
	// re-imaged) instead of failing with [ErrIdentityChanged]. Interactive
	// CLIs set this; daemons whose enrollment is bound to the key leave it
	// false so the operator re-enrolls deliberately.
	RecoverIdentity bool
}

// ErrIdentityChanged signals that the machine's signing identity changed
// since the key was created. The caller must re-enroll or re-register the
// new public key. NewSigner returns it instead of recovering only when
// SignerOptions.RecoverIdentity is false.
var ErrIdentityChanged = errors.New("tpm: machine identity changed since the key was created")

// state is the on-disk representation of a signer. Only public material is
// stored for TPM keys. Software keys additionally carry their wrapped
// private key. The JSON shape matches the state files written by nokkud and
// nk before this package existed, so existing state keeps loading.
type state struct {
	Method string `json:"method"`
	PubKey string `json:"pubkey"`
	Salt   []byte `json:"salt,omitempty"`
	Nonce  []byte `json:"nonce,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

// NewSigner loads or creates the machine's signing identity: TPM when
// available, else a machine-wrapped software key (an error when
// RequireTPM is set).
func NewSigner(opts SignerOptions) (Signer, error) {
	if len(opts.Salt) == 0 {
		return nil, errors.New("tpm: salt is required")
	}
	if opts.Store == nil {
		return nil, errors.New("tpm: store is required")
	}

	st, err := loadState(opts.Store)
	if err != nil && !errors.Is(err, ErrNoState) {
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
	fallback, softErr := openSoft(opts, nil)
	if softErr != nil {
		return nil, errors.Join(fmt.Errorf("tpm: no TPM available: %w", tpmErr), softErr)
	}
	return fallback, nil
}

// loadState reads the persisted signer state. ErrNoState when absent.
func loadState(store Store) (*state, error) {
	data, err := store.Load()
	if err != nil {
		return nil, err
	}
	var st state
	if err = json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("tpm: parse signer state: %w", err)
	}
	return &st, nil
}

// saveState persists the signer state.
func saveState(store Store, st *state) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("tpm: serialize signer state: %w", err)
	}
	if err = store.Save(data); err != nil {
		return fmt.Errorf("tpm: write signer state: %w", err)
	}
	return nil
}

// openTPMIdentity opens the TPM device and derives the signing key for
// opts.Salt, verifying it against the persisted public half when st exists.
func openTPMIdentity(opts SignerOptions, st *state) (Signer, error) {
	dev, err := openTPMDevice()
	if err != nil {
		return nil, err
	}
	k, err := NewKey(dev, opts.Salt)
	if err != nil {
		_ = dev.Close()
		return nil, err
	}

	s := &tpmIdentity{key: k, pem: pemEncodePublicKey(k.Public())}

	// The persisted public half detects a TPM clear or replacement: the
	// derived key changes even though nothing was stored.
	if st != nil && st.PubKey != "" && st.PubKey != string(s.pem) {
		if !opts.RecoverIdentity {
			_ = s.Close()
			return nil, fmt.Errorf(
				"%w: the TPM key changed (TPM cleared or replaced); re-enroll to register the new key",
				ErrIdentityChanged,
			)
		}
		slog.Warn("tpm: TPM identity changed since last use, registering the new key")
	}
	if st == nil || st.PubKey != string(s.pem) {
		if err = saveState(opts.Store, &state{Method: MethodTPM, PubKey: string(s.pem)}); err != nil {
			_ = s.Close()
			return nil, err
		}
	}
	return s, nil
}

// tpmIdentity adapts a TPM [Key] to the [Signer] interface.
type tpmIdentity struct {
	key *Key
	pem []byte
}

func (s *tpmIdentity) Public() crypto.PublicKey { return s.key.Public() }

func (s *tpmIdentity) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, digest, opts)
}

func (s *tpmIdentity) Method() string { return MethodTPM }

func (s *tpmIdentity) PEM() []byte { return append([]byte(nil), s.pem...) }

func (s *tpmIdentity) Close() error { return s.key.Close() }

// pemEncodePublicKey returns the PKIX PEM encoding of pub.
func pemEncodePublicKey(pub crypto.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
