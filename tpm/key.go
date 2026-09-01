package tpm

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Key is a TPM-resident ECDSA P-256 key implementing [crypto.Signer].
//
// The key is a deterministic primary key. Reopening it with the same salt
// yields the same key pair until the TPM's owner seed changes (TPM clear or
// replacement). The private key never leaves the TPM.
type Key struct {
	tpm    transport.TPM
	closer transport.TPMCloser // nil when the caller owns the transport
	key    *primaryKey
	mu     sync.Mutex
}

// OpenKey opens the default TPM device and creates the primary key for salt.
// The Key owns the device: Close closes it.
func OpenKey(salt []byte) (*Key, error) {
	dev, err := openTPMDevice()
	if err != nil {
		return nil, err
	}
	k, err := NewKey(dev, salt)
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	k.closer = dev
	return k, nil
}

// NewKey creates the primary key for salt on an already open TPM. The
// returned Key does not own t.
func NewKey(t transport.TPM, salt []byte) (*Key, error) {
	key, err := createPrimary(t, salt)
	if err != nil {
		return nil, err
	}
	return &Key{tpm: t, key: key}, nil
}

// Public returns the ECDSA public key.
func (k *Key) Public() crypto.PublicKey {
	return k.key.pub
}

// Sign signs a SHA-256 digest and returns the DER-encoded ECDSA signature.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf(
			"tpm: unsupported hash %v (key template pins SHA-256)",
			opts.HashFunc(),
		)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return signECDSA(k.tpm, k.key, digest)
}

// Close flushes the key handle and closes the TPM transport if the Key owns
// it (see OpenKey).
func (k *Key) Close() error {
	var err error
	_, ferr := tpm2.FlushContext{FlushHandle: k.key.hnd}.Execute(k.tpm)
	err = errors.Join(err, ferr)
	if k.closer != nil {
		err = errors.Join(err, k.closer.Close())
	}
	return err
}
