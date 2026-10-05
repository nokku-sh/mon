package dpopclient

import (
	"github.com/nokku-sh/mon/dpop"
	"github.com/nokku-sh/mon/tpm"
)

// NewProofer builds a DPoP proofer over a mon/tpm machine signer. The salt in
// opts namespaces the derived key and must come from the registry documented
// in the mon README.
func NewProofer(opts tpm.SignerOptions) (*dpop.Proofer, error) {
	signer, err := tpm.NewSigner(opts)
	if err != nil {
		return nil, err
	}
	return dpop.NewProofer(signer, dpop.ProoferOptions{})
}
