package dpopclient

import (
	"github.com/nokku-sh/mon/dpop"
	"github.com/nokku-sh/mon/tpm"
)

// NewProofer builds a DPoP proofer over a mon/tpm machine signer. The salt
// namespaces the derived key and must come from the registry documented in
// the mon README.
func NewProofer(
	salt []byte,
	statePath string,
	requireTPM bool,
	onIdentityChange tpm.IdentityChangePolicy,
) (*dpop.Proofer, error) {
	signer, err := tpm.NewSigner(tpm.SignerOptions{
		Salt:             salt,
		StatePath:        statePath,
		RequireTPM:       requireTPM,
		OnIdentityChange: onIdentityChange,
	})
	if err != nil {
		return nil, err
	}
	return dpop.NewProofer(signer, dpop.ProoferOptions{})
}
