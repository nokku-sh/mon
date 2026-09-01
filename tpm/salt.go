package tpm

// The salts below are a cross-binary contract. Several Nokku binaries can run
// on the same machine and share one TPM: two purposes deriving keys with the
// same salt would silently share an identity. Every new purpose must get a
// distinct constant here. Never pass a local literal to OpenKey, NewKey or
// NewSigner.

const (
	// SaltDaemon namespaces nokkud's request-signing (DPoP) key.
	SaltDaemon = "nokku-daemon"
	// SaltCLI namespaces nk's request-signing (DPoP) key.
	SaltCLI = "nokku-cli"
	// SaltHost namespaces nokkud's SSH host identity key.
	SaltHost = "nokku-host"
	// SaltSSH namespaces nk's SSH agent identity key.
	SaltSSH = "nokku-ssh"
)
