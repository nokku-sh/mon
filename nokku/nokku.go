// Package nokku holds the constants shared by every Nokku binary
// (the nokkud daemon on downstream hosts and the nk CLI). They form a
// cross-binary contract: several binaries can run on the same machine and
// share one TPM, so every new purpose must get a distinct constant here.
// Never pass a local literal where one of these applies.
package nokku

// Signing key salts. Two purposes deriving TPM keys with the same salt
// would silently share an identity.
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
