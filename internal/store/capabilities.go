package store

// Capabilities describes which security properties a backend can support in
// its current configuration. The CLI uses this for reporting and doctor checks;
// policy enforcement still happens per request.
type Capabilities struct {
	EncryptedAtRest          bool
	NonAmbientBrokerAuth     bool
	ScopedStoreAuthorization bool
	ShortLivedCredential     bool
	BackendAudit             bool
	InteractiveUnlock        bool
	UnattendedBootstrap      bool
}

// StrongUnattended reports whether a backend has the properties needed for
// enforceable unattended use rather than only compatibility/runtime delivery.
func (c Capabilities) StrongUnattended() bool {
	return c.EncryptedAtRest &&
		c.NonAmbientBrokerAuth &&
		c.ScopedStoreAuthorization &&
		c.ShortLivedCredential &&
		c.BackendAudit &&
		c.UnattendedBootstrap
}
