package store

import "context"

// Gopass is a placeholder backend. gopass support is planned (Phase 1 stretch)
// but not built yet; Get returns ErrUnimplemented so the reference syntax and
// resolver wiring exist ahead of the implementation.
type Gopass struct{}

// NewGopass returns the placeholder gopass backend.
func NewGopass() *Gopass { return &Gopass{} }

// Name implements Store.
func (*Gopass) Name() string { return "gopass" }

// Capabilities implements Store.
func (*Gopass) Capabilities() Capabilities {
	return Capabilities{
		EncryptedAtRest:   true,
		InteractiveUnlock: true,
	}
}

// Get implements Store. It is not yet implemented.
func (*Gopass) Get(context.Context, SecretRef) ([]byte, error) {
	return nil, ErrUnimplemented
}
