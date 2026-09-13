package store

import (
	"context"
	"fmt"
)

// OnePassword fetches secrets by shelling out to `op read`, which consumes a
// native op:// secret reference and manages its own session and unlock.
type OnePassword struct {
	run runner
	bin string
}

// NewOnePassword returns a 1Password backend that runs the real `op` binary.
func NewOnePassword() *OnePassword { return &OnePassword{run: execRunner{}, bin: "op"} }

// Name implements Store.
func (*OnePassword) Name() string { return "onepassword" }

// Capabilities implements Store.
func (*OnePassword) Capabilities() Capabilities {
	return Capabilities{
		EncryptedAtRest:   true,
		InteractiveUnlock: true,
		BackendAudit:      true,
	}
}

// Get implements Store. It runs `op read --no-newline <op://...>`; --no-newline
// makes op emit the raw value with no trailing newline.
func (p *OnePassword) Get(ctx context.Context, ref SecretRef) ([]byte, error) {
	out, err := p.run.run(ctx, p.bin, "read", "--no-newline", ref.Path)
	if err != nil {
		return nil, fmt.Errorf("onepassword: fetch %q via %s: %w", ref.Raw, p.bin, err)
	}
	return out, nil
}
