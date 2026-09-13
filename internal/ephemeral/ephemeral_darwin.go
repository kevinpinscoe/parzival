//go:build darwin

package ephemeral

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ramSectors is the RAM-disk size in 512-byte sectors. 16384 = 8 MiB, ample for
// a rendered credential file and far below any real cost.
const ramSectors = "16384"

// newDir creates a fresh, per-invocation RAM disk, mounts it (hidden from
// Finder) at a private 0700 mountpoint, and returns a teardown that unmounts and
// detaches it. $TMPDIR on macOS is APFS (persistent, Time Machine-visible), so a
// RAM disk is the only way to keep the rendered secret off durable storage.
//
// newfs_hfs + a nobrowse mount is used rather than `diskutil erasevolume`, which
// is markedly slower.
func newDir() (*Dir, error) {
	// The mountpoint lives on APFS but stays empty until the RAM disk is mounted
	// over it, and is empty again after unmount — no secret ever lands on APFS.
	mp, err := os.MkdirTemp("", "parzival-")
	if err != nil {
		return nil, fmt.Errorf("ephemeral: create mountpoint: %w", err)
	}

	// Attach an unformatted RAM-backed block device (no root required).
	out, err := exec.Command("hdiutil", "attach", "-nomount", "ram://"+ramSectors).Output()
	if err != nil {
		os.Remove(mp)
		return nil, fmt.Errorf("ephemeral: hdiutil attach: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		os.Remove(mp)
		return nil, fmt.Errorf("ephemeral: hdiutil attach returned no device")
	}
	device := fields[0]

	detach := func() {
		if err := exec.Command("diskutil", "eject", device).Run(); err != nil {
			exec.Command("hdiutil", "detach", "-force", device).Run()
		}
	}

	// Lay down a filesystem, then mount it hidden from Finder at our mountpoint.
	if err := exec.Command("newfs_hfs", "-v", "parzival", device).Run(); err != nil {
		detach()
		os.Remove(mp)
		return nil, fmt.Errorf("ephemeral: newfs_hfs: %w", err)
	}
	if err := exec.Command("diskutil", "mount", "-mountPoint", mp, "-mountOptions", "nobrowse", device).Run(); err != nil {
		detach()
		os.Remove(mp)
		return nil, fmt.Errorf("ephemeral: diskutil mount: %w", err)
	}

	// Restrict the volume root to the owner (files are 0600 regardless).
	os.Chmod(mp, 0o700)

	return &Dir{
		path: mp,
		teardown: func() {
			detach()
			os.Remove(mp)
		},
	}, nil
}
