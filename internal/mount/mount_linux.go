//go:build linux

// Package mount implements `parzival mount`: a FUSE filesystem that exposes one
// read-only virtual credential file per profile. Each open() runs the approval
// policy, fetches the secret(s) fresh, renders the profile template, and serves
// the result from memory — nothing is ever written to disk. Content is served
// with FOPEN_DIRECT_IO so it is never page-cached and every open re-fetches.
package mount

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/kevinpinscoe/parzival/internal/policy"
	"github.com/kevinpinscoe/parzival/internal/profile"
	"github.com/kevinpinscoe/parzival/internal/secret"
	"github.com/kevinpinscoe/parzival/internal/store"
)

// Serve mounts a parzival credential filesystem at mountpoint and blocks until it
// is unmounted or the process receives SIGINT/SIGTERM. identity is the policy
// label applied to every open() on this mount (from `mount --as`).
func Serve(mountpoint, identity string) error {
	root := &rootNode{identity: identity}
	server, err := fs.Mount(mountpoint, root, &fs.Options{
		MountOptions: fuse.MountOptions{
			FsName:     "parzival",
			Name:       "parzival",
			AllowOther: false, // owner-only
		},
	})
	if err != nil {
		return fmt.Errorf("mount %s: %w", mountpoint, err)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		_ = server.Unmount()
	}()

	fmt.Fprintf(os.Stderr, "parzival: mounted at %s (one file per profile; Ctrl-C to unmount)\n", mountpoint)
	server.Wait()
	return nil
}

// rootNode is the mount root: it lists profiles as read-only virtual files.
type rootNode struct {
	fs.Inode
	identity string
}

var (
	_ = (fs.NodeReaddirer)((*rootNode)(nil))
	_ = (fs.NodeLookuper)((*rootNode)(nil))
)

func (r *rootNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	names, err := profileNames()
	if err != nil {
		return nil, syscall.EIO
	}
	entries := make([]fuse.DirEntry, 0, len(names))
	for _, n := range names {
		entries = append(entries, fuse.DirEntry{Name: n, Mode: fuse.S_IFREG})
	}
	return fs.NewListDirStream(entries), 0
}

func (r *rootNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if _, err := profile.Load(name); err != nil {
		return nil, syscall.ENOENT
	}
	out.Mode = 0o400
	child := &credFile{profileName: name, identity: r.identity}
	return r.NewInode(ctx, child, fs.StableAttr{Mode: fuse.S_IFREG}), 0
}

// credFile is a virtual file backed by a profile.
type credFile struct {
	fs.Inode
	profileName string
	identity    string
}

var (
	_ = (fs.NodeOpener)((*credFile)(nil))
	_ = (fs.NodeReader)((*credFile)(nil))
	_ = (fs.NodeGetattrer)((*credFile)(nil))
	_ = (fs.NodeReleaser)((*credFile)(nil))
)

type credHandle struct{ data []byte }

func (c *credFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if int(flags)&(os.O_WRONLY|os.O_RDWR) != 0 {
		return nil, 0, syscall.EACCES // read-only
	}
	data, errno := c.materialize(ctx)
	if errno != 0 {
		return nil, 0, errno
	}
	// DIRECT_IO: no page cache, so the plaintext is never cached and every open
	// re-runs policy + re-fetches.
	return &credHandle{data: data}, fuse.FOPEN_DIRECT_IO, 0
}

func (c *credFile) Read(ctx context.Context, f fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h, ok := f.(*credHandle)
	if !ok {
		return nil, syscall.EIO
	}
	if off >= int64(len(h.data)) {
		return fuse.ReadResultData(nil), 0
	}
	end := off + int64(len(dest))
	if end > int64(len(h.data)) {
		end = int64(len(h.data))
	}
	return fuse.ReadResultData(h.data[off:end]), 0
}

func (c *credFile) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = 0o400
	if h, ok := f.(*credHandle); ok {
		out.Size = uint64(len(h.data))
	}
	return 0
}

func (c *credFile) Release(ctx context.Context, f fs.FileHandle) syscall.Errno {
	if h, ok := f.(*credHandle); ok {
		secret.Zero(h.data)
	}
	return 0
}

// materialize authorizes and fetches the profile's secrets, then renders the
// template. The per-open caller (uid/pid/exe) is recorded in the audit log as
// provenance but is not used to gate the request.
func (c *credFile) materialize(ctx context.Context) ([]byte, syscall.Errno) {
	prof, err := profile.Load(c.profileName)
	if err != nil {
		return nil, syscall.ENOENT
	}
	caller := callerString(ctx)
	now := time.Now()

	secrets := make(map[string][]byte, len(prof.Secrets))
	defer func() {
		for _, v := range secrets {
			secret.Zero(v)
		}
	}()

	for name, ref := range prof.Secrets {
		parsed, err := store.ParseRef(ref)
		if err != nil {
			return nil, syscall.EIO
		}
		if err := policy.Authorize(policy.Request{Ref: parsed.Raw, Identity: c.identity, Mode: policy.ModeMount, Time: now, Caller: caller}); err != nil {
			return nil, syscall.EACCES
		}
		backend, err := store.Resolve(parsed)
		if err != nil {
			return nil, syscall.EIO
		}
		val, err := backend.Get(ctx, parsed)
		if err != nil {
			return nil, syscall.EIO
		}
		secrets[name] = val
	}

	rendered, err := prof.Render(secrets)
	if err != nil {
		return nil, syscall.EIO
	}
	return rendered, 0
}

// callerString formats the FUSE caller for the audit log.
func callerString(ctx context.Context) string {
	fc, ok := fuse.FromContext(ctx)
	if !ok {
		return ""
	}
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", fc.Pid))
	return fmt.Sprintf("uid=%d pid=%d exe=%s", fc.Uid, fc.Pid, exe)
}

// profileNames lists the profile names (without .json) in the profiles directory.
func profileNames() ([]string, error) {
	entries, err := os.ReadDir(profile.Dir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	sort.Strings(names)
	return names, nil
}
