// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package luks2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/snapcore/secboot"
	internal_luks2 "github.com/snapcore/secboot/internal/luks2"
	"golang.org/x/sys/unix"
)

type probeDepthKeyType struct{}

var (
	probeDepthKey = probeDepthKeyType{}

	devRoot              = "/dev"
	filepathEvalSymlinks = filepath.EvalSymlinks
	osStat               = os.Stat
	sysfsRoot            = "/sys"
	unixStat             = unix.Stat
)

const storageContainerBackendName = "luks2"

type storageContainerBackend struct {
	// mu is used to protect access to containers so that the
	// Probe() method is callable safely from multiple goroutines
	// (eg, it should be safe to call from more than 1 task in snapd).
	mu         sync.Mutex
	containers map[uint64]*storageContainerImpl
}

func newStorageContainerBackend() *storageContainerBackend {
	return &storageContainerBackend{
		containers: make(map[uint64]*storageContainerImpl),
	}
}

// Probe implements [secboot.StorageContainerBackend.Probe].
//
// The path can be the path to the LUKS2 source device, or a symbolic link to it, or it can
// be a path to an open DM volume that is backed by a LUKS2 storage device - this function
// will walk the DM tables in this case to find the underlying source device. It identifies
// a [StorageContainer] by its device number, and so it will always return the same instance
// for any paths that reference the same container, regardless of what type of path is supplied.
func (b *storageContainerBackend) Probe(ctx context.Context, path string) (secboot.StorageContainer, error) {
	// Use the luksview package to test if the supplied path is
	// a device or file containing a LUKS2 container.
	_, err := newLuksView(ctx, path)
	if err != nil {
		if errors.Is(err, internal_luks2.ErrInvalidMagic) {
			// We expect this error if the supplied path genuinely doesn't reference
			// a LUKS2 container. It's possible we were supplied a path to a DM
			// device, so walk the tree of tables to obtain a source device.
			sourcePath, err := sourceDeviceFromDMDevice(ctx, path)
			switch {
			case errors.Is(err, errNotDMBlockDevice):
				// Not a DM block device, so ignore this.
				return nil, nil
			case errors.Is(err, errUnsupportedTargetType):
				// Ignore DM block devices with unrecognized target types.
				return nil, nil
			case err != nil:
				// Any other type of error is unexpected, so return this.
				return nil, fmt.Errorf("cannot obtain source device for dm device %s: %w", path, err)
			default:
				// The supplied path is a DM device and we have a source path - try
				// again to see if we can find a LUKS2 header on the new source path.
				// Apply a depth limit here to avoid too much recursion. The permitted
				// depth here should be sufficient for lvm (linear) inside crypt or
				// the stack of DM devices associated with an in-progress reencrypt.
				var depth uint
				if d := ctx.Value(probeDepthKey); d != nil {
					depth = d.(uint)
					if depth > 10 {
						return nil, errors.New("path to dm device that is too deeply nested")
					}
				}
				ctx := context.WithValue(ctx, probeDepthKey, depth+1)
				return b.Probe(ctx, sourcePath)
			}
		}

		// The supplied device begins with what looks like a LUKS2 header,
		// but the header failed to parse for some reason. Treat the supplied
		// path as a path to a LUKS2 container and return an error in this
		// case.
		return nil, err
	}

	// The supplied path corresponds to a LUKS2 container. We want to return
	// a container with a resolved path rather than symbolic links, so do that
	// now.
	resolved, err := filepathEvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve symlink: %w", err)
	}

	// We map containers by device number so that we can return the same container
	// if it's probed again, even with a different path. Obtain that here.
	var st unix.Stat_t
	if err := unixStat(resolved, &st); err != nil {
		return nil, &os.PathError{Op: "stat", Path: resolved, Err: err}
	}

	// Find an existing container or create a new one.
	b.mu.Lock()
	defer b.mu.Unlock()
	container, exists := b.containers[st.Rdev]
	if !exists {
		container = &storageContainerImpl{
			path: resolved,
			dev:  st.Rdev,
		}
		b.containers[st.Rdev] = container
	}

	return container, nil
}

func init() {
	secboot.RegisterStorageContainerBackend(storageContainerBackendName, newStorageContainerBackend())
}
