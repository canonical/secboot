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

var (
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
// The path can be the path to the LUKS2 source device, or a symbolic link to one.
//
// It identifies a [StorageContainer] by its device number, and it will always return
// the same instance for any paths that reference the same container, regardless of
// what path is supplied.
func (b *storageContainerBackend) Probe(ctx context.Context, path string) (secboot.StorageContainer, error) {
	// Use the luksview package to test if the supplied path is
	// a device or file containing a LUKS2 container.
	_, err := newLuksView(ctx, path)
	switch {
	case errors.Is(err, internal_luks2.ErrInvalidMagic):
		// We expect this error if the supplied path genuinely doesn't reference
		// a LUKS2 container. Return nothing in this case.
		return nil, nil
	case err != nil:
		// This error may indicate that the supplied device begins with what
		// looks like a LUKS2 header, but the header failed to parse for some
		// reason. Or it could be any other unexpected error. We'll return the
		// error in this case.
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

// ProbeActivated implements [secboot.StorageContainerBackend.ProbeActivated].
//
// The path can be the path to a DM device that is backed by a LUKS2 container, or
// a symbolic link to one.
//
// It identifies a [StorageContainer] by its device number, and it will always return
// the same instance for any paths that reference the same container, regardless of
// what path is supplied.
func (b *storageContainerBackend) ProbeActivated(ctx context.Context, path string) (secboot.StorageContainer, error) {
	// If we have a path to a DM device, walk the tables to find the
	// source LUKS2 container.
	for path != "" {
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
		}

		// The current path is a DM device and we have a source path
		// for it. Try using this with Probe.
		container, err := b.Probe(ctx, sourcePath)
		if err != nil {
			// We don't expect an error.
			return nil, err
		}

		if container != nil {
			// We've found the source LUKS2 storage container.
			return container, nil
		}

		// Try again
		path = sourcePath
	}

	return nil, nil
}

func init() {
	secboot.RegisterStorageContainerBackend(storageContainerBackendName, newStorageContainerBackend())
}
