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
	"strings"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/luks2"
	"golang.org/x/sys/unix"
)

// StorageContainer represents a LUKS2 storage container.
type StorageContainer interface {
	secboot.StorageContainer

	// Dev returns the device number for the LUKS2 storage container.
	// The major and minor components of this can be accessed with
	// unix.Major and unix.Minor.
	Dev() uint64

	// ActiveVolumeName returns the associated volume name if this
	// StorageContainer is active. If it isn't active, it is
	// expected to return a secboot.ErrStorageContainerNotActive
	// error.
	ActiveVolumeName(ctx context.Context) (string, error)

	// TODO: Add LUKS2 UUID / label accessors here as well.
}

type activateOptionKey string

const (
	volumeNameKey activateOptionKey = "volume-name"
)

type activateOptions map[any]any

func (o activateOptions) Add(key, value any) {
	o[key] = value
}

type volumeNameOption string

func (o volumeNameOption) ApplyTo(visitor secboot.ActivateOptionVisitor) {
	if _, ok := visitor.(activateOptions); !ok {
		panic("WithVolumeName can only be used for the luks2 backend")
	}
	visitor.Add(volumeNameKey, string(o))
}

// WithVolumeName is used to specify the volume name used to create the
// DM device when unlocking a LUKS2 container.
//
// XXX: It is mandatory for now for any [StorageContainer] managed by this
// package. A future revision will relax this requirement and support a
// mode where the volume name is created automatically, perhaps based on
// the UUID of the LUKS2 container. An automatically generated volume name
// can be retrieved afterwards using [StorageContainer.ActiveVolumeName].
func WithVolumeName(name string) secboot.ActivateOption {
	return volumeNameOption(name)
}

// storageContainerImpl is an implementation of [secboot.StorageContainer].
type storageContainerImpl struct {
	path string
	dev  uint64
}

// Dev implements [StorageContainer.Dev].
func (c *storageContainerImpl) Dev() uint64 {
	return c.dev
}

// ActiveVolumeName implements [StorageContainer.ActiveVolumeName].
func (c *storageContainerImpl) ActiveVolumeName(ctx context.Context) (string, error) {
	// To determine if this container is associated with an active volume,
	// and in order to obtain the volume name, we need to iterate over
	// the existing device mapper volumes to find any that are backed by
	// this storage container.
	dmDevices, err := filepath.Glob(filepath.Join(devRoot, "dm-*"))
	if err != nil {
		return "", fmt.Errorf("cannot build list of active dm devices: %w", err)
	}

	// Iterate over the list of active DM volumes.
	for _, path := range dmDevices {
		// Obtain a source device path from this DM volume path.
		sourcePath, err := sourceDeviceFromDMDevice(ctx, path)
		if err == errUnsupportedTargetType {
			// The table for this DM volume has a target type that we
			// don't recognize, so ignore it.
			continue
		}
		if err != nil {
			// We don't expect any other error here.
			return "", fmt.Errorf("cannot obtain source device path for dm volume %s: %w", path, err)
		}

		// We have a source block device path for this DM volume. Is it this StorageContainer?
		var st unix.Stat_t
		if err := unixStat(sourcePath, &st); err != nil {
			return "", &os.PathError{Op: "stat", Path: sourcePath, Err: err}
		}
		if st.Rdev != c.dev {
			// The source path for this DM volume is not related to this container
			// because they have different device numbers, so continue and try the
			// next DM volume.
			continue
		}

		// We've found a DM volume that is backed by this StorageContainer. Obtain
		// the name of the volume from sysfs.
		name, err := os.ReadFile(filepath.Join(sysfsRoot, "devices/virtual/block", filepath.Base(path), "dm/name"))
		if err != nil {
			return "", fmt.Errorf("cannot read volume name for %s: %w", path, err)
		}
		volumeName := strings.TrimRight(string(name), "\n") // The kernel adds a newline
		if volumeName == "" {
			// This should never happen as it's an invalid name, but, just in case...
			return "", fmt.Errorf("invalid empty volume name for %s", path)
		}

		// There should only ever be one DM volume backed by this storage container,
		// and this is enforced by libcryptsetup, so return the first one we find.
		return volumeName, nil
	}

	// There are no active DM volumes that are backed by this storage container.
	return "", secboot.ErrStorageContainerNotActive
}

// Path implements [secboot.StorageContainer.Path]
func (c *storageContainerImpl) Path() string {
	return c.path
}

// BackendName implements [secboot.StorageContainer.BackendName]
func (c *storageContainerImpl) BackendName() string {
	return storageContainerBackendName
}

// Activate implements [secboot.StorageContainer.Activate]
func (c *storageContainerImpl) Activate(ctx context.Context, ki secboot.KeyslotInfo, key []byte, opts ...secboot.ActivateOption) error {
	// TODO: Activate should require a temporary read lock (equivalent to OpenRead).
	optsCtx := make(activateOptions)
	for _, opt := range opts {
		opt.ApplyTo(optsCtx)
	}

	vn, exists := optsCtx[volumeNameKey]
	if !exists {
		// TODO: Relax this requirement and autogenerate a volume name.
		return errors.New("missing WithVolumeName option for LUKS2 container")
	}
	volumeName, ok := vn.(string)
	if !ok {
		return errors.New("invalid volume name")
	}

	slot := luks2.AnySlot
	if ki != nil {
		if lki, ok := ki.(*keyslotInfoImpl); ok {
			slot = lki.keyslotId
		}
	}

	if err := luks2Ops.Activate(volumeName, c.path, key, slot); err != nil {
		return fmt.Errorf("cannot activate container %s with volume name %q: %w", c.path, volumeName, err)
	}
	return nil
}

// Deactivate implements [secboot.StorageContainer.Deactivate]
func (c *storageContainerImpl) Deactivate(ctx context.Context) error {
	// TODO: Deactivate should require a temporary read lock (equivalent to OpenRead).

	// The StorageContainer only references the LUKS2 source device path
	// and source device number. We need the volume name in order to
	// deactivate it.
	volumeName, err := c.ActiveVolumeName(ctx)
	if err != nil {
		return fmt.Errorf("cannot obtain volume name: %w", err)
	}

	if err := luks2Ops.Deactivate(volumeName); err != nil {
		return fmt.Errorf("cannot deactivate volume %q: %w", volumeName, err)
	}

	return nil
}

// OpenRead implements [secboot.StorageContainer.OpenRead]
func (c *storageContainerImpl) OpenRead(ctx context.Context) (secboot.StorageContainerReader, error) {
	// TODO: Implment locking here, especially when we have the OpenReadWriter API. The locking
	// must prevent any readers being opened if a read/writer is open, and it must prevent more
	// than one read/writer being open at a time. Multiple readers can be open in parallel.
	return &storageContainerReader{
		impl: &storageContainerReadWriterImpl{container: c},
	}, nil
}
