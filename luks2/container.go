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

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/luks2"
)

// StorageContainer represents a LUKS2 storage container.
type StorageContainer interface {
	secboot.StorageContainer // Common to all StorageContainer implementations.

	// Dev returns the device number for the LUKS2 storage container.
	// The major and minor components of this can be accessed with
	// unix.Major and unix.Minor.
	Dev() uint64

	// TODO: Add LUKS2 UUID / label accessors here as well.
}

// storageContainerImpl is an implementation of [secboot.StorageContainer].
type storageContainerImpl struct {
	// path is the canonical path of the device node for this
	// storage container.
	path string

	// dev is the unix device number for this storage container.
	dev uint64
}

// Dev implements [StorageContainer.Dev].
func (c *storageContainerImpl) Dev() uint64 {
	return c.dev
}

// Path implements [secboot.StorageContainer.Path]
func (c *storageContainerImpl) Path() string {
	return c.path
}

// CredentialName implements [secboot.StorageContainer.CredentialName]
func (c *storageContainerImpl) CredentialName() string {
	return c.path
}

// BackendName implements [secboot.StorageContainer.BackendName]
func (c *storageContainerImpl) BackendName() string {
	return storageContainerBackendName
}

// Activate implements [secboot.StorageContainer.Activate]
func (c *storageContainerImpl) Activate(ctx context.Context, ks secboot.Keyslot, key []byte, cfg secboot.ActivateConfigGetter) error {
	// TODO: Activate should require a temporary read lock (equivalent to OpenRead).
	volumeName, exists := secboot.ActivateConfigGet[string](cfg, volumeNameKey)
	if !exists {
		// TODO: Relax this requirement and autogenerate a volume name.
		return errors.New("missing WithVolumeName option for LUKS2 container")
	}

	slot := luks2.AnySlot
	if ks != nil {
		if lks, ok := ks.(Keyslot); ok {
			slot = lks.PreferredKeyslotId()
		}
	}

	if err := luks2Ops.Activate(volumeName, c.path, key, slot); err != nil {
		return fmt.Errorf("cannot activate container %s with volume name %q: %w", c.path, volumeName, err)
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
