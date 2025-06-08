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

package secboot

import (
	"context"
	"errors"
	"fmt"
	"io"
)

var (
	ErrNoStorageContainer = errors.New("no storage container for path")
)

type ActivateOptionVisitor interface {
	Add(key, value any)
}

type ActivateOption interface {
	ApplyTo(ActivateOptionVisitor)
}

// KeyslotType describes the type of a keyslot.
type KeyslotType string

const (
	KeyslotTypePlatform KeyslotType = "platform"
	KeyslotTypeRecovery KeyslotType = "recovery"
)

// KeyslotInfo provides information about a keyslot.
type KeyslotInfo interface {
	Type() KeyslotType
	Name() string
	Priority() int
	Data() KeyDataReader
}

// StorageContainerReader provides a mechanism to perform read-only
// operations on keyslots on a storage container. The backend should
// permit as many of these to be opened as required, but should never
// permit one to be opened at the same time as a [StorageContainerWriter].
type StorageContainerReader interface {
	io.Closer

	// ListKeyslotNames returns a sorted list of keyslot names.
	ListKeyslotNames(ctx context.Context) ([]string, error)

	// ReadKeyslot returns information about the keyslot with
	// the specified name.
	ReadKeyslot(ctx context.Context, name string) (KeyslotInfo, error)
}

// StorageContainer represents some type of storage container that
// can store keyslots, making the core code in secboot agnostic to
// the storage backend.
type StorageContainer interface {
	Path() string // The path of this storage container.

	// BackendName is the name of the backend that created this
	// StorageContainer instance.
	BackendName() string

	// Activate unlocks this container with the specified key.
	// The keyslot info can be supplied so that the backend can
	// map the supplied key to a specific keyslot. If it is empty,
	// it will iterate and try all keyslots. The caller can specify
	// one or more options, which may be backend-specific.
	Activate(ctx context.Context, keyslotInfo KeyslotInfo, key []byte, opts ...ActivateOption) error

	// Deactivate locks this storage container.
	Deactivate(ctx context.Context) error

	// OpenRead opens this storage container in order to perform
	// operations to keyslots that only require read access. The backend
	// should permit as many of these to be opened as is requested, but
	// must not allow a combination of StorageContainerReader and
	// StorageContainerWriter to be opened (of which there should only
	// ever be 1 open at a time).
	OpenRead(ctx context.Context) (StorageContainerReader, error)
}

// NewStorageContainer creates a new StorageContainer from the specified
// path, probing each of the registered backends to obtain an appropriate
// instance. If no StorageContainer is found, a ErrNoStorageContainer error
// is returned.
func NewStorageContainer(ctx context.Context, path string) (StorageContainer, error) {
	for name, backend := range storageContainerHandlers {
		container, err := backend.Probe(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("cannot probe %q backend for path %q: %w", name, path, err)
		}
		if container != nil {
			return container, nil
		}
	}

	return nil, ErrNoStorageContainer
}
