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
	ErrContainerClosed    = errors.New("storage container reader/writer is already closed")
	ErrKeyslotNotFound    = errors.New("keyslot not found")
	ErrNoStorageContainer = errors.New("no storage container for path")
)

// ActivateOptionVisitor is used for gathering options (using
// ActivateOption). Each backend shouls provide its own
// implementation of this.
type ActivateOptionVisitor interface {
	Add(key, value any)
}

// ActivateOption represents an option that can be supplied to
// StorageContainer.Activate.
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
	Data() KeyDataReader // TODO: This will eventually just be a io.Reader.
}

// StorageContainerReader provides a mechanism to perform read-only
// operations on keyslots on a storage container.
//
// The implementation does not need to be threadsafe - it should be
// used from a single goroutine. If access is needed on another
// goroutine, use the associated [StorageContainer] to open a new one.
//
// The backend should permit as many of these to be opened as required,
// but should never permit one to be opened at the same time as a
// [StorageContainerReadWriter].
type StorageContainerReader interface {
	// Container returns the StorageContainer that this reader
	// was opened from.
	Container() StorageContainer

	// io.Closer is used to close this reader.
	io.Closer

	// ListKeyslotNames returns a sorted list of keyslot names.
	ListKeyslotNames(ctx context.Context) ([]string, error)

	// ReadKeyslot returns information about the keyslot with
	// the specified name.
	ReadKeyslot(ctx context.Context, name string) (KeyslotInfo, error)
}

// StorageContainer represents some type of storage container that
// can store keyslots, making the core code in secboot agnostic to
// the storage backend. Implementation of this should be safe to
// access from multiple goroutines.
type StorageContainer interface {
	Path() string // The path of this storage container.

	// BackendName is the name of the backend that created this
	// StorageContainer instance.
	//
	// XXX: See the comment for RegisterStorageContainerBackend about
	// using something other than a string for identifying the storage
	// backend.
	BackendName() string

	// Activate unlocks this container with the specified key.
	// The caller can choose to supply the KeyslotInfo instance
	// related to the keyslot from which the supplied key is
	// associated with (obtained from StorageContainerReader.ReadKeyslot).
	// If supplied, the backend can use this to target the supplied
	// key at a specific keyslot. If keyslotInfo nil is supplied, the
	// backend will have to test all keyslots with the supplied key.
	// The caller can specify one or more options, which may be
	// backend-specific.
	Activate(ctx context.Context, keyslotInfo KeyslotInfo, key []byte, opts ...ActivateOption) error

	// Deactivate locks this storage container.
	Deactivate(ctx context.Context) error

	// OpenRead opens this storage container in order to perform
	// operations to keyslots that only require read access. The backend
	// should permit as many of these to be opened as is requested, but
	// must not allow a combination of StorageContainerReader and
	// StorageContainerReadWriter (when it exists) to be open at the same
	// time (and the backend should only permit one StorageContainerReadWriter
	// to be open at a time).
	OpenRead(ctx context.Context) (StorageContainerReader, error)
}

// NewStorageContainer creates a new StorageContainer from the specified
// path, probing each of the registered backends to obtain an appropriate
// instance. The path may or may not be a path to a block device, depending
// on the backends that are registered, because not all backends that may
// exist in the future will make use of block devices for a storage container.
//
// If no StorageContainer is found, a ErrNoStorageContainer error is returned.
//
// This is safe to call from multiple goroutines.
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
