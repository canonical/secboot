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
	"sync"
)

// StorageContainerBackend is an interface used by secboot to communicate
// with a backend that has support for a specific type of encrypted storage
// container.
type StorageContainerBackend interface {
	// Probe returns a StorageContainer instance for the supplied
	// path if it can be handled by this backend, else it returns
	// (nil, nil).
	//
	// Implementations should always return the same StorageContainer
	// instance for the same container referenced by the supplied path -
	// the implementation should at least handle the cases of symbolic
	// links and maybe any other cases where the supplied path has some
	// indirect relationship to a storage container.
	//
	// Implementations of this must be safe to call from any goroutine.
	Probe(ctx context.Context, path string) (StorageContainer, error)
}

var (
	storageContainerHandlersMu sync.Mutex
	storageContainerHandlers   = make(map[string]StorageContainerBackend)
)

// RegisterStorageContainerBackend permits a backend that manages storage containers
// with keyslots to be registered with and used by this package. Specifying a nil
// backend will delete the previously registered backend.
//
// XXX(chrisccoulson): Should we use a string to identify a backend or use any
// arbitrary comparable go type instead (in the same way that [context.Context]
// works)? I think I would prefer this (but perhaps it should be considered as
// these abstractions evolve). We can't do this for [RegisteredPlatformKeyDataHandler]
// because the platform name is serialized as a string in the keyslot metadata and has
// to be decoded later on in order to identify the platform - it's not possible to
// preserve go types in this case.
func RegisterStorageContainerBackend(name string, backend StorageContainerBackend) {
	storageContainerHandlersMu.Lock()
	defer storageContainerHandlersMu.Unlock()

	if backend == nil {
		delete(storageContainerHandlers, name)
		return
	}

	storageContainerHandlers[name] = backend
}
