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
)

// StorageContainerBackend is an interface used by secboot to communicate
// with a backend that has support for a specific type of encrypted storage
// container.
type StorageContainerBackend interface {
	// Probe returns a StorageContainer instance for the supplied
	// path if it can be handled by this backend, else it returns
	// (nil, nil).
	Probe(ctx context.Context, path string) (StorageContainer, error)
}

var storageContainerHandlers = make(map[string]StorageContainerBackend)

// RegisterStorageContainerBackend permits a backend that manages storage containers
// with keyslots to be registered with and used by this package. Specifying a nil
// backend will delete the previously registered backend.
func RegisterStorageContainerBackend(name string, backend StorageContainerBackend) {
	if backend == nil {
		delete(storageContainerHandlers, name)
		return
	}

	storageContainerHandlers[name] = backend
}
