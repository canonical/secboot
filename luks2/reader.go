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
	"fmt"
	"sort"

	"github.com/snapcore/secboot"
)

// storageContainerReadWriterImpl is the main implementation that backs
// any StorageContainerReader and (eventually) StorageContainerReadWriter
// interfaces.
type storageContainerReadWriterImpl struct {
	container *storageContainerImpl
	keyslots  map[string]*keyslotInfoImpl
}

func (s *storageContainerReadWriterImpl) ensureKeyslotNames() error {
	if s.keyslots != nil {
		return nil
	}

	keyslots := make(map[string]*keyslotInfoImpl)

	names, err := luks2Ops.ListUnlockKeyNames(s.container.Path())
	if err != nil {
		return err
	}
	for _, name := range names {
		keyslots[name] = &keyslotInfoImpl{
			keyslotType: secboot.KeyslotTypePlatform,
			keyslotName: name,
		}
	}

	names, err = luks2Ops.ListRecoveryKeyNames(s.container.Path())
	if err != nil {
		return err
	}
	for _, name := range names {
		// The existing secboot API doesn't map keyslot names to LUKS2 keyslot
		// IDs for recovery keyslots. We will eventually do that when this package
		// natively supports LUKS2 rather than using the legacy secboot APIs.
		keyslots[name] = &keyslotInfoImpl{
			keyslotType: secboot.KeyslotTypeRecovery,
			keyslotName: name,
		}
	}

	s.keyslots = keyslots
	return nil
}

func (s *storageContainerReadWriterImpl) Container() secboot.StorageContainer {
	return s.container
}

func (s *storageContainerReadWriterImpl) Close() error {
	// TODO: This does nothing for now but will eventually release a lock (see the
	// comment in storageContainer.OpenRead).
	return nil
}

func (s *storageContainerReadWriterImpl) ListKeyslotNames(ctx context.Context) ([]string, error) {
	if err := s.ensureKeyslotNames(); err != nil {
		return nil, err
	}

	var names []string
	for name := range s.keyslots {
		names = append(names, name)
	}
	sort.Strings(names)

	return names, nil
}

func (s *storageContainerReadWriterImpl) ReadKeyslot(ctx context.Context, name string) (secboot.KeyslotInfo, error) {
	if err := s.ensureKeyslotNames(); err != nil {
		return nil, err
	}

	info, exists := s.keyslots[name]
	if !exists {
		return nil, secboot.ErrKeyslotNotFound
	}

	switch info.keyslotType {
	case secboot.KeyslotTypeRecovery:
		// The existing secboot API doesn't expose the LUKS2 keyslot ID so we
		// use the luksview package directly, via a bit of an abstraction so that
		// it can be mocked in unit tests. This will all be cleaned up eventually
		// once all of this functionality is implemented natively in this package.
		view, err := newLuksView(ctx, s.container.Path())
		if err != nil {
			return nil, fmt.Errorf("cannot obtain new luksview.View: %w", err)
		}
		token, _, inUse := view.TokenByName(name)
		if !inUse {
			return nil, fmt.Errorf("no metadata for keyslot %q", name)
		}
		info.keyslotId = token.Keyslots()[0] // luksview guarantees there is always 1 keyslot here.
	case secboot.KeyslotTypePlatform:
		r, err := luks2Ops.NewKeyDataReader(s.container.Path(), name)
		if err != nil {
			return nil, fmt.Errorf("cannot obtain reader for %q: %w", name, err)
		}
		info.keyslotId = r.KeyslotID()
		info.keyslotPriority = r.Priority()
		info.keyslotData = r
	default:
		panic("not reached")
	}

	return info, nil
}

// closedStorageContainerReadWriterImpl is an implementation of StorageContainerReader
// and (eventually) StorageContainerReadWriter that just returns
// secboot.ErrStorageContainerClosed for every method.
type closedStorageContainerReadWriterImpl struct{}

func (*closedStorageContainerReadWriterImpl) Container() secboot.StorageContainer {
	return nil
}

func (*closedStorageContainerReadWriterImpl) Close() error {
	return secboot.ErrStorageContainerClosed
}

func (*closedStorageContainerReadWriterImpl) ListKeyslotNames(_ context.Context) ([]string, error) {
	return nil, secboot.ErrStorageContainerClosed
}

func (*closedStorageContainerReadWriterImpl) ReadKeyslot(_ context.Context, _ string) (secboot.KeyslotInfo, error) {
	return nil, secboot.ErrStorageContainerClosed
}

// storageContainerReader is an implementation of [secboot.StorageContainerReader].
type storageContainerReader struct {
	// impl is an extra indirection that permits us to block access
	// the real container after it's been closed and any associated
	// lock has been released - it does this by having the io.Closer
	// implementation swapping impl with an instance that returns a
	// secboot.ErrStorageContainerClosed error for each method.
	impl secboot.StorageContainerReader
}

// Container implements [secboot.StorageContainerReader.Container].
func (s *storageContainerReader) Container() secboot.StorageContainer {
	return s.impl.Container()
}

// Close implements [io.Closer].
func (s *storageContainerReader) Close() error {
	if err := s.impl.Close(); err != nil {
		return err
	}

	s.impl = new(closedStorageContainerReadWriterImpl)
	return nil
}

// ListKeyslotNames implements [secboot.StorageContainerReader.ListKeyslotNames].
func (s *storageContainerReader) ListKeyslotNames(ctx context.Context) ([]string, error) {
	return s.impl.ListKeyslotNames(ctx)
}

// ReadKeyslot implements [secboot.StorageContainerReader.ListKeyslotNames].
func (s *storageContainerReader) ReadKeyslot(ctx context.Context, name string) (secboot.KeyslotInfo, error) {
	return s.impl.ReadKeyslot(ctx, name)
}
