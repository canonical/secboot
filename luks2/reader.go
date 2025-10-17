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
	internal_luks2 "github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luksview"
)

// storageContainerReadWriterImpl is the main implementation that backs
// any StorageContainerReader and (eventually) StorageContainerReadWriter
// interfaces.
type storageContainerReadWriterImpl struct {
	container *storageContainerImpl

	// keyslots is a cache of the keyslot metadata for this storage
	// container. We keep this here under the assumption that no other
	// processes are messing with this information, and that we will
	// ensure that whilst there is no limit on the number of goroutines
	// permitted to have read access to this container, we won't permit
	// the following:
	// - a goroutine to have read/write access whilst there are are readers.
	// - go routines to have read access whilst there is a goroutine with
	//   read/write access.
	// - more than one goroutine at a time to have read/write access.
	keyslots map[string]*keyslotImpl
}

// ensureKeyslotNames ensures that the names of keyslots are cached.
// XXX: There is only read access for storage containers for now. Although there will
// eventually be read/write access, snapd will continue to use the existing
// [secboot.LUKS2KeyDataWriter] in the meantime. It is an error to modify the LUKS2
// header with an open reader, and this package will ensure that a read/writer cannot
// be opened whilst there are open readers when read/write access is supported.
// Therefore, it is safe to assume that the cached information will not change for
// now. When read/write access is implemented, writes will need to ensure that cached
// data is properly refreshed and kept in sync.
func (s *storageContainerReadWriterImpl) ensureKeyslotNames() error {
	if s.keyslots != nil {
		return nil
	}

	keyslots := make(map[string]*keyslotImpl)

	names, err := luks2Ops.ListUnlockKeyNames(s.container.Path())
	if err != nil {
		return err
	}
	for _, name := range names {
		keyslots[name] = &keyslotImpl{
			keyslotType: secboot.KeyslotTypePlatform,
			keyslotName: name,
			keyslotId:   internal_luks2.AnySlot, // use AnySlot to indicate we haven't filled this Keyslot yet.
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
		keyslots[name] = &keyslotImpl{
			keyslotType: secboot.KeyslotTypeRecovery,
			keyslotName: name,
			keyslotId:   internal_luks2.AnySlot, // use AnySlot to indicate we haven't filled this Keyslot yet.
		}
	}

	s.keyslots = keyslots
	return nil
}

// ensureKeyslot ensures that the keyslot data for the keyslot with the specified name
// is cached.
// XXX: There is only read access for storage containers for now. Although there will
// eventually be read/write access, snapd will continue to use the existing
// [secboot.LUKS2KeyDataWriter] in the meantime. It is an error to modify the LUKS2
// header with an open reader, and this package will ensure that a read/writer cannot
// be opened whilst there are open readers when read/write access is supported.
// Therefore, it is safe to assume that the cached information will not change for
// now. When read/write access is implemented, writes will need to ensure that cached
// data is properly refreshed and kept in sync.
func (s *storageContainerReadWriterImpl) ensureKeyslot(ctx context.Context, name string) error {
	if err := s.ensureKeyslotNames(); err != nil {
		return err
	}

	ks, exists := s.keyslots[name]
	if !exists {
		return secboot.ErrKeyslotNotFound
	}

	if ks.keyslotId != internal_luks2.AnySlot {
		// We already have everything for this keyslot.
		return nil
	}

	// The existing secboot API doesn't expose the LUKS2 keyslot ID for recovery
	// keys, and we also don't want to create a new KeyDataReader yet for platform
	// keys, so we use the luksview package directly via a bit of an abstraction
	// so that it can be mocked in unit tests. This will all be cleaned up
	// eventually once all of this functionality is implemented natively in this
	// package.
	//
	// The new unlocking API will test a recovery key separately against each
	// individual recovery keyslot, so we know which keyslot is used for unlocking.
	view, err := newLuksView(ctx, s.container.Path())
	if err != nil {
		return fmt.Errorf("cannot obtain new luksview.View: %w", err)
	}
	token, _, inUse := view.TokenByName(name)
	if !inUse {
		return fmt.Errorf("no metadata for keyslot %q", name)
	}
	ks.keyslotId = token.Keyslots()[0] // luksview guarantees there is always 1 keyslot here.
	if ks.keyslotType == secboot.KeyslotTypePlatform {
		// TODO: Once the functionality of luksview is implemented directly in
		// this package, we'll give recovery keyslots a priority as well. This
		// makes sense given that a recovery key will be tested separately
		// against each individual recovery keyslot with the new unlocking API.
		kdToken, ok := token.(*luksview.KeyDataToken)
		if !ok {
			return fmt.Errorf("platform keyslot %q has an invalid token", name)
		}
		ks.keyslotPriority = kdToken.Priority
	}

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

func (s *storageContainerReadWriterImpl) ReadKeyslot(ctx context.Context, name string) (secboot.Keyslot, error) {
	if err := s.ensureKeyslot(ctx, name); err != nil {
		return nil, err
	}

	ks := s.keyslots[name]

	// Make a copy of the keyslotImpl so that we can always
	// attach a new KeyDataReader for platform key slots.
	// TODO: In a follow-up, just make the keyslots map a
	// map[string]*luksview.Token so that we cache the
	// keydata from the token, and then we just wrap it
	// in a secboot.KeyDataReader and new keyslotImpl here.
	// This would get rid of the call to secboot.NewLUKS2KeyDataReader.
	ksCopy := *ks

	if ks.keyslotType == secboot.KeyslotTypePlatform {
		r, err := luks2Ops.NewKeyDataReader(s.container.Path(), name)
		if err != nil {
			return nil, fmt.Errorf("cannot obtain reader for %q: %w", name, err)
		}
		ksCopy.keyslotData = r
	}

	return &ksCopy, nil
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

func (*closedStorageContainerReadWriterImpl) ReadKeyslot(_ context.Context, _ string) (secboot.Keyslot, error) {
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
func (s *storageContainerReader) ReadKeyslot(ctx context.Context, name string) (secboot.Keyslot, error) {
	return s.impl.ReadKeyslot(ctx, name)
}
