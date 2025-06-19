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

package keyringtest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"syscall"

	"github.com/snapcore/secboot/internal/keyring"
	"golang.org/x/sys/unix"
	. "gopkg.in/check.v1"
)

// KeyringTestMixin provides some helpers for use when running unit tests
// that make use of the kernel keyring.
type KeyringTestMixin struct {
	ids []keyring.KeyID
}

func (m *KeyringTestMixin) SetUpTest(c *C) {
	m.ids = nil
}

func (m *KeyringTestMixin) TearDownTest(c *C) {
	// Invalidate all keys registered with AdKeyToInvalidate.
	for _, id := range m.ids {
		_, err := unix.KeyctlInt(unix.KEYCTL_INVALIDATE, int(id), 0, 0, 0)
		if errors.Is(err, syscall.Errno(syscall.ENOKEY)) || errors.Is(err, syscall.Errno(syscall.EACCES)) {
			// The key was already invalidated
			continue
		}
		c.Check(err, IsNil, Commentf("key ID: %x", id))
	}
}

// AddKeyToInvalidate adds the key with the specified ID to the list of
// keys to invalidate at the end of the test.
func (m *KeyringTestMixin) AddKeyToInvalidate(id keyring.KeyID) {
	m.ids = append(m.ids, id)
}

// ListKeyringKeys returns a slice of key IDs contained within the specified keyring.
func (m *KeyringTestMixin) ListKeyringKeys(c *C, keyringId keyring.KeyID) []keyring.KeyID {
	// Obtain the size of the payload of the keyring with the specified ID.
	sz, err := unix.KeyctlBuffer(unix.KEYCTL_READ, int(keyringId), nil, 0)
	c.Assert(err, IsNil)

	// The size should be a modulus of 4.
	c.Assert(sz%4, Equals, 0)

	// Allocate a buffer for the payload of the keyring with the specified ID,
	// and read the keyring payload into it.
	payload := make([]byte, sz)
	_, err = unix.KeyctlBuffer(unix.KEYCTL_READ, int(keyringId), payload, 0)
	c.Assert(err, IsNil)

	// Decode the keyring payload into a slice of key IDs
	ids := make([]keyring.KeyID, sz>>2)
	c.Assert(binary.Read(bytes.NewReader(payload), binary.LittleEndian, &ids), IsNil)
	return ids
}

// CheckKeyInKeyring fails the test if the key with the specified ID is not in the keyring
// with the specified ID.
func (m *KeyringTestMixin) CheckKeyInKeyring(c *C, keyId, keyringId keyring.KeyID) {
	ids := m.ListKeyringKeys(c, keyringId)
	for _, id := range ids {
		if id == keyId {
			// The key with the specified keyId is linked into the
			// keyring with the specified keyringId
			return
		}
	}
	c.Errorf("cannot find key with ID %x in keyring with ID %x", keyId, keyringId)
}

// CheckKeyNoInKeyring fails the test if the key with the specified ID is in the keyring
// with the specified ID.
func (m *KeyringTestMixin) CheckKeyNotInKeyring(c *C, keyId, keyringId keyring.KeyID) {
	ids := m.ListKeyringKeys(c, keyringId)
	for _, id := range ids {
		if id == keyId {
			// The key with the specified keyId is linked into the
			// keyring with the specified keyringId
			c.Errorf("found key with ID in keyring with ID %x", keyId, keyringId)
			return
		}
	}
}

// JoinAnonymousSessionKeyring creates and joins a new anonyous session keyring.
// The new keyring will contain a link to the user keyring, for performing tests
// that require certain possessor permissions on keys in the user keyring. This
// is to work around the fact that the test binary isn't guaranteed to start
// attached to a session keyring that contains a link to the user keyring.
func (m *KeyringTestMixin) JoinAnonymousSessionKeyring(c *C) {
	// Create and join an anonyous session keyring.
	id, err := keyctlJoinSessionKeyring("")
	c.Assert(err, IsNil)
	newId := keyring.KeyID(id)

	// Create a link to the user keyring in our new session keyring.
	c.Assert(keyring.LinkKey(keyring.UserKeyring, newId), IsNil)
}
