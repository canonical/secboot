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
	"context"
	"errors"
	"os"
	"sync"

	"github.com/snapcore/secboot/internal/keyring"
	. "gopkg.in/check.v1"
)

// KeyringTestMixin provides some helpers for use when running unit tests
// that make use of the kernel keyring.
type KeyringTestMixin struct {
	mu  sync.Mutex
	ids []keyring.KeyID
}

func (m *KeyringTestMixin) SetUpTest(c *C) {
	m.ids = nil
}

func (m *KeyringTestMixin) TearDownTest(c *C) {
	// Invalidate all keys registered with AddKeyToInvalidate.
	for _, id := range m.ids {
		err := keyring.InvalidateKey(id)
		if errors.Is(err, keyring.ErrKeyNotExist) {
			// The key was already invalidated.
			continue
		}
		c.Check(err, IsNil, Commentf("key ID: %x", id))
	}
}

func (m *KeyringTestMixin) AddKeyToInvalidate(c *C, id keyring.KeyID, threadBound bool) {
	keyType, uid, gid, perm, desc, err := keyring.DescribeKey(id)
	// View permissions are required for KEYCTL_DESCRIBE.
	c.Assert(err, IsNil)

	// To determine whether we are a possessor, we need to search each of
	// the process's keyrings.
	keyrings := []keyring.KeyID{keyring.SessionKeyring, keyring.ProcessKeyring}
	if threadBound {
		keyrings = append(keyrings, keyring.ThreadKeyring)
	}

	keyPossessed := false
	for _, ring := range keyrings {
		id2, err := keyring.SearchKey(ring, keyType, desc, 0)
		if errors.Is(err, keyring.ErrKeyNotExist) {
			continue
		}
		c.Assert(err, IsNil)
		if id2 == id {
			keyPossessed = true
			break
		}
	}

	requiredPerm := keyring.KeyPerm(0x08) // search permission, required for KEYCTL_INVALIDATE
	switch {
	case keyPossessed:
		requiredPerm <<= 24
	case int64(uid) == int64(os.Getuid()):
		requiredPerm <<= 16
	case int64(gid) == int64(os.Getgid()):
		requiredPerm <<= 8
	}
	c.Assert(perm&requiredPerm, Equals, requiredPerm)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.ids = append(m.ids, id)
}

// CheckKeyInKeyring fails the test if the key with the specified ID is not in the keyring
// with the specified ID.
func (m *KeyringTestMixin) CheckKeyInKeyring(c *C, keyId, keyringId keyring.KeyID) {
	ids, err := keyring.ListKeyringKeys(context.Background(), keyringId)
	c.Assert(err, IsNil)

	for _, id := range ids {
		if id == keyId {
			// The key with the specified keyId is linked into the
			// keyring with the specified keyringId
			return
		}
	}
	c.Errorf("cannot find key with ID %d in keyring with ID %d", keyId, keyringId)
}

// CheckKeyNoInKeyring fails the test if the key with the specified ID is in the keyring
// with the specified ID.
func (m *KeyringTestMixin) CheckKeyNotInKeyring(c *C, keyId, keyringId keyring.KeyID) {
	ids, err := keyring.ListKeyringKeys(context.Background(), keyringId)
	c.Assert(err, IsNil)

	for _, id := range ids {
		if id == keyId {
			// The key with the specified keyId is linked into the
			// keyring with the specified keyringId
			c.Errorf("found key with ID %d in keyring with ID %d", keyId, keyringId)
			return
		}
	}
}

// JoinSharedAnonymousSessionKeyring creates and joins a new anonyous session
// keyring. The new keyring will contain a link to the user keyring, for
// performing tests that require certain possessor permissions on keys in the
// user keyring. This is to work around the fact that the test binary isn't
// guaranteed to start attached to a session keyring that contains a link to
// the user keyring.
func (m *KeyringTestMixin) JoinSharedAnonymousSessionKeyring(c *C) {
	// Create and join an anonyous session keyring.
	id, err := keyring.JoinSessionKeyring("")
	c.Assert(err, IsNil)

	// Create a link to the user keyring in our new session keyring.
	c.Assert(keyring.LinkKey(keyring.UserKeyring, id), IsNil)
}
