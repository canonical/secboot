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
	"runtime"
	"time"

	"github.com/snapcore/secboot/internal/keyring"
	. "gopkg.in/check.v1"
)

// TestMixin can be embedded in a suite in order to track the
// addition of keys and to automatically invalidate them at the end
// of a test.
type TestMixin struct {
	AddedKeys      []keyring.KeyID
	lockedOSThread int
}

func (m *TestMixin) SetUpTest(c *C) {
	c.Check(m.AddedKeys, HasLen, 0)
	c.Check(m.lockedOSThread, Equals, 0)

	m.AddedKeys = nil
}

func (m *TestMixin) TearDownTest(c *C) {
	n := len(m.AddedKeys)
	if n > 0 {
		// This looks like a long timeout for something that should happen
		// quickly, but there have already been failures at 30s, and SSHing
		// into a github runner instance reveals some moments where the
		// instance becomes unresponsive for 10s of seconds.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		InvalidateKeysAndWaitForGC(c, ctx, m.AddedKeys...)
		cancel()

		m.AddedKeys = nil
	}

	for m.lockedOSThread > 0 {
		runtime.UnlockOSThread()
		m.lockedOSThread -= 1
	}
}

// AddKey is a wrapper around [keyring.AddKey] that will abort the test if
// it fails. The added key is tracked for invalidation at the end of the
// test. If a test needs to invalidate the key before the end of the test,
// it should use [InvalidateKeysAndWaitForGC] to avoid unexpected errors.
func (m *TestMixin) AddKey(c *C, key []byte, keyType keyring.KeyType, desc string, keyringId keyring.KeyID) keyring.KeyID {
	id, err := m.AddKeyNoCheck(key, keyType, desc, keyringId)
	c.Assert(err, IsNil)
	return id
}

// AddKeyNoCheck is a wrapper around [keyring.KeyID]. The added key is
// tracked for invalidation at the end of the test. If a test needs to
// invalidate the key before the end of the test, it should use
// [InvalidateKeysAndWaitForGC] to avoid unexpected errors.
func (m *TestMixin) AddKeyNoCheck(key []byte, keyType keyring.KeyType, desc string, keyringId keyring.KeyID) (keyring.KeyID, error) {
	id, err := keyring.AddKey(key, keyType, desc, keyringId)
	if err != nil {
		return id, err
	}

	m.AddedKeys = append(m.AddedKeys, id)
	return id, nil
}

// LockOSThread calls [runtime.LockOSThread] to bind the calling goroutine
// to the current OS thread, and keeps track of the number of times it is
// called so that [runtime.UnlockOSThread] can be called an appropriate
// number of times automatically at the end of the test. Use this if a test
// needs to bind to a single OS thread until after the test teardown completes.
//
// A test may need to bind to an OS thread in order to use the thread keyring
// or if it wants to join and use a session keyring.
//
// If a test wants to unbind from its OS thread before the test is torn down
// after calling this, use [UnlockOSThread] rather than [runtime.UnlockOSThread].
func (m *TestMixin) LockOSThread() {
	runtime.LockOSThread()
	m.lockedOSThread += 1
}

// UnlockOSThread undoes the action of [LockOSThread].
func (m *TestMixin) UnlockOSThread() {
	runtime.UnlockOSThread()
	m.lockedOSThread -= 1
}

//func (m *TestMixin) JoinNewSessionKeyringAndPossessUserKeyring(c *C) {
//}

// InvalidateKeysAndWaitForGC invalidates the specified keys and waits for them
// to be fully garbage collected, failing the test if there is an error. This will
// correctly handle the case where a key has already been invalidated.
//
// This should be used by any test that wants to invalidate keys and rely on
// seeing predictable errors for subsequent operations on the invalidated keys,
// and to ensure predictability across tests.
func InvalidateKeysAndWaitForGC(c *C, ctx context.Context, ids ...keyring.KeyID) {
	// When we execute KEYCTL_INVALIDATE, the key is marked invalid and a
	// GC is scheduled before the keyctl syscall returns. If another operation
	// is executed on the key before the GC work begins, the keyctl syscall
	// may return ENOKEY for operations that check the key's flags (key_validate
	// in the kernel). If another operation is executed on the key once the GC
	// work has completed, the keyctl syscall will return ENOKEY. However, if
	// an operation is executed on the key once the GC work has begun, it may
	// be possible to hit a point where the key has been GCd from some or all
	// of the keyrings in which it was linked but before the key has been
	// completely GCd. In this case, and where the operation is relying on
	// possessor permissions, and where the key has been removed from all of
	// the process keyrings, the keyctl syscall may return EACCES that occurs
	// during key lookup (from lookup_user_key in the kernel).
	//
	// The KEYCTL_INVALIDATE operation doesn't check the key's flags, so
	// it is expected that the keyctl syscall will return no error in the
	// case where it is executed on an invalid key if the GC work hasn't
	// started yet. We take advantage of that here by looping KEYCTL_INVALIDATE
	// until we see an error that isn't EACCES.
	for _, id := range ids {
		var err error
		for {
			err = ctx.Err()
			if err != nil {
				break
			}

			err = keyring.InvalidateKey(id)
			if err != nil && !errors.Is(err, keyring.ErrPermission) {
				// Break on any error that isn't ErrPermission.
				break
			}

			// Either InvalidateKey succeeded or it returned ErrPermission,
			// so try again.
			time.Sleep(200 * time.Millisecond)
		}

		if errors.Is(err, keyring.ErrKeyNotExist) {
			// This error is ok.
			err = nil
		}
		c.Check(err, IsNil, Commentf("key ID: %d", id))
	}
}

// CheckKeyInKeyring fails the test if the key with the specified ID is not
// in the keyring with the specified ID.
func CheckKeyInKeyring(c *C, keyId, keyringId keyring.KeyID) {
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

// CheckKeyNoInKeyring fails the test if the key with the specified ID is in
// the keyring with the specified ID.
func CheckKeyNotInKeyring(c *C, keyId, keyringId keyring.KeyID) {
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
