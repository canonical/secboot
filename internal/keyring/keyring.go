// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2012-2025 Canonical Ltd
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

package keyring

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

// KeyID is an identifier for a key in the kernel's keyring.
type KeyID int32

const (
	NoKey KeyID = 0

	ThreadKeyring  KeyID = -1 // per-thread keyring
	ProcessKeyring KeyID = -2 // per-process keyring

	// SessionKeyring corresponds to the session keyring
	// attached to a process. It is empty by default, and
	// an access either populates it with a new anonymous
	// keyring, or the user session keyring (in which the
	// kernel creates a link to the user keyring), depending
	// what action is being performed that references this
	// keyring.
	SessionKeyring KeyID = -3

	// UserKeyring is a per-user keyring. It is not directly
	// attached to any process / thread, but may be reachable
	// by linking it from a keyring that is attached to the
	// process (normally via the session keyring).
	UserKeyring KeyID = -4

	// UserSessionKeyring is the per-user session keyring. It
	// contains a link to the corresponding UserKeyring, created
	// by the kernel. This keyring may become attached to a
	// process's SessionKeyring in some circumstances.
	UserSessionKeyring KeyID = -5
)

// KeyType describes the type of a key.
type KeyType string

const (
	BigKeyKeyType    KeyType = "big_key"
	EncryptedKeyType KeyType = "encrypted"
	KeyringKeyType   KeyType = "keyring" // a keyring in which other keys can be stored or linked.
	LogonKeyType     KeyType = "logon"   // a logon key with a payload that is only accessible to the kernel.a
	TrustedKeyType   KeyType = "trusted"
	UserKeyType      KeyType = "user" // a key with an arbitrary payload.

	DeadKeyType KeyType = ".dead"
)

// AddKey creates a key of the specified type and with the specified description,
// populates it with the specified key payload and adds it to the keyring with
// the specified key ID.
//
// On success, it returns the ID of the newly added key.
func AddKey(key []byte, keyType KeyType, desc string, keyringId KeyID) (KeyID, error) {
	id, err := unix.AddKey(string(keyType), desc, key, int(keyringId))
	if err != nil {
		return 0, processSyscallError(err)
	}
	return KeyID(id), nil
}

// ReadKey reads and returns the payload of the key with the specified ID. It
// attempts to handle the case where there might be another writer to this key
// at the same time that we are attempting to read it. The supplied context
// can be used to exit this loop.
func ReadKey(ctx context.Context, id KeyID) ([]byte, error) {
	var key []byte

	for ctx.Err() == nil {
		// Read the payload. The first read will be with an empty buffer.
		// The returned size is the full payload size of the key in the
		// kernel rather than the number of bytes read to userspace, and
		// so we can use this to allocate an appropriately sized buffer.
		sz, err := unix.KeyctlBuffer(unix.KEYCTL_READ, int(id), key, 0)
		if err != nil {
			return nil, fmt.Errorf("cannot read key payload with buffer size %d: %w", len(key), processSyscallError(err))
		}

		if sz <= len(key) {
			// We've read the entire key payload into the buffer we allocated.
			// Handle the case where a writer decreased the size of the key
			// payload after we allocated the buffer to store its contents -
			// in this case, the key payload doesn't occupy the full buffer.
			// Return the buffer slice truncated to the correct size in this
			// case.
			return key[:sz], nil
		}

		// The buffer isn't big enough to fit the entire payload
		// into. This will always be the case on the first iteration
		// because we supply a zero-sized buffer. It's also possible
		// that a writer increased the size of the key payload after
		// we allocated a buffer to store its contents, meaning that
		// we've only read the part of the key payload that fits into
		// the buffer we allocated.
		//
		// In any case, allocate a larger buffer and try again.
		key = make([]byte, sz)
	}

	return nil, ctx.Err()
}

// SearchKey searches for a key with the specified type and desciption recursively
// from the keyring with the supplied ID. If the destination key ID is not 0, a
// link to the discovered key will be added to the associated keyring.
//
// On success, the ID of the discovered key will be returned.
func SearchKey(keyringId KeyID, keyType KeyType, desc string, destinationRingId KeyID) (KeyID, error) {
	id, err := unix.KeyctlSearch(int(keyringId), string(keyType), desc, int(destinationRingId))
	if err != nil {
		return 0, processSyscallError(err)
	}
	return KeyID(id), nil
}

// GetKeyringID returns the proper keyring ID for the supplied special keyring
// ID. The create argument indicates whether the keyring should be created if
// the requested keyring is not yet attached to this process. Note that if the
// supplied ID is SessionKeyring and this process has no session keyring, one
// will be attached regardless - it will be the keyring associated with
// UserSessionKeyring if create is false, or a new anonymous keyring if create
// is true.
func GetKeyringID(id KeyID, create bool) (KeyID, error) {
	realId, err := unix.KeyctlGetKeyringID(int(id), create)
	if err != nil {
		return 0, processSyscallError(err)
	}
	return KeyID(realId), nil
}

// LinkKey links the key with the specified ID into the keyring with
// the specified ID.
func LinkKey(id, keyringId KeyID) error {
	_, err := unix.KeyctlInt(unix.KEYCTL_LINK, int(id), int(keyringId), 0, 0)
	return processSyscallError(err)
}

// UnlinkKey unlinks the key with the specified ID from the keyring with
// the specified ID.
func UnlinkKey(id, keyringId KeyID) error {
	_, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, int(id), int(keyringId), 0, 0)
	return processSyscallError(err)
}
