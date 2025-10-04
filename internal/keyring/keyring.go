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
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

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
// the specified key ID. Write permission is required on the specified keyring.
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
// can be used to exit this loop. Read permission for the specified key is
// required.
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

// ListKeyringKeys lists the IDs of all of the keys in the keyring with
// the specified ID. The supplied ID must correspond to a keyring.
// Both read and view permissions are required for the specified key.
func ListKeyringKeys(ctx context.Context, id KeyID) ([]KeyID, error) {
	desc, err := DescribeKey(id)
	if err != nil {
		return nil, err
	}
	if desc.Type != KeyringKeyType {
		return nil, ErrExpectedKeyring
	}

	payload, err := ReadKey(ctx, id)
	if err != nil {
		return nil, err
	}

	// Decode the keyring payload into a slice of key IDs
	sz := len(payload)
	// sz%4 should be zero, but we don't check this. If it isn't
	// true, then all that will happen is binary.Read will return
	// a io.ErrUnexpectedEOF error because there will be fewer
	// than 4 remaining bytes after decoding the penultimate ID.
	ids := make([]KeyID, sz>>2)
	if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// SearchKey searches for a key with the specified type and desciption recursively
// from the keyring with the supplied ID. If the destination key ID is not 0, a
// link to the discovered key will be added to the associated keyring.
//
// This requires search permission on the specified keyring, any nested keyrings
// and the leaf key that matches the type and desciption. If the destination key ID
// is not zero, the associated keyring must have write permission and the discovered
// key must have link permission.
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
// is true. Search permission is required on the specified keyring.
func GetKeyringID(id KeyID, create bool) (KeyID, error) {
	realId, err := unix.KeyctlGetKeyringID(int(id), create)
	if err != nil {
		return 0, processSyscallError(err)
	}
	return KeyID(realId), nil
}

// LinkKey links the key with the specified ID into the keyring with
// the specified ID. Link permission is required for the key to which
// a link is being created, and write permission is required for the
// keyring from which the key will be linked.
func LinkKey(id, keyringId KeyID) error {
	_, err := unix.KeyctlInt(unix.KEYCTL_LINK, int(id), int(keyringId), 0, 0)
	return processSyscallError(err)
}

// UnlinkKey unlinks the key with the specified ID from the keyring with
// the specified ID. Write permission is required on the keyring.
func UnlinkKey(id, keyringId KeyID) error {
	_, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, int(id), int(keyringId), 0, 0)
	return processSyscallError(err)
}

type KeyRole int

const (
	KeyPossessorRole KeyRole = 24
	KeyUserRole      KeyRole = 16
	KeyGroupRole     KeyRole = 8
	KeyOtherRole     KeyRole = 0
)

type KeyRolePerm uint8

const (
	KeyViewPerm KeyRolePerm = 1 << iota
	KeyReadPerm
	KeyWritePerm
	KeySearchPerm
	KeyLinkPerm
	KeySetAttrPerm

	KeyAllPerms KeyRolePerm = 0x3f
)

// KeyPerm represnts the permissions of a key.
type KeyPerm uint32

const (
	KeyPossessorViewPerm    KeyPerm = KeyPerm(KeyViewPerm) << KeyPerm(KeyPossessorRole)
	KeyPossessorReadPerm    KeyPerm = KeyPerm(KeyReadPerm) << KeyPerm(KeyPossessorRole)
	KeyPossessorWritePerm   KeyPerm = KeyPerm(KeyWritePerm) << KeyPerm(KeyPossessorRole)
	KeyPossessorSearchPerm  KeyPerm = KeyPerm(KeySearchPerm) << KeyPerm(KeyPossessorRole)
	KeyPossessorLinkPerm    KeyPerm = KeyPerm(KeyLinkPerm) << KeyPerm(KeyPossessorRole)
	KeyPossessorSetAttrPerm KeyPerm = KeyPerm(KeySetAttrPerm) << KeyPerm(KeyPossessorRole)
	KeyPossessorAllPerms    KeyPerm = KeyPerm(KeyAllPerms) << KeyPerm(KeyPossessorRole)

	KeyUserViewPerm    KeyPerm = KeyPerm(KeyViewPerm) << KeyPerm(KeyUserRole)
	KeyUserReadPerm    KeyPerm = KeyPerm(KeyViewPerm) << KeyPerm(KeyUserRole)
	KeyUserWritePerm   KeyPerm = KeyPerm(KeyWritePerm) << KeyPerm(KeyUserRole)
	KeyUserSearchPerm  KeyPerm = KeyPerm(KeySearchPerm) << KeyPerm(KeyUserRole)
	KeyUserLinkPerm    KeyPerm = KeyPerm(KeyLinkPerm) << KeyPerm(KeyUserRole)
	KeyUserSetAttrPerm KeyPerm = KeyPerm(KeySetAttrPerm) << KeyPerm(KeyUserRole)
	KeyUserAllPerms    KeyPerm = KeyPerm(KeyAllPerms) << KeyPerm(KeyUserRole)

	KeyGroupViewPerm    KeyPerm = KeyPerm(KeyViewPerm) << KeyPerm(KeyGroupRole)
	KeyGroupReadPerm    KeyPerm = KeyPerm(KeyViewPerm) << KeyPerm(KeyGroupRole)
	KeyGroupWritePerm   KeyPerm = KeyPerm(KeyWritePerm) << KeyPerm(KeyGroupRole)
	KeyGroupSearchPerm  KeyPerm = KeyPerm(KeySearchPerm) << KeyPerm(KeyGroupRole)
	KeyGroupLinkPerm    KeyPerm = KeyPerm(KeyLinkPerm) << KeyPerm(KeyGroupRole)
	KeyGroupSetAttrPerm KeyPerm = KeyPerm(KeySetAttrPerm) << KeyPerm(KeyGroupRole)
	KeyGroupAllPerms    KeyPerm = KeyPerm(KeyAllPerms) << KeyPerm(KeyGroupRole)

	KeyOtherViewPerm    KeyPerm = KeyPerm(KeyViewPerm) << KeyPerm(KeyOtherRole)
	KeyOtherReadPerm    KeyPerm = KeyPerm(KeyViewPerm) << KeyPerm(KeyOtherRole)
	KeyOtherWritePerm   KeyPerm = KeyPerm(KeyWritePerm) << KeyPerm(KeyOtherRole)
	KeyOtherSearchPerm  KeyPerm = KeyPerm(KeySearchPerm) << KeyPerm(KeyOtherRole)
	KeyOtherLinkPerm    KeyPerm = KeyPerm(KeyLinkPerm) << KeyPerm(KeyOtherRole)
	KeyOtherSetAttrPerm KeyPerm = KeyPerm(KeySetAttrPerm) << KeyPerm(KeyOtherRole)
	KeyOtherAllPerms    KeyPerm = KeyPerm(KeyAllPerms) << KeyPerm(KeyOtherRole)
)

// String implements [fmt.Stringer].
func (p KeyPerm) String() string {
	permChar := func(role KeyRole, perm KeyRolePerm, c byte) byte {
		if p&(KeyPerm(perm)<<KeyPerm(role)) == 0 {
			return '-'
		}
		return c
	}

	var b strings.Builder
	for i, role := range []KeyRole{KeyPossessorRole, KeyUserRole, KeyGroupRole, KeyOtherRole} {
		if i > 0 {
			io.WriteString(&b, "|")
		}
		fmt.Fprintf(&b, "--%c%c%c%c%c%c",
			permChar(role, KeySetAttrPerm, 'a'),
			permChar(role, KeyLinkPerm, 'l'),
			permChar(role, KeySearchPerm, 's'),
			permChar(role, KeyWritePerm, 'w'),
			permChar(role, KeyReadPerm, 'r'),
			permChar(role, KeyViewPerm, 'v'),
		)
	}

	return b.String()
}

// SetPerm sets the specified permissions on the key referenced by the supplied ID.
// The "set attributes" permission is required on the specified key.
func SetPerm(id KeyID, perm KeyPerm) error {
	return processSyscallError(unix.KeyctlSetperm(int(id), uint32(perm)))
}

// KeyDescription represents the description of a key.
type KeyDescription struct {
	Type KeyType
	UID  uint32
	GID  uint32
	Perm KeyPerm
	Desc string
}

// String implements [fmt.Stringer].
func (d KeyDescription) String() string {
	return fmt.Sprintf("%s %d %d %s: %s", d.Perm, d.UID, d.GID, d.Type, d.Desc)
}

// DescribeKey returns public information about the key with the supplied ID.
// View permission is required on the specified key.
func DescribeKey(id KeyID) (desc KeyDescription, err error) {
	str, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, int(id))
	if err != nil {
		return KeyDescription{}, processSyscallError(err)
	}

	comps := strings.Split(str, ";")
	if len(comps) != 5 {
		return KeyDescription{}, fmt.Errorf("invalid number of components in %q:\n%s", str, hex.Dump([]byte(str)))
	}

	desc.Type = KeyType(comps[0])

	n, err := strconv.ParseUint(comps[1], 10, 32)
	if err != nil {
		return KeyDescription{}, fmt.Errorf("cannot parse uid %q: %w", comps[1], err)
	}
	desc.UID = uint32(n)

	n, err = strconv.ParseUint(comps[2], 10, 32)
	if err != nil {
		return KeyDescription{}, fmt.Errorf("cannot parse gid %q: %w", comps[2], err)
	}
	desc.GID = uint32(n)

	n, err = strconv.ParseUint(comps[3], 16, 32)
	if err != nil {
		return KeyDescription{}, fmt.Errorf("cannot parse perm %q: %w", comps[3], err)
	}
	desc.Perm = KeyPerm(n)

	desc.Desc = comps[4]

	return desc, nil
}

// InvalidateKey invalidates the key associated with the supplied ID, removing it
// from all keyrings and scheduling it for garbage collection. This requires
// search permission on the specified key.
func InvalidateKey(id KeyID) error {
	_, err := unix.KeyctlInt(unix.KEYCTL_INVALIDATE, int(id), 0, 0, 0)
	return processSyscallError(err)
}

// JoinSessionKeyring replaces this process's current session keyring with
// another one. If an empty string is supplied, a new anonymous keyring is
// created. If a name is supplied and it corresponds to an existing keyring,
// this keyring will be used as the process's new session keyring, else a
// keyring with that name will be created.
func JoinSessionKeyring(name string) (KeyID, error) {
	id, err := keyctlJoinSessionKeyring(name)
	return KeyID(id), processSyscallError(err)
}
