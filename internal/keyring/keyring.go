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

// Package keyring provides a way to work with the kernel keyring.
package keyring

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

var (
	runtimeLockOSThread   = runtime.LockOSThread
	runtimeUnlockOSThread = runtime.UnlockOSThread
)

// KeyID is an identifier for a key in the kernel's keyring.
type KeyID int32

const (
	NoKey KeyID = 0

	// ThreadKeyring is a per-thread keyring. It is
	// created lazily by some keyring operations. In order
	// to make use of this, a goroutine must bind itself to
	// a single OS thread using runtime.LockOSThread.
	ThreadKeyring KeyID = -1

	// ProcessKeyring is a per-process keyring. It is
	// created lazily when required by some keyring operations,
	// but only for the calling OS thread. That means that the
	// process keyring is only global for the entire process
	// if it is created in a single-threaded environment, which
	// isn't possible from go. In order to make use of the
	// process keyring, import the processinit sub-package which
	// will initialize the process keyring before the go runtime
	// starts.
	ProcessKeyring KeyID = -2

	// SessionKeyring corresponds to the session keyring
	// attached to a process. A new process inherits the parent
	// process's session keyring, which may be unset. In this
	// case, a session keyring is attached lazily when required
	// by any keyring operation, and this may either be with a
	// new anonymous keyring, or the user session keyring,
	// depending what operation is being performed that references
	// this keyring. Updates to the session keyring only affect
	// the calling thread. That means that the session keyring is
	// only global for the entire process if it is modified in a
	// single-threaded environment, which isn't possible from go.
	// This package will ensure that the session keyring is
	// initialized to point to the user session keyring for
	// whichever OS thread it is used from if there is not already
	// a session keyring attached. In order to create and join an
	// anonymous session keyring, import the forcesessioninit
	// sub-package which will join a new anonymous/ keyring before
	// the go runtime starts.
	SessionKeyring KeyID = -3

	// UserKeyring is a per-user keyring. This is not attached
	// to a process.
	UserKeyring KeyID = -4

	// UserSessionKeyring is the per-user session keyring. It
	// contains a link to the corresponding UserKeyring, created
	// by the kernel. It is not attached to a process.
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

// maybeCheckAndPrepareAttachedKeyring will ensure that if the supplied key ID
// corresponds to either the process or session keyring, that the real keyring ID
// is the same each time it is used. If the process keyring changes between uses,
// then it means that a process keyring was created lazily from the go runtime,
// resulting in each OS thread ending up with a different process keyring. If the
// session keyring changes between uses, then it means that either something
// executed KEYCTL_JOIN_SESSION_KEYRING after the go runtime started, or the
// process was started without a session keyring but something triggered the
// attachment of a new anonymous session keyring - something that this package
// tries to protect against - resulting in each OS thread ending up with a different
// session keyring. In both of these cases (for the process and session keyrings),
// it results in the keyring seen by a goroutine being dependent on the OS thread
// it happens to be running on.
//
// If the supplied ID is the process keyring, and a process keyring has not been
// created, then a ErrKeyNotExist error will be returned.
//
// If the supplied ID is the session keyring and there is no session keyring
// attached, this function has the side effect of attaching the user session keyring
// as the session keyring (it isn't possible to avoid this). This is ok though,
// as long as the behaviour is consistent across OS threads because it means that
// a goroutine will see the same session keyring regardless of which OS thread it
// is executing on.
//
// This function may return with the calling goroutine locked to an OS thread. On
// success, the caller should execute the returned callback to unlock the goroutine
// from the OS thread it is executing on once the subsequent keyring operation has
// completed.
var maybeCheckAndPrepareAttachedKeyring = func(id KeyID) (unlockOSThreadIfNeeded func(), err error) {
	switch id {
	default:
		return func() {}, nil
	case ProcessKeyring, SessionKeyring:
		// continue
	}

	needUnlockOSThread := false

	if id == SessionKeyring {
		runtimeLockOSThread()
		needUnlockOSThread = true
	}
	defer func() {
		if !needUnlockOSThread {
			return
		}
		runtimeUnlockOSThread()
	}()

	if _, err := GetKeyringID(id); err != nil {
		return nil, err
	}

	if needUnlockOSThread {
		// On success, return with the current goroutine locked
		// to the current OS thread, if it was previously locked.
		needUnlockOSThread = false
		return func() {
			runtimeUnlockOSThread()
		}, nil
	}

	return func() {}, nil
}

// AddKey creates a key of the specified type and with the specified description,
// populates it with the specified key payload and adds it to the keyring with
// the specified key ID. Write permission is required on the specified keyring.
//
// On success, it returns the ID of the newly added key.
func AddKey(key []byte, keyType KeyType, desc string, keyringId KeyID) (KeyID, error) {
	unlockOSThreadIfNeeded, err := maybeCheckAndPrepareAttachedKeyring(keyringId)
	if err != nil {
		return 0, err
	}
	defer unlockOSThreadIfNeeded()

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
	unlockOSThreadIfNeeded, err := maybeCheckAndPrepareAttachedKeyring(id)
	if err != nil {
		return nil, err
	}
	defer unlockOSThreadIfNeeded()

	var key []byte

	for ctx.Err() == nil {
		// Read the payload. The first read will be with an empty buffer.
		// The returned size is the full payload size of the key in the
		// kernel rather than the number of bytes read to userspace, and
		// so we can use this to allocate an appropriately sized buffer.
		sz, err := unix.KeyctlBuffer(unix.KEYCTL_READ, int(id), key, 0)
		if err != nil {
			return nil, processSyscallError(err)
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
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})
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
	// We only do this for the destination keyring. The search keyring
	// lookup is called without the KEY_LOOKUP_CREATE flag in the kernel,
	// which means that if it refers to the session keyring, then the
	// user session keyring will be attached as the session keyring if
	// there isn't one already.
	unlockOSThreadIfNeeded, err := maybeCheckAndPrepareAttachedKeyring(destinationRingId)
	if err != nil {
		return 0, err
	}
	defer unlockOSThreadIfNeeded()

	id, err := unix.KeyctlSearch(int(keyringId), string(keyType), desc, int(destinationRingId))
	if err != nil {
		return 0, processSyscallError(err)
	}
	return KeyID(id), nil
}

var (
	// processKeyringID tracks the real process keyring ID for this process.
	processKeyringID KeyID

	// sessionKeyringID tracks the real session keyring ID for this process.
	sessionKeyringID KeyID
)

// GetKeyringID returns the real keyring ID for the supplied special keyring
// ID. The underlying system call supports a "create" argument. That isn't
// exposed here (this function passes create=false unless the supplied keyring
// ID is the thread keyring). It isn't appropriate to create and attach a
// process keyring from the go runtime because these must be created in a
// single threaded environment. If the supplied keyring ID is the thread
// keyring, then the thread keyring is created if there isn't already one
// attached to the calling OS thread. Note that thread keyring usage requires
// the goroutine to be locked to a single OS thread. If the keyring ID
// corresponds to the session keyring, then the user session keyring will be
// attached as the session keyring for the calling OS thread if there isn't
// already a session keyring. This is a safe default because it means that
// every goroutine will see the same session keyring. It is not appropriate
// to create and join a new anonymous session keyring (which is what
// create=true would do) from the go runtime because this would mean the
// session keyring a goroutine could access would depend on the OS thread it
// is executing on.
func GetKeyringID(id KeyID) (KeyID, error) {
	create := false
	if id == ThreadKeyring {
		create = true
	}

	realId, err := unix.KeyctlGetKeyringID(int(id), create)
	if err != nil {
		return 0, processSyscallError(err)
	}

	switch id {
	case ProcessKeyring:
		// If we are requesting the ID of the process keyring, record the
		// real keyring ID and make sure that it doesn't change. A process
		// cannot change its process keyring once it has been created.
		// However, process keyrings are lazily created when required for
		// the calling OS thread only, so in order to use the process
		// keyring from go, one must create it from a single-thread
		// execution context, before the go runtime starts.
		if !atomic.CompareAndSwapInt32((*int32)(&processKeyringID), 0, int32(realId)) {
			if atomic.LoadInt32((*int32)(&processKeyringID)) != int32(realId) {
				panic("multiple process keyrings, try importing the processinit sub-package")
			}
		}
	case SessionKeyring:
		// If we are requesting the ID of the session keyring, record the
		// real keyring ID and make sure that it doesn't change. This means
		// that KEYCTL_JOIN_SESSION_KEYRING cannot be used from go, but
		// we don't export a function for that anyway.
		//
		// If it changes, then either something external called executed
		// KEYCTL_JOIN_SESSION_KEYRING, or we were started without a session
		// keyring and each OS thread is being attached lazily to different
		// anonymous keyrings, which this package tries to prevent.
		if !atomic.CompareAndSwapInt32((*int32)(&sessionKeyringID), 0, int32(realId)) {
			if atomic.LoadInt32((*int32)(&sessionKeyringID)) != int32(realId) {
				panic("session keyring changed or multiple session keyrings, " +
					"don't use KEYCTL_JOIN_SESSION_KEYRING or maybe try importing " +
					"the forcesessioninit sub-package to start with a new anonymous session keyring")
			}
		}
	}

	return KeyID(realId), nil
}

// LinkKey links the key with the specified ID into the keyring with
// the specified ID. Link permission is required for the key to which
// a link is being created, and write permission is required for the
// keyring from which the key will be linked.
func LinkKey(id, keyringId KeyID) error {
	unlockOSThreadIfNeeded, err := maybeCheckAndPrepareAttachedKeyring(id)
	if err != nil {
		return err
	}
	defer unlockOSThreadIfNeeded()

	unlockOSThreadIfNeeded, err = maybeCheckAndPrepareAttachedKeyring(keyringId)
	if err != nil {
		return err
	}
	defer unlockOSThreadIfNeeded()

	_, err = unix.KeyctlInt(unix.KEYCTL_LINK, int(id), int(keyringId), 0, 0)
	return processSyscallError(err)
}

// UnlinkKey unlinks the key with the specified ID from the keyring with
// the specified ID. Write permission is required on the keyring.
func UnlinkKey(id, keyringId KeyID) error {
	// The kernel does not perform the lookup for either key ID with the
	// KEY_LOOKUP_CREATE flag, which means that if either of them corresponds
	// to the session keyring, then the user session keyring will be attached
	// as the session keyring if there isn't one already.
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
	unlockOSThreadIfNeeded, err := maybeCheckAndPrepareAttachedKeyring(id)
	if err != nil {
		return err
	}
	defer unlockOSThreadIfNeeded()

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
	// The kernel does not perform the lookup for the key with the
	// KEY_LOOKUP_CREATE flag, which means that if it corresponds to the
	// session keyring, then the user session keyring will be attached
	// as the session keyring if there isn't one already.
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
	// The kernel does not perform the lookup for the key with the
	// KEY_LOOKUP_CREATE flag, which means that if it corresponds to the
	// session keyring, then the user session keyring will be attached
	// as the session keyring if there isn't one already.
	_, err := unix.KeyctlInt(unix.KEYCTL_INVALIDATE, int(id), 0, 0, 0)
	return processSyscallError(err)
}
