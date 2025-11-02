// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021-2025 Canonical Ltd
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

var (
	InternalGetKeyringID                = internalGetKeyringID
	MaybeCheckAndPrepareAttachedKeyring = maybeCheckAndPrepareAttachedKeyring
	ProcessSyscallError                 = processSyscallError
)

func SetProcessKeyringID(id KeyID) {
	processKeyringID = id
}

func GetProcessKeyringID() KeyID {
	return processKeyringID
}

func SetSessionKeyringID(id KeyID) {
	sessionKeyringID = id
}

func GetSessionKeyringID() KeyID {
	return sessionKeyringID
}

func MockInternalGetKeyringID(fn func(KeyID) (KeyID, error)) (restore func()) {
	orig := internalGetKeyringID
	internalGetKeyringID = fn
	return func() {
		internalGetKeyringID = orig
	}
}

func MockMaybeCheckAndPrepareAttachedKeyring(fn func(KeyID) (func(), error)) (restore func()) {
	orig := maybeCheckAndPrepareAttachedKeyring
	maybeCheckAndPrepareAttachedKeyring = fn
	return func() {
		maybeCheckAndPrepareAttachedKeyring = orig
	}
}

func MockRuntimeLockOSThread(fn func()) (restore func()) {
	orig := runtimeLockOSThread
	runtimeLockOSThread = fn
	return func() {
		runtimeLockOSThread = orig
	}
}

func MockRuntimeUnlockOSThread(fn func()) (restore func()) {
	orig := runtimeUnlockOSThread
	runtimeUnlockOSThread = fn
	return func() {
		runtimeUnlockOSThread = orig
	}
}
