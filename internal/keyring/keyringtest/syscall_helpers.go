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
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// keyctlJoinSessionKeyring is an implementation of [unix.KeyctlJoinSessionKeyring]
// the makes it possible to create and join an anonymous keyring, which is requested by
// passing NUL as the name at the syscall level, and which can be requested by passing
// an empty string to this API. This isn't possible in the x/sys/unix implementation
// because an empty string is passed as a single byte buffer containing a NUL terminator,
// which fails in key_alloc because this is an invalid name.
func keyctlJoinSessionKeyring(name string) (ringId int, err error) {
	var _p2 *byte
	if len(name) > 0 {
		// Only accept non-empty strings to create a named
		// keyring.
		_p2, err = syscall.BytePtrFromString(name)
		if err != nil {
			return 0, err
		}
	}
	r1, _, e1 := syscall.Syscall(syscall.SYS_KEYCTL, uintptr(unix.KEYCTL_JOIN_SESSION_KEYRING), uintptr(unsafe.Pointer(_p2)), 0)
	ringId = int(r1)
	if e1 != 0 {
		err = e1
	}
	return ringId, err
}
