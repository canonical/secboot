// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package testutil

import (
	"encoding/binary"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

const (
	sessionKeyring = -3
	UserKeyring    = -4
)

func GetKeyringKeys(c *C, keyringId int) (out []int) {
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyringId, nil, 0)
	c.Assert(err, IsNil)
	buf := make([]byte, n)
	_, err = unix.KeyctlBuffer(unix.KEYCTL_READ, keyringId, buf, 0)
	c.Assert(err, IsNil)

	for len(buf) > 0 {
		id := int(binary.LittleEndian.Uint32(buf[0:4]))
		buf = buf[4:]
		out = append(out, id)
	}
	return out
}
