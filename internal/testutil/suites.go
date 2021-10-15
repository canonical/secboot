// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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
	"github.com/snapcore/snapd/testutil"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

type KeyringTestBase struct {
	testutil.BaseTest
	ProcessPossessesUserKeyringKeys bool
}

func (b *KeyringTestBase) SetUpSuite(c *C) {
	UserKeyringId, err := unix.KeyctlGetKeyringID(UserKeyring, false)
	c.Assert(err, IsNil)

	keys := GetKeyringKeys(c, sessionKeyring)
	for _, id := range keys {
		if id == UserKeyringId {
			b.ProcessPossessesUserKeyringKeys = true
			break
		}
	}
}

func (b *KeyringTestBase) SetUpTest(c *C) {
	startKeys := GetKeyringKeys(c, UserKeyring)

	b.AddCleanup(func() {
		for _, id1 := range GetKeyringKeys(c, UserKeyring) {
			found := false
			for _, id2 := range startKeys {
				if id1 == id2 {
					found = true
					break
				}
			}
			if found {
				continue
			}
			_, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, id1, UserKeyring, 0, 0)
			c.Check(err, IsNil)
		}
	})
}
