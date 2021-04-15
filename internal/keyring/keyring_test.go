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

package keyring_test

import (
	"math/rand"
	"syscall"
	"testing"

	. "github.com/snapcore/secboot/internal/keyring"
	"github.com/snapcore/secboot/internal/testutil"

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type keyringSuite struct {
	testutil.KeyringTestBase
}

func (s *keyringSuite) SetUpSuite(c *C) {
	s.KeyringTestBase.SetUpSuite(c)

	if !s.ProcessPossessesUserKeyringKeys {
		c.Skip("Test requires the user keyring to be linked from the process's session keyring")
	}
}

var _ = Suite(&keyringSuite{})

type testAddKeyToUserKeyringData struct {
	key        []byte
	devicePath string
	purpose    string
	prefix     string
	desc       string
}

func (s *keyringSuite) testAddKeyToUserKeyring(c *C, data *testAddKeyToUserKeyringData) {
	c.Check(AddKeyToUserKeyring(data.key, data.devicePath, data.purpose, data.prefix), IsNil)

	id, err := unix.KeyctlSearch(-4, "user", data.desc, 0)
	c.Check(err, IsNil)

	buf := make([]byte, len(data.key))
	sz, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
	c.Check(err, IsNil)
	c.Check(sz, Equals, len(data.key))
	c.Check(buf, DeepEquals, data.key)

	desc, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, id)
	c.Check(err, IsNil)
	c.Check(desc, Matches, "user;[[:digit:]]+;[[:digit:]]+;3f010000;"+data.desc)

	userKeys := testutil.GetKeyringKeys(c, testutil.UserKeyring)
	c.Check(id, testutil.InSlice(Equals), userKeys)
}

func (s *keyringSuite) TestAddKeyToUserKeyring1(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringData{
		key:        key,
		devicePath: "/dev/sda1",
		purpose:    "unlock",
		prefix:     "secboot",
		desc:       "secboot:/dev/sda1:unlock"})
}

func (s *keyringSuite) TestAddKeyToUserKeyring2(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringData{
		key:        key,
		devicePath: "/dev/nvme0n1p1",
		purpose:    "bar",
		prefix:     "foo",
		desc:       "foo:/dev/nvme0n1p1:bar"})
}

type testGetKeyFromUserKeyringData struct {
	key        []byte
	devicePath string
	purpose    string
	prefix     string
}

func (s *keyringSuite) testGetKeyFromUserKeyring(c *C, data *testGetKeyFromUserKeyringData) {
	c.Check(AddKeyToUserKeyring(data.key, data.devicePath, data.purpose, data.prefix), IsNil)

	key, err := GetKeyFromUserKeyring(data.devicePath, data.purpose, data.prefix)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, data.key)
}

func (s *keyringSuite) TestGetKeyFromUserKeyring1(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testGetKeyFromUserKeyring(c, &testGetKeyFromUserKeyringData{
		key:        key,
		devicePath: "/dev/sda1",
		purpose:    "unlock",
		prefix:     "secboot"})
}

func (s *keyringSuite) TestGetKeyFromUserKeyring2(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testGetKeyFromUserKeyring(c, &testGetKeyFromUserKeyringData{
		key:        key,
		devicePath: "/dev/nvme0n1p1",
		purpose:    "bar",
		prefix:     "foo"})
}

func (s *keyringSuite) TestGetKeyFromUserKeyringNoKey(c *C) {
	_, err := GetKeyFromUserKeyring("/dev/sda1", "foo", "bar")
	c.Check(err, ErrorMatches, "cannot find key: required key not available")

	var e syscall.Errno
	c.Check(xerrors.As(err, &e), testutil.IsTrue)
	c.Check(e, Equals, syscall.ENOKEY)
}

type testRemoveKeyFromUserKeyringData struct {
	devicePath string
	purpose    string
	prefix     string
}

func (s *keyringSuite) testRemoveKeyFromUserKeyring(c *C, data *testRemoveKeyFromUserKeyringData) {
	c.Check(AddKeyToUserKeyring(make([]byte, 32), data.devicePath, data.purpose, data.prefix), IsNil)
	c.Check(RemoveKeyFromUserKeyring(data.devicePath, data.purpose, data.prefix), IsNil)

	_, err := GetKeyFromUserKeyring(data.devicePath, data.purpose, data.prefix)
	c.Check(err, ErrorMatches, "cannot find key: required key not available")
}

func (s *keyringSuite) TestRemoveKeyFromUserKeyring1(c *C) {
	s.testRemoveKeyFromUserKeyring(c, &testRemoveKeyFromUserKeyringData{
		devicePath: "/dev/sda1",
		purpose:    "unlock",
		prefix:     "secboot"})
}

func (s *keyringSuite) TestRemoveKeyFromUserKeyring2(c *C) {
	s.testRemoveKeyFromUserKeyring(c, &testRemoveKeyFromUserKeyringData{
		devicePath: "/dev/nvme0n1p1",
		purpose:    "bar",
		prefix:     "foo"})
}

func (s *keyringSuite) TestRemoveKeyFromUserKeyringNoKey(c *C) {
	err := RemoveKeyFromUserKeyring("/dev/sda1", "foo", "bar")
	c.Check(err, ErrorMatches, "cannot find key: required key not available")

	var e syscall.Errno
	c.Check(xerrors.As(err, &e), testutil.IsTrue)
	c.Check(e, Equals, syscall.ENOKEY)
}
