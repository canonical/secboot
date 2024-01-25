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

package secboot_test

import (
	"math/rand"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/keyring"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

type keyringSuite struct {
	testutil.KeyringTestBase
}

var _ = Suite(&keyringSuite{})

func (s *keyringSuite) SetUpSuite(c *C) {
	s.KeyringTestBase.SetUpSuite(c)

	if !s.ProcessPossessesUserKeyringKeys {
		c.Skip("Test requires the user keyring to be linked from the process's session keyring")
	}
}

type testGetDiskUnlockKeyFromKernelData struct {
	key        DiskUnlockKey
	prefix     string
	devicePath string
}

func (s *keyringSuite) testGetDiskUnlockKeyFromKernel(c *C, data *testGetDiskUnlockKeyFromKernelData) {
	prefix := data.prefix
	if prefix == "" {
		prefix = "ubuntu-fde"
	}
	c.Check(keyring.AddKeyToUserKeyring(data.key, data.devicePath, "unlock", prefix), IsNil)

	key, err := GetDiskUnlockKeyFromKernel(data.prefix, data.devicePath, false)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, data.key)
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernel1(c *C) {
	key := make(DiskUnlockKey, 32)
	rand.Read(key)

	s.testGetDiskUnlockKeyFromKernel(c, &testGetDiskUnlockKeyFromKernelData{
		key:        key,
		devicePath: "/dev/sda1"})
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernel2(c *C) {
	key := make(DiskUnlockKey, 32)
	rand.Read(key)

	s.testGetDiskUnlockKeyFromKernel(c, &testGetDiskUnlockKeyFromKernelData{
		key:        key,
		prefix:     "foo",
		devicePath: "/dev/nvme0n1p2"})
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernel3(c *C) {
	key := make(DiskUnlockKey, 16)
	rand.Read(key)

	s.testGetDiskUnlockKeyFromKernel(c, &testGetDiskUnlockKeyFromKernelData{
		key:        key,
		devicePath: "/dev/sda1"})
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernelNoKey(c *C) {
	_, err := GetDiskUnlockKeyFromKernel("", "/dev/sda1", false)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernelAndRemove(c *C) {
	key := make(DiskUnlockKey, 32)
	rand.Read(key)

	c.Check(keyring.AddKeyToUserKeyring(key, "/dev/sda1", "unlock", "ubuntu-fde"), IsNil)

	key2, err := GetDiskUnlockKeyFromKernel("", "/dev/sda1", true)
	c.Check(err, IsNil)
	c.Check(key2, DeepEquals, key)

	_, err = GetDiskUnlockKeyFromKernel("", "/dev/sda1", true)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")

	_, err = keyring.GetKeyFromUserKeyring("/dev/sda1", "unlock", "ubuntu-fde")
	c.Check(err, ErrorMatches, "cannot find key: required key not available")
}

type testGetPrimaryKeyFromKernelData struct {
	key        PrimaryKey
	prefix     string
	devicePath string
}

func (s *keyringSuite) testGetPrimaryKeyFromKernel(c *C, data *testGetPrimaryKeyFromKernelData) {
	prefix := data.prefix
	if prefix == "" {
		prefix = "ubuntu-fde"
	}
	c.Check(keyring.AddKeyToUserKeyring(data.key, data.devicePath, "aux", prefix), IsNil)

	key, err := GetPrimaryKeyFromKernel(data.prefix, data.devicePath, false)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, data.key)
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernel1(c *C) {
	key := make(PrimaryKey, 32)
	rand.Read(key)

	s.testGetPrimaryKeyFromKernel(c, &testGetPrimaryKeyFromKernelData{
		key:        key,
		devicePath: "/dev/sda1"})
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernel2(c *C) {
	key := make(PrimaryKey, 32)
	rand.Read(key)

	s.testGetPrimaryKeyFromKernel(c, &testGetPrimaryKeyFromKernelData{
		key:        key,
		prefix:     "foo",
		devicePath: "/dev/nvme0n1p2"})
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernelNoKey(c *C) {
	_, err := GetPrimaryKeyFromKernel("", "/dev/sda1", false)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernelAndRemove(c *C) {
	key := make(PrimaryKey, 32)
	rand.Read(key)

	c.Check(keyring.AddKeyToUserKeyring(key, "/dev/sda1", "aux", "ubuntu-fde"), IsNil)

	key2, err := GetPrimaryKeyFromKernel("", "/dev/sda1", true)
	c.Check(err, IsNil)
	c.Check(key2, DeepEquals, key)

	_, err = GetPrimaryKeyFromKernel("", "/dev/sda1", true)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")

	_, err = keyring.GetKeyFromUserKeyring("/dev/sda1", "aux", "ubuntu-fde")
	c.Check(err, ErrorMatches, "cannot find key: required key not available")
}
