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
	"context"
	"fmt"
	"math/rand"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/keyring"
	"github.com/snapcore/secboot/internal/keyring/keyringtest"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"
)

func getKeyFromUserKeyring(devicePath string, purpose KeyringKeyPurpose, prefix string) ([]byte, error) {
	id, err := keyring.SearchKey(keyring.UserKeyring, keyring.UserKeyType, FormatDesc(devicePath, purpose, prefix), 0)
	if err != nil {
		return nil, fmt.Errorf("cannot find key: %w", err)
	}
	key, err := keyring.ReadKey(context.Background(), id)
	if err != nil {
		return nil, fmt.Errorf("cannot read key payload: %w", err)
	}

	return key, nil
}

type keyringLegacySuite struct {
	testutil.KeyringTestBase
}

var _ = Suite(&keyringLegacySuite{})

func (s *keyringLegacySuite) SetUpSuite(c *C) {
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

func (s *keyringLegacySuite) testGetDiskUnlockKeyFromKernel(c *C, data *testGetDiskUnlockKeyFromKernelData) {
	prefix := data.prefix
	if prefix == "" {
		prefix = "ubuntu-fde"
	}
	c.Check(AddKeyToUserKeyringLegacy(data.key, data.devicePath, "unlock", prefix), IsNil)

	key, err := GetDiskUnlockKeyFromKernel(data.prefix, data.devicePath, false)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, data.key)
}

func (s *keyringLegacySuite) TestGetDiskUnlockKeyFromKernel1(c *C) {
	key := make(DiskUnlockKey, 32)
	rand.Read(key)

	s.testGetDiskUnlockKeyFromKernel(c, &testGetDiskUnlockKeyFromKernelData{
		key:        key,
		devicePath: "/dev/sda1"})
}

func (s *keyringLegacySuite) TestGetDiskUnlockKeyFromKernel2(c *C) {
	key := make(DiskUnlockKey, 32)
	rand.Read(key)

	s.testGetDiskUnlockKeyFromKernel(c, &testGetDiskUnlockKeyFromKernelData{
		key:        key,
		prefix:     "foo",
		devicePath: "/dev/nvme0n1p2"})
}

func (s *keyringLegacySuite) TestGetDiskUnlockKeyFromKernel3(c *C) {
	key := make(DiskUnlockKey, 16)
	rand.Read(key)

	s.testGetDiskUnlockKeyFromKernel(c, &testGetDiskUnlockKeyFromKernelData{
		key:        key,
		devicePath: "/dev/sda1"})
}

func (s *keyringLegacySuite) TestGetDiskUnlockKeyFromKernelNoKey(c *C) {
	_, err := GetDiskUnlockKeyFromKernel("", "/dev/sda1", false)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")
}

func (s *keyringLegacySuite) TestGetDiskUnlockKeyFromKernelAndRemove(c *C) {
	key := make(DiskUnlockKey, 32)
	rand.Read(key)

	c.Check(AddKeyToUserKeyringLegacy(key, "/dev/sda1", "unlock", "ubuntu-fde"), IsNil)

	key2, err := GetDiskUnlockKeyFromKernel("", "/dev/sda1", true)
	c.Check(err, IsNil)
	c.Check(key2, DeepEquals, key)

	_, err = GetDiskUnlockKeyFromKernel("", "/dev/sda1", true)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")

	_, err = getKeyFromUserKeyring("/dev/sda1", "unlock", "ubuntu-fde")
	c.Check(err, ErrorMatches, "cannot find key: cannot complete operation because a specified key does not exist")
}

type testGetPrimaryKeyFromKernelData struct {
	key        PrimaryKey
	prefix     string
	devicePath string
}

func (s *keyringLegacySuite) testGetPrimaryKeyFromKernel(c *C, data *testGetPrimaryKeyFromKernelData) {
	prefix := data.prefix
	if prefix == "" {
		prefix = "ubuntu-fde"
	}
	c.Check(AddKeyToUserKeyringLegacy(data.key, data.devicePath, "aux", prefix), IsNil)

	key, err := GetPrimaryKeyFromKernel(data.prefix, data.devicePath, false)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, data.key)
}

func (s *keyringLegacySuite) TestGetPrimaryKeyFromKernel1(c *C) {
	key := make(PrimaryKey, 32)
	rand.Read(key)

	s.testGetPrimaryKeyFromKernel(c, &testGetPrimaryKeyFromKernelData{
		key:        key,
		devicePath: "/dev/sda1"})
}

func (s *keyringLegacySuite) TestGetPrimaryKeyFromKernel2(c *C) {
	key := make(PrimaryKey, 32)
	rand.Read(key)

	s.testGetPrimaryKeyFromKernel(c, &testGetPrimaryKeyFromKernelData{
		key:        key,
		prefix:     "foo",
		devicePath: "/dev/nvme0n1p2"})
}

func (s *keyringLegacySuite) TestGetPrimaryKeyFromKernelNoKey(c *C) {
	_, err := GetPrimaryKeyFromKernel("", "/dev/sda1", false)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")
}

func (s *keyringLegacySuite) TestGetPrimaryKeyFromKernelAndRemove(c *C) {
	key := make(PrimaryKey, 32)
	rand.Read(key)

	c.Check(AddKeyToUserKeyringLegacy(key, "/dev/sda1", "aux", "ubuntu-fde"), IsNil)

	key2, err := GetPrimaryKeyFromKernel("", "/dev/sda1", true)
	c.Check(err, IsNil)
	c.Check(key2, DeepEquals, key)

	_, err = GetPrimaryKeyFromKernel("", "/dev/sda1", true)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")

	_, err = getKeyFromUserKeyring("/dev/sda1", "aux", "ubuntu-fde")
	c.Check(err, ErrorMatches, "cannot find key: cannot complete operation because a specified key does not exist")
}

type keyringSuite struct {
	snapd_testutil.BaseTest
	keyringtest.KeyringTestMixin
	symlinks map[string]string
}

func (s *keyringSuite) SetUpSuite(c *C) {
	s.JoinAnonymousSessionKeyring(c)
}

func (s *keyringSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	s.KeyringTestMixin.SetUpTest(c)

	s.symlinks = make(map[string]string)
	restore := MockFilepathEvalSymlinks(s.symlinks)
	s.AddCleanup(restore)
}

func (s *keyringSuite) TearDownTest(c *C) {
	s.KeyringTestMixin.TearDownTest(c)
	s.BaseTest.TearDownTest(c)
}

func (s *keyringSuite) addSymlink(target, link string) {
	s.symlinks[link] = target
}

var _ = Suite(&keyringSuite{})

type testAddKeyToUserKeyringParams struct {
	key     []byte
	path    string
	purpose KeyringKeyPurpose
	prefix  string

	desc string
}

func (s *keyringSuite) testAddKeyToUserKeyring(c *C, params *testAddKeyToUserKeyringParams) error {
	added, err := AddKeyToUserKeyring(params.key, params.path, params.purpose, params.prefix)
	if err != nil {
		return err
	}
	s.AddKeyToInvalidate(added)

	id, err := keyring.SearchKey(keyring.UserKeyring, keyring.UserKeyType, params.desc, 0)
	c.Assert(err, IsNil)
	c.Check(id, Equals, added)

	payload, err := keyring.ReadKey(context.Background(), id)
	c.Assert(err, IsNil)
	c.Check(payload, DeepEquals, params.key)

	return nil
}

func (s *keyringSuite) TestAddKeyToUserKeyring(c *C) {
	err := s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
		desc:    "ubuntu-fde:/dev/nvme0n1p3:unlock",
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestAddKeyToUserKeyringDifferentKey(c *C) {
	err := s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:     testutil.DecodeHexString(c, "9473d7975f98f1c8eaa16fb94dedcd06a566bbd6dca7df2c9890dc4ebc36dc84"),
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
		desc:    "ubuntu-fde:/dev/nvme0n1p3:unlock",
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestAddKeyToUserKeyringDifferentPath(c *C) {
	err := s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		path:    "/dev/sda1",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
		desc:    "ubuntu-fde:/dev/sda1:unlock",
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestAddKeyToUserKeyringDifferentPurpose(c *C) {
	err := s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposePrimary,
		prefix:  "ubuntu-fde",
		desc:    "ubuntu-fde:/dev/nvme0n1p3:primary",
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestAddKeyToUserKeyringDifferentPrefix(c *C) {
	err := s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "other-prefix",
		desc:    "other-prefix:/dev/nvme0n1p3:unlock",
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestAddKeyToUserKeyringNoPrefix(c *C) {
	err := s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposeUnlock,
		desc:    "ubuntu-fde:/dev/nvme0n1p3:unlock",
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestAddKeyToUserKeyringResolveSymlinks(c *C) {
	s.addSymlink("/dev/nvme0n1p3", "/dev/disk/by-path/pci-0000:00:0e.0-pci-10000:e1:00.0-nvme-1-part3")

	err := s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		path:    "/dev/disk/by-path/pci-0000:00:0e.0-pci-10000:e1:00.0-nvme-1-part3",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
		desc:    "ubuntu-fde:/dev/nvme0n1p3:unlock",
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestAddKeyToUserKeyringError(c *C) {
	err := s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:     make([]byte, 40000), // exceed the payload size for a user key
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
		desc:    "ubuntu-fde:/dev/nvme0n1p3:unlock",
	})
	c.Check(err, Equals, keyring.ErrInvalidArgs)
}

type testGetKeyFromKernelParams struct {
	key  []byte
	desc string

	path    string
	purpose KeyringKeyPurpose
	prefix  string
	unlink  bool
}

func (s *keyringSuite) testGetKeyFromKernel(c *C, params *testGetKeyFromKernelParams) error {
	id, err := keyring.AddKey(params.key, keyring.UserKeyType, params.desc, keyring.UserKeyring)
	c.Assert(err, IsNil)
	s.AddKeyToInvalidate(id)

	key, err := GetKeyFromKernel(context.Background(), params.path, params.purpose, params.prefix, params.unlink)
	if err != nil {
		return err
	}
	c.Check(key, DeepEquals, params.key)

	currentId, err := keyring.SearchKey(keyring.UserKeyring, keyring.UserKeyType, params.desc, 0)
	if params.unlink {
		c.Check(err, Equals, keyring.ErrKeyNotExist)
	} else {
		c.Assert(err, IsNil)
		c.Check(currentId, Equals, id)
	}
	return nil
}

func (s *keyringSuite) TestGetKeyFromKernel(c *C) {
	err := s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		desc:    "ubuntu-fde:/dev/nvme0n1p3:unlock",
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
		unlink:  false,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestGetKeyFromKernelDifferentKey(c *C) {
	err := s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:     testutil.DecodeHexString(c, "9473d7975f98f1c8eaa16fb94dedcd06a566bbd6dca7df2c9890dc4ebc36dc84"),
		desc:    "ubuntu-fde:/dev/nvme0n1p3:unlock",
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
		unlink:  false,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestGetKeyFromKernelDifferentPath(c *C) {
	err := s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		desc:    "ubuntu-fde:/dev/sda1:unlock",
		path:    "/dev/sda1",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
		unlink:  false,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestGetKeyFromKernelDifferentPurpose(c *C) {
	err := s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		desc:    "ubuntu-fde:/dev/nvme0n1p3:primary",
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposePrimary,
		prefix:  "ubuntu-fde",
		unlink:  false,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestGetKeyFromKernelDifferentPrefix(c *C) {
	err := s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		desc:    "other-prefix:/dev/nvme0n1p3:unlock",
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "other-prefix",
		unlink:  false,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestGetKeyFromKernelNoPrefix(c *C) {
	err := s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		desc:    "ubuntu-fde:/dev/nvme0n1p3:unlock",
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposeUnlock,
		unlink:  false,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestGetKeyFromKernelUnlink(c *C) {
	err := s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		desc:    "ubuntu-fde:/dev/nvme0n1p3:unlock",
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
		unlink:  true,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestGetKeyFromKernelNotExist(c *C) {
	err := s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:     testutil.DecodeHexString(c, "44b4250197ebc469dd0ab2da353d2d87e1dbe6601dc076f7f95160f21000fbef"),
		desc:    "ubuntu-fde:/dev/nvme0n1p3:primary",
		path:    "/dev/nvme0n1p3",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
		unlink:  false,
	})
	c.Check(err, Equals, ErrKernelKeyNotFound)
}
