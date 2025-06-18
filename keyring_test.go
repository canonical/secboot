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
	"errors"
	"os"
	"syscall"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/keyring"
	"github.com/snapcore/secboot/internal/keyring/keyringtest"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"
	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

type keyringTestMixin struct {
	keyringtest.TestMixin

	fileInfo map[string]unix.Stat_t

	restoreAddKey   func()
	restoreUnixStat func()
}

func (*keyringTestMixin) SetUpSuite(c *C) {
	// Ensure that we possess keys added to the user keyring.
	c.Check(keyring.LinkKey(keyring.UserKeyring, keyring.SessionKeyring), IsNil)
}

func (m *keyringTestMixin) SetUpTest(c *C) {
	m.TestMixin.SetUpTest(c)

	m.restoreAddKey = MockKeyringAddKey(m.AddKeyNoCheck)

	m.fileInfo = make(map[string]unix.Stat_t)
	m.restoreUnixStat = MockUnixStat(func(path string, st *unix.Stat_t) error {
		info, exists := m.fileInfo[path]
		if !exists {
			return syscall.ENOENT
		}
		*st = info
		return nil
	})
}

func (m *keyringTestMixin) TearDownTest(c *C) {
	if m.restoreUnixStat != nil {
		m.restoreUnixStat()
		m.restoreUnixStat = nil
	}
	if m.restoreAddKey != nil {
		m.restoreAddKey()
		m.restoreAddKey = nil
	}

	m.TestMixin.TearDownTest(c)
}

func (*keyringTestMixin) TearDownSuite(c *C) {
	c.Check(keyring.UnlinkKey(keyring.UserKeyring, keyring.SessionKeyring), IsNil)
}

func (m *keyringTestMixin) addFileInfo(path string, st *unix.Stat_t) {
	m.fileInfo[path] = *st
}

func (m *keyringTestMixin) addFileInfos(infos map[string]unix.Stat_t) {
	for k, v := range infos {
		m.addFileInfo(k, &v)
	}
}

type keyringSuite struct {
	snapd_testutil.BaseTest
	keyringTestMixin

	fileInfo map[string]unix.Stat_t
}

func (s *keyringSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	s.keyringTestMixin.SetUpTest(c)
}

func (s *keyringSuite) TearDownTest(c *C) {
	s.keyringTestMixin.TearDownTest(c)
	s.BaseTest.TearDownTest(c)
}

var _ = Suite(&keyringSuite{})

func (s *keyringSuite) TestFormatKeyringKeyDesc(c *C) {
	c.Check(FormatKeyringKeyDesc("/dev/sda1", KeyringKeyPurposeUnlock, "ubuntu-fde"), Equals, "ubuntu-fde:/dev/sda1:unlock")
}

func (s *keyringSuite) TestFormatKeyringKeyDescDifferentPath(c *C) {
	c.Check(FormatKeyringKeyDesc("/dev/nvme0n1p2", KeyringKeyPurposeUnlock, "ubuntu-fde"), Equals, "ubuntu-fde:/dev/nvme0n1p2:unlock")
}

func (s *keyringSuite) TestFormatKeyringKeyDescDifferentPurpose(c *C) {
	c.Check(FormatKeyringKeyDesc("/dev/sda1", KeyringKeyPurposeAuxiliary, "ubuntu-fde"), Equals, "ubuntu-fde:/dev/sda1:aux")
}

func (s *keyringSuite) TestFormatKeyringKeyDescDifferentPrefix(c *C) {
	c.Check(FormatKeyringKeyDesc("/dev/sda1", KeyringKeyPurposeUnlock, "foo"), Equals, "foo:/dev/sda1:unlock")
}

type testAddKeyToUserKeyringLegacyParams struct {
	key     []byte
	path    string
	purpose KeyringKeyPurpose
	prefix  string
}

func (s *keyringSuite) testAddKeyToUserKeyringLegacy(c *C, params *testAddKeyToUserKeyringLegacyParams) {
	c.Assert(AddKeyToUserKeyringLegacy(params.key, params.path, params.purpose, params.prefix), IsNil)

	c.Assert(s.AddedKeys, HasLen, 1)
	addedId := s.AddedKeys[0]

	// Check the added key description
	desc, err := keyring.DescribeKey(addedId)
	c.Assert(err, IsNil)
	c.Check(desc.Type, Equals, keyring.UserKeyType)
	c.Check(desc.UID, Equals, uint32(os.Getuid()))
	c.Check(desc.GID, Equals, uint32(os.Getgid()))
	c.Check(desc.Perm, Equals, keyring.KeyPossessorAllPerms|keyring.KeyUserViewPerm)
	c.Check(desc.Desc, Equals, FormatKeyringKeyDesc(params.path, params.purpose, params.prefix))

	// Check the added key is in the user keyring
	keyringtest.CheckKeyInKeyring(c, addedId, keyring.UserKeyring)

	// Read back the key
	key, err := keyring.ReadKey(context.Background(), addedId)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, params.key)
}

func (s *keyringSuite) TestAddKeyToUserKeyringLegacy(c *C) {
	s.testAddKeyToUserKeyringLegacy(c, &testAddKeyToUserKeyringLegacyParams{
		key:     testutil.DecodeHexString(c, "cee3f393e3554db5e57389fd1b4a58e26843a4496c33f0d2f33eba5a523299d8"),
		path:    "/dev/sda1",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
	})
}

func (s *keyringSuite) TestAddKeyToUserKeyringLegacyDifferentKey(c *C) {
	s.testAddKeyToUserKeyringLegacy(c, &testAddKeyToUserKeyringLegacyParams{
		key:     testutil.DecodeHexString(c, "e2f7601d447a9a29d096a6470f27621dcc846ac4c82c30fae577c4ec4a53a0cb"),
		path:    "/dev/sda1",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
	})
}

func (s *keyringSuite) TestAddKeyToUserKeyringLegacyDifferentPath(c *C) {
	s.testAddKeyToUserKeyringLegacy(c, &testAddKeyToUserKeyringLegacyParams{
		key:     testutil.DecodeHexString(c, "cee3f393e3554db5e57389fd1b4a58e26843a4496c33f0d2f33eba5a523299d8"),
		path:    "/dev/nvme0n1p2",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "ubuntu-fde",
	})
}

func (s *keyringSuite) TestAddKeyToUserKeyringLegacyDifferentPurpose(c *C) {
	s.testAddKeyToUserKeyringLegacy(c, &testAddKeyToUserKeyringLegacyParams{
		key:     testutil.DecodeHexString(c, "cee3f393e3554db5e57389fd1b4a58e26843a4496c33f0d2f33eba5a523299d8"),
		path:    "/dev/sda1",
		purpose: KeyringKeyPurposeAuxiliary,
		prefix:  "ubuntu-fde",
	})
}

func (s *keyringSuite) TestAddKeyToUserKeyringLegacyDifferentPrefix(c *C) {
	s.testAddKeyToUserKeyringLegacy(c, &testAddKeyToUserKeyringLegacyParams{
		key:     testutil.DecodeHexString(c, "cee3f393e3554db5e57389fd1b4a58e26843a4496c33f0d2f33eba5a523299d8"),
		path:    "/dev/sda1",
		purpose: KeyringKeyPurposeUnlock,
		prefix:  "foo",
	})
}

func (s *keyringSuite) TestAddKeyToUserKeyringLegacyInvalidPrefix(c *C) {
	err := AddKeyToUserKeyringLegacy(nil, "/dev/sda1", KeyringKeyPurposeUnlock, "ubuntu:fde")
	c.Check(err, ErrorMatches, `invalid prefix`)
}

func (s *keyringSuite) TestAddKeyToUserKeyringLegacyInvalidPurpose(c *C) {
	err := AddKeyToUserKeyringLegacy(nil, "/dev/sda1", "unlock:foo", "ubuntu-fde")
	c.Check(err, ErrorMatches, `invalid purpose`)
}

func (s *keyringSuite) TestAddKeyToUserKeyringLegacyAddKeyErr(c *C) {
	err := AddKeyToUserKeyringLegacy(nil, "/dev/sda1", KeyringKeyPurposeUnlock, "ubuntu-fde")
	c.Check(err, ErrorMatches, `cannot complete operation because one or more arguments is invalid`)
	c.Check(errors.Is(err, keyring.ErrInvalidArgs), testutil.IsTrue)
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

	c.Check(AddKeyToUserKeyringLegacy(data.key, data.devicePath, KeyringKeyPurposeUnlock, prefix), IsNil)

	c.Assert(s.AddedKeys, HasLen, 1)
	addedId := s.AddedKeys[0]

	key, err := GetDiskUnlockKeyFromKernel(data.prefix, data.devicePath, false)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, data.key)
	keyringtest.CheckKeyInKeyring(c, addedId, keyring.UserKeyring)
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernel(c *C) {
	s.testGetDiskUnlockKeyFromKernel(c, &testGetDiskUnlockKeyFromKernelData{
		key:        testutil.DecodeHexString(c, "12bd560279b49c30ac014827c0356fdb9a968fead2f9ea83808d34189515af97"),
		devicePath: "/dev/sda1"})
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernelDifferentPath(c *C) {
	s.testGetDiskUnlockKeyFromKernel(c, &testGetDiskUnlockKeyFromKernelData{
		key:        testutil.DecodeHexString(c, "12bd560279b49c30ac014827c0356fdb9a968fead2f9ea83808d34189515af97"),
		devicePath: "/dev/nvme0n1p2"})
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernelDifferentPrefix(c *C) {
	s.testGetDiskUnlockKeyFromKernel(c, &testGetDiskUnlockKeyFromKernelData{
		key:        testutil.DecodeHexString(c, "12bd560279b49c30ac014827c0356fdb9a968fead2f9ea83808d34189515af97"),
		prefix:     "foo",
		devicePath: "/dev/sda1"})
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernelDifferentKey(c *C) {
	s.testGetDiskUnlockKeyFromKernel(c, &testGetDiskUnlockKeyFromKernelData{
		key:        testutil.DecodeHexString(c, "a2824435f358871b2f3b9cc269e50bd1ae71d607aa085188bfd0392995d7282a"),
		devicePath: "/dev/sda1"})
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernelNotFound1(c *C) {
	_, err := GetDiskUnlockKeyFromKernel("", "/dev/sda1", false)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernelNotFound2(c *C) {
	// Add a key with a different path
	c.Check(AddKeyToUserKeyringLegacy([]byte{1}, "/dev/nvme0n1p2", KeyringKeyPurposeUnlock, "ubuntu-fde"), IsNil)

	_, err := GetDiskUnlockKeyFromKernel("", "/dev/sda1", false)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernelNotFound3(c *C) {
	// Add a key with a different purpose
	c.Check(AddKeyToUserKeyringLegacy([]byte{1}, "/dev/nvme0n1p2", KeyringKeyPurposeAuxiliary, "ubuntu-fde"), IsNil)

	_, err := GetDiskUnlockKeyFromKernel("", "/dev/sda1", false)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernelNotFound4(c *C) {
	// Add a key with a different prefix
	c.Check(AddKeyToUserKeyringLegacy([]byte{1}, "/dev/sda1", KeyringKeyPurposeUnlock, "foo"), IsNil)

	_, err := GetPrimaryKeyFromKernel("", "/dev/sda1", false)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetDiskUnlockKeyFromKernelAndRemove(c *C) {
	key := DiskUnlockKey(testutil.DecodeHexString(c, "12bd560279b49c30ac014827c0356fdb9a968fead2f9ea83808d34189515af97"))

	c.Check(AddKeyToUserKeyringLegacy(key, "/dev/sda1", KeyringKeyPurposeUnlock, "ubuntu-fde"), IsNil)

	c.Assert(s.AddedKeys, HasLen, 1)
	addedId := s.AddedKeys[0]

	recoveredKey, err := GetDiskUnlockKeyFromKernel("", "/dev/sda1", true)
	c.Check(err, IsNil)
	c.Check(recoveredKey, DeepEquals, key)
	keyringtest.CheckKeyNotInKeyring(c, addedId, keyring.UserKeyring)
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

	c.Check(AddKeyToUserKeyringLegacy(data.key, data.devicePath, KeyringKeyPurposeAuxiliary, prefix), IsNil)

	c.Assert(s.AddedKeys, HasLen, 1)
	addedId := s.AddedKeys[0]

	key, err := GetPrimaryKeyFromKernel(data.prefix, data.devicePath, false)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, data.key)
	keyringtest.CheckKeyInKeyring(c, addedId, keyring.UserKeyring)
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernel(c *C) {
	s.testGetPrimaryKeyFromKernel(c, &testGetPrimaryKeyFromKernelData{
		key:        testutil.DecodeHexString(c, "c3e00a237a9f8dbf0fd66c473401054ba5232a1cf6564d52945d7726a464ffa9"),
		devicePath: "/dev/sda1"})
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernelDifferentPath(c *C) {
	s.testGetPrimaryKeyFromKernel(c, &testGetPrimaryKeyFromKernelData{
		key:        testutil.DecodeHexString(c, "c3e00a237a9f8dbf0fd66c473401054ba5232a1cf6564d52945d7726a464ffa9"),
		devicePath: "/dev/nvme0n1p2"})
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernelDifferentPrefix(c *C) {
	s.testGetPrimaryKeyFromKernel(c, &testGetPrimaryKeyFromKernelData{
		key:        testutil.DecodeHexString(c, "c3e00a237a9f8dbf0fd66c473401054ba5232a1cf6564d52945d7726a464ffa9"),
		prefix:     "bar",
		devicePath: "/dev/sda1"})
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernelDifferentKey(c *C) {
	s.testGetPrimaryKeyFromKernel(c, &testGetPrimaryKeyFromKernelData{
		key:        testutil.DecodeHexString(c, "45e7980983b500db40387038af99fcd21817f618c10e62eb757b480483a17548"),
		devicePath: "/dev/sda1"})
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernelNotFound1(c *C) {
	_, err := GetPrimaryKeyFromKernel("", "/dev/sda1", false)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernelNotFound2(c *C) {
	// Add a key with a different path
	c.Check(AddKeyToUserKeyringLegacy([]byte{1}, "/dev/nvme0n1p2", KeyringKeyPurposeAuxiliary, "ubuntu-fde"), IsNil)

	_, err := GetPrimaryKeyFromKernel("", "/dev/sda1", false)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernelNotFound3(c *C) {
	// Add a key with a different purpose
	c.Check(AddKeyToUserKeyringLegacy([]byte{1}, "/dev/nvme0n1p2", KeyringKeyPurposeUnlock, "ubuntu-fde"), IsNil)

	_, err := GetPrimaryKeyFromKernel("", "/dev/sda1", false)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernelNotFound4(c *C) {
	// Add a key with a different prefix
	c.Check(AddKeyToUserKeyringLegacy([]byte{1}, "/dev/sda1", KeyringKeyPurposeAuxiliary, "foo"), IsNil)

	_, err := GetPrimaryKeyFromKernel("", "/dev/sda1", false)
	c.Check(err, ErrorMatches, "cannot find key in kernel keyring")
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetPrimaryKeyFromKernelAndRemove(c *C) {
	key := PrimaryKey(testutil.DecodeHexString(c, "c3e00a237a9f8dbf0fd66c473401054ba5232a1cf6564d52945d7726a464ffa9"))

	c.Check(AddKeyToUserKeyringLegacy(key, "/dev/sda1", KeyringKeyPurposeAuxiliary, "ubuntu-fde"), IsNil)

	c.Assert(s.AddedKeys, HasLen, 1)
	addedId := s.AddedKeys[0]

	recoveredKey, err := GetPrimaryKeyFromKernel("", "/dev/sda1", true)
	c.Check(err, IsNil)
	c.Check(recoveredKey, DeepEquals, key)
	keyringtest.CheckKeyNotInKeyring(c, addedId, keyring.UserKeyring)
}

type testParseKeyringKeyDescParams struct {
	desc    string
	prefix  string
	name    string
	purpose KeyringKeyPurpose
	ok      bool
}

func (s *keyringSuite) testParseKeyringKeyDesc(c *C, params *testParseKeyringKeyDescParams) {
	prefix, name, purpose, ok := ParseKeyringKeyDesc(params.desc)
	c.Check(ok, Equals, params.ok)
	c.Check(prefix, Equals, params.prefix)
	c.Check(name, Equals, params.name)
	c.Check(purpose, Equals, params.purpose)
}

func (s *keyringSuite) TestParseKeyringKeyDesc(c *C) {
	s.testParseKeyringKeyDesc(c, &testParseKeyringKeyDescParams{
		desc:    "ubuntu-fde:/dev/sda1:unlock",
		prefix:  "ubuntu-fde",
		name:    "/dev/sda1",
		purpose: KeyringKeyPurposeUnlock,
		ok:      true,
	})
}

func (s *keyringSuite) TestParseKeyringKeyDescDifferentPrefix(c *C) {
	s.testParseKeyringKeyDesc(c, &testParseKeyringKeyDescParams{
		desc:    "foo:/dev/sda1:unlock",
		prefix:  "foo",
		name:    "/dev/sda1",
		purpose: KeyringKeyPurposeUnlock,
		ok:      true,
	})
}

func (s *keyringSuite) TestParseKeyringKeyDescDifferentName(c *C) {
	s.testParseKeyringKeyDesc(c, &testParseKeyringKeyDescParams{
		desc:    "ubuntu-fde:/dev/nvme0n1p2:unlock",
		prefix:  "ubuntu-fde",
		name:    "/dev/nvme0n1p2",
		purpose: KeyringKeyPurposeUnlock,
		ok:      true,
	})
}

func (s *keyringSuite) TestParseKeyringKeyDescDifferentPurpose(c *C) {
	s.testParseKeyringKeyDesc(c, &testParseKeyringKeyDescParams{
		desc:    "ubuntu-fde:/dev/sda1:primary",
		prefix:  "ubuntu-fde",
		name:    "/dev/sda1",
		purpose: KeyringKeyPurposePrimary,
		ok:      true,
	})
}

func (s *keyringSuite) TestParseKeyringKeyDescBad(c *C) {
	s.testParseKeyringKeyDesc(c, &testParseKeyringKeyDescParams{
		desc: "foo:bar",
		ok:   false,
	})
}

func (s *keyringSuite) TestParseKeyringKeyDescNameWithColon(c *C) {
	s.testParseKeyringKeyDesc(c, &testParseKeyringKeyDescParams{
		desc:    "ubuntu-fde:foo:bar:unlock",
		prefix:  "ubuntu-fde",
		name:    "foo:bar",
		purpose: KeyringKeyPurposeUnlock,
		ok:      true,
	})
}

type testAddKeyToUserKeyringParams struct {
	key       []byte
	container StorageContainer
	purpose   KeyringKeyPurpose
	prefix    string
}

func (s *keyringSuite) testAddKeyToUserKeyring(c *C, params *testAddKeyToUserKeyringParams) {
	c.Check(AddKeyToUserKeyring(params.key, params.container, params.purpose, params.prefix), IsNil)

	c.Assert(s.AddedKeys, HasLen, 1)
	addedId := s.AddedKeys[0]

	// Check the added key description
	desc, err := keyring.DescribeKey(addedId)
	c.Assert(err, IsNil)
	c.Check(desc.Type, Equals, keyring.UserKeyType)
	c.Check(desc.UID, Equals, uint32(os.Getuid()))
	c.Check(desc.GID, Equals, uint32(os.Getgid()))
	c.Check(desc.Perm, Equals, keyring.KeyPossessorAllPerms|keyring.KeyUserViewPerm)
	c.Check(desc.Desc, Equals, FormatKeyringKeyDesc(params.container.CredentialName(), params.purpose, params.prefix))

	// Check the added key is in the user keyring
	keyringtest.CheckKeyInKeyring(c, addedId, keyring.UserKeyring)

	// Read back the key
	key, err := keyring.ReadKey(context.Background(), addedId)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, params.key)
}

func (s *keyringSuite) TestAddKeyToUserKeyring(c *C) {
	s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:       testutil.DecodeHexString(c, "7434fd1fcb1f9e2a0dc67bf7a41fde30ca4c84cc6443a4c094798a1039ff536f"),
		container: newMockStorageContainer(withStorageContainerCredentialName("/dev/sda1")),
		purpose:   KeyringKeyPurposeUnlock,
		prefix:    "ubuntu-fde",
	})
}

func (s *keyringSuite) TestAddKeyToUserKeyringDifferentKey(c *C) {
	s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:       testutil.DecodeHexString(c, "6cbfdc112d8e5c1b886cfa4c2981530177a285420a5c2debdd36a7eef645da12"),
		container: newMockStorageContainer(withStorageContainerCredentialName("/dev/sda1")),
		purpose:   KeyringKeyPurposeUnlock,
		prefix:    "ubuntu-fde",
	})
}

func (s *keyringSuite) TestAddKeyToUserKeyringDifferentCredentialName(c *C) {
	s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:       testutil.DecodeHexString(c, "7434fd1fcb1f9e2a0dc67bf7a41fde30ca4c84cc6443a4c094798a1039ff536f"),
		container: newMockStorageContainer(withStorageContainerCredentialName("/dev/nvme0n1p2")),
		purpose:   KeyringKeyPurposeUnlock,
		prefix:    "ubuntu-fde",
	})
}

func (s *keyringSuite) TestAddKeyToUserKeyringDifferentPurpose(c *C) {
	s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:       testutil.DecodeHexString(c, "7434fd1fcb1f9e2a0dc67bf7a41fde30ca4c84cc6443a4c094798a1039ff536f"),
		container: newMockStorageContainer(withStorageContainerCredentialName("/dev/sda1")),
		purpose:   KeyringKeyPurposePrimary,
		prefix:    "ubuntu-fde",
	})
}

func (s *keyringSuite) TestAddKeyToUserKeyringDifferentPrefix(c *C) {
	s.testAddKeyToUserKeyring(c, &testAddKeyToUserKeyringParams{
		key:       testutil.DecodeHexString(c, "7434fd1fcb1f9e2a0dc67bf7a41fde30ca4c84cc6443a4c094798a1039ff536f"),
		container: newMockStorageContainer(withStorageContainerCredentialName("/dev/sda1")),
		purpose:   KeyringKeyPurposeUnlock,
		prefix:    "foo",
	})
}

func (s *keyringSuite) TestAddKeyToUserKeyringInvalidPrefix(c *C) {
	err := AddKeyToUserKeyring(nil, newMockStorageContainer(withStorageContainerCredentialName("/dev/sda1")), KeyringKeyPurposeUnlock, "ubuntu:fde")
	c.Check(err, ErrorMatches, `invalid prefix`)
}

func (s *keyringSuite) TestAddKeyToUserKeyringInvalidPurpose(c *C) {
	err := AddKeyToUserKeyring(nil, newMockStorageContainer(withStorageContainerCredentialName("/dev/sda1")), "unlock:foo", "ubuntu-fde")
	c.Check(err, ErrorMatches, `invalid purpose`)
}

func (s *keyringSuite) TestAddKeyToUserKeyringAddKeyErr(c *C) {
	err := AddKeyToUserKeyring(nil, newMockStorageContainer(withStorageContainerCredentialName("/dev/sda1")), KeyringKeyPurposeUnlock, "ubuntu-fde")
	c.Check(err, ErrorMatches, `cannot complete operation because one or more arguments is invalid`)
	c.Check(errors.Is(err, keyring.ErrInvalidArgs), testutil.IsTrue)
}

type testGetKeyFromKernelParams struct {
	key       []byte
	prefix    string
	container StorageContainer
	purpose   KeyringKeyPurpose
}

func (s *keyringSuite) testGetKeyFromKernel(c *C, params *testGetKeyFromKernelParams) {
	prefix := params.prefix
	if prefix == "" {
		prefix = "ubuntu-fde"
	}

	c.Check(AddKeyToUserKeyring(params.key, params.container, params.purpose, prefix), IsNil)

	c.Assert(s.AddedKeys, HasLen, 1)
	addedId := s.AddedKeys[0]

	key, err := GetKeyFromKernel(context.Background(), params.container, params.purpose, params.prefix)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, params.key)
	keyringtest.CheckKeyInKeyring(c, addedId, keyring.UserKeyring)
}

func (s *keyringSuite) TestGetKeyFromKernel(c *C) {
	s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:       testutil.DecodeHexString(c, "d39ba1f85c1a0144e34700c445d88833255dbe59f8c96bc590b26e39c8f81035"),
		container: newMockStorageContainer(withStorageContainerCredentialName("/dev/sda1")),
		purpose:   KeyringKeyPurposeUnlock,
	})
}

func (s *keyringSuite) TestGetKeyFromKernelDifferentKey(c *C) {
	s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:       testutil.DecodeHexString(c, "c943cac74ecd57438847327a6b7f61e619fd64346ac7b099584ee2ddf6a59ef6"),
		container: newMockStorageContainer(withStorageContainerCredentialName("/dev/sda1")),
		purpose:   KeyringKeyPurposeUnlock,
	})
}

func (s *keyringSuite) TestGetKeyFromKernelDifferentPrefix(c *C) {
	s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:       testutil.DecodeHexString(c, "d39ba1f85c1a0144e34700c445d88833255dbe59f8c96bc590b26e39c8f81035"),
		prefix:    "foo",
		container: newMockStorageContainer(withStorageContainerCredentialName("/dev/sda1")),
		purpose:   KeyringKeyPurposeUnlock,
	})
}

func (s *keyringSuite) TestGetKeyFromKernelDifferentCredentialName(c *C) {
	s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:       testutil.DecodeHexString(c, "d39ba1f85c1a0144e34700c445d88833255dbe59f8c96bc590b26e39c8f81035"),
		container: newMockStorageContainer(withStorageContainerCredentialName("/dev/nvme0n1p3")),
		purpose:   KeyringKeyPurposeUnlock,
	})
}

func (s *keyringSuite) TestGetKeyFromKernelDifferentPurpose(c *C) {
	s.testGetKeyFromKernel(c, &testGetKeyFromKernelParams{
		key:       testutil.DecodeHexString(c, "d39ba1f85c1a0144e34700c445d88833255dbe59f8c96bc590b26e39c8f81035"),
		container: newMockStorageContainer(withStorageContainerCredentialName("/dev/sda1")),
		purpose:   KeyringKeyPurposeUnlock,
	})
}

func (s *keyringSuite) TestGetKeyFromKernelCanceledContext(c *C) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	cancelFunc()

	container := newMockStorageContainer(withStorageContainerCredentialName("/dev/sda1"))

	c.Check(AddKeyToUserKeyring([]byte{1}, container, KeyringKeyPurposeUnlock, "ubuntu-fde"), IsNil)

	_, err := GetKeyFromKernel(ctx, container, KeyringKeyPurposeUnlock, "")
	c.Check(err, ErrorMatches, `context canceled`)
	c.Check(errors.Is(err, context.Canceled), testutil.IsTrue)
}

func (s *keyringSuite) TestGetKeyFromKernelNotFound1(c *C) {
	// Test where the container path points to a block device.
	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})

	_, err := GetKeyFromKernel(
		context.Background(),
		newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("/dev/sda1"),
		), KeyringKeyPurposeUnlock,
		"",
	)
	c.Check(err, ErrorMatches, `cannot find key in kernel keyring`)
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetKeyFromKernelNotFound2(c *C) {
	// Test where the container path doesn't point to anything
	_, err := GetKeyFromKernel(
		context.Background(),
		newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("/dev/sda1"),
		),
		KeyringKeyPurposeUnlock,
		"",
	)
	c.Check(err, ErrorMatches, `cannot find key in kernel keyring`)
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetKeyFromKernelNotFound3(c *C) {
	// Test where the container path doesn't point to a block device.
	s.addFileInfo("/", &unix.Stat_t{Mode: unix.S_IFDIR})

	_, err := GetKeyFromKernel(
		context.Background(),
		newMockStorageContainer(
			withStorageContainerPath("/"),
			withStorageContainerCredentialName("name"),
		),
		KeyringKeyPurposeUnlock,
		"",
	)
	c.Check(err, ErrorMatches, `cannot find key in kernel keyring`)
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetKeyFromKernelNotFound4(c *C) {
	// Add a key with a different name, where the name is a path that points to a block device.
	c.Check(AddKeyToUserKeyring([]byte{1}, newMockStorageContainer(withStorageContainerCredentialName("/dev/nvme0n1p3")), KeyringKeyPurposeUnlock, "ubuntu-fde"), IsNil)

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	s.addFileInfo("/dev/nvme0n1p3", &unix.Stat_t{Rdev: unix.Mkdev(259, 2), Mode: unix.S_IFBLK})

	_, err := GetKeyFromKernel(
		context.Background(),
		newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("/dev/sda1"),
		),
		KeyringKeyPurposeUnlock,
		"",
	)
	c.Check(err, ErrorMatches, `cannot find key in kernel keyring`)
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetKeyFromKernelNotFound5(c *C) {
	// Add a key with a different name, where the name is a path that doesn't point to anything.
	c.Check(AddKeyToUserKeyring([]byte{1}, newMockStorageContainer(withStorageContainerPath("/dev/nvme0n1p3")), KeyringKeyPurposeUnlock, "ubuntu-fde"), IsNil)

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})

	_, err := GetKeyFromKernel(
		context.Background(),
		newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("/dev/sda1"),
		),
		KeyringKeyPurposeUnlock,
		"",
	)
	c.Check(err, ErrorMatches, `cannot find key in kernel keyring`)
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetKeyFromKernelNotFound6(c *C) {
	// Add a key with a different name, where the name is a path that doesn't point to a block device.
	c.Check(AddKeyToUserKeyring([]byte{1}, newMockStorageContainer(withStorageContainerCredentialName("/")), KeyringKeyPurposeUnlock, "ubuntu-fde"), IsNil)

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	s.addFileInfo("/", &unix.Stat_t{Mode: unix.S_IFDIR})

	_, err := GetKeyFromKernel(
		context.Background(),
		newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("/dev/sda1"),
		),
		KeyringKeyPurposeUnlock,
		"",
	)
	c.Check(err, ErrorMatches, `cannot find key in kernel keyring`)
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetKeyFromKernelNotFound7(c *C) {
	container := newMockStorageContainer(
		withStorageContainerPath("/dev/sda1"),
		withStorageContainerCredentialName("/dev/sda1"),
	)

	// Add a key with a different purpose.
	c.Check(AddKeyToUserKeyring([]byte{1}, container, KeyringKeyPurposePrimary, "ubuntu-fde"), IsNil)

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})

	_, err := GetKeyFromKernel(context.Background(), container, KeyringKeyPurposeUnlock, "")
	c.Check(err, ErrorMatches, `cannot find key in kernel keyring`)
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetKeyFromKernelNotFound8(c *C) {
	container := newMockStorageContainer(
		withStorageContainerPath("/dev/sda1"),
		withStorageContainerCredentialName("/dev/sda1"),
	)

	// Add a key with a different purpose, but test that legacy behaviour
	// where a request for "primary" is tested against legacy keys with "aux"
	c.Check(AddKeyToUserKeyring([]byte{1}, container, KeyringKeyPurposeUnlock, "ubuntu-fde"), IsNil)

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})

	_, err := GetKeyFromKernel(context.Background(), container, KeyringKeyPurposePrimary, "")
	c.Check(err, ErrorMatches, `cannot find key in kernel keyring`)
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetKeyFromKernelNotFound9(c *C) {
	container := newMockStorageContainer(
		withStorageContainerPath("/dev/sda1"),
		withStorageContainerCredentialName("/dev/sda1"),
	)

	// Add a key with a different prefix.
	c.Check(AddKeyToUserKeyring([]byte{1}, container, KeyringKeyPurposeUnlock, "foo"), IsNil)

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})
	_, err := GetKeyFromKernel(context.Background(), container, KeyringKeyPurposeUnlock, "")
	c.Check(err, ErrorMatches, `cannot find key in kernel keyring`)
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetKeyFromKernelNotFound10(c *C) {
	// Add a key that isn't a user key.
	s.AddKey(c, nil, keyring.KeyringKeyType, "foo", keyring.UserKeyring)

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})

	_, err := GetKeyFromKernel(
		context.Background(),
		newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("/dev/sda1"),
		),
		KeyringKeyPurposeUnlock,
		"",
	)
	c.Check(err, ErrorMatches, `cannot find key in kernel keyring`)
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

func (s *keyringSuite) TestGetKeyFromKernelNotFound11(c *C) {
	// Add a key with the wrong description format.
	s.AddKey(c, []byte{1}, keyring.UserKeyType, "foo", keyring.UserKeyring)

	s.addFileInfo("/dev/sda1", &unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK})

	_, err := GetKeyFromKernel(
		context.Background(),
		newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("/dev/sda1"),
		),
		KeyringKeyPurposeUnlock,
		"",
	)
	c.Check(err, ErrorMatches, `cannot find key in kernel keyring`)
	c.Check(errors.Is(err, ErrKernelKeyNotFound), testutil.IsTrue)
}

type testGetKeyFromKernelWithLegacyAddKeyParams struct {
	fileInfo map[string]unix.Stat_t

	key           []byte
	prefix        string
	devicePath    string
	container     StorageContainer
	createPurpose KeyringKeyPurpose
	getPurpose    KeyringKeyPurpose
}

func (s *keyringSuite) testGetKeyFromKernelWithLegacyAddKey(c *C, params *testGetKeyFromKernelWithLegacyAddKeyParams) {
	s.addFileInfos(params.fileInfo)

	prefix := params.prefix
	if prefix == "" {
		prefix = "ubuntu-fde"
	}

	c.Check(AddKeyToUserKeyringLegacy(params.key, params.devicePath, params.createPurpose, prefix), IsNil)

	c.Assert(s.AddedKeys, HasLen, 1)
	addedId := s.AddedKeys[0]

	key, err := GetKeyFromKernel(context.Background(), params.container, params.getPurpose, params.prefix)
	c.Check(err, IsNil)
	c.Check(key, DeepEquals, params.key)
	keyringtest.CheckKeyInKeyring(c, addedId, keyring.UserKeyring)
}

func (s *keyringSuite) TestGetKeyFromKernelWithLegacyAddKey(c *C) {
	s.testGetKeyFromKernelWithLegacyAddKey(c, &testGetKeyFromKernelWithLegacyAddKeyParams{
		fileInfo: map[string]unix.Stat_t{
			"/dev/sda1": unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK},
		},
		key:        testutil.DecodeHexString(c, "d39ba1f85c1a0144e34700c445d88833255dbe59f8c96bc590b26e39c8f81035"),
		devicePath: "/dev/sda1",
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("name"),
		),
		createPurpose: KeyringKeyPurposeUnlock,
		getPurpose:    KeyringKeyPurposeUnlock,
	})
}

func (s *keyringSuite) TestGetKeyFromKernelWithLegacyAddKeySymlink(c *C) {
	s.testGetKeyFromKernelWithLegacyAddKey(c, &testGetKeyFromKernelWithLegacyAddKeyParams{
		fileInfo: map[string]unix.Stat_t{
			"/dev/sda1": unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK},
			"/dev/disk/by-uuid/f1a12dae-f794-4a40-83a7-731429364417": unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK},
		},
		key:        testutil.DecodeHexString(c, "d39ba1f85c1a0144e34700c445d88833255dbe59f8c96bc590b26e39c8f81035"),
		devicePath: "/dev/disk/by-uuid/f1a12dae-f794-4a40-83a7-731429364417",
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("name"),
		),
		createPurpose: KeyringKeyPurposeUnlock,
		getPurpose:    KeyringKeyPurposeUnlock,
	})
}

func (s *keyringSuite) TestGetKeyFromKernelWithLegacyAddKeyDifferentPath(c *C) {
	s.testGetKeyFromKernelWithLegacyAddKey(c, &testGetKeyFromKernelWithLegacyAddKeyParams{
		fileInfo: map[string]unix.Stat_t{
			"/dev/nvme0n1p2": unix.Stat_t{Rdev: unix.Mkdev(259, 2), Mode: unix.S_IFBLK},
		},
		key:        testutil.DecodeHexString(c, "d39ba1f85c1a0144e34700c445d88833255dbe59f8c96bc590b26e39c8f81035"),
		devicePath: "/dev/nvme0n1p2",
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/nvme0n1p2"),
			withStorageContainerCredentialName("name"),
		),
		createPurpose: KeyringKeyPurposeUnlock,
		getPurpose:    KeyringKeyPurposeUnlock,
	})
}

func (s *keyringSuite) TestGetKeyFromKernelWithLegacyAddKeyDifferentPurpose(c *C) {
	s.testGetKeyFromKernelWithLegacyAddKey(c, &testGetKeyFromKernelWithLegacyAddKeyParams{
		fileInfo: map[string]unix.Stat_t{
			"/dev/sda1": unix.Stat_t{Rdev: unix.Mkdev(8, 1), Mode: unix.S_IFBLK},
		},
		key:        testutil.DecodeHexString(c, "d39ba1f85c1a0144e34700c445d88833255dbe59f8c96bc590b26e39c8f81035"),
		devicePath: "/dev/sda1",
		container: newMockStorageContainer(
			withStorageContainerPath("/dev/sda1"),
			withStorageContainerCredentialName("name"),
		),
		createPurpose: KeyringKeyPurposeAuxiliary,
		getPurpose:    KeyringKeyPurposePrimary,
	})
}
