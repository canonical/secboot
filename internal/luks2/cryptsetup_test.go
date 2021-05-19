// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package luks2_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	. "github.com/snapcore/secboot/internal/luks2"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"
)

type cryptsetupSuite struct {
	snapd_testutil.BaseTest
}

func (s *cryptsetupSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.AddCleanup(MockRunDir(c.MkDir()))

	cryptsetupWrapperBottom := `
# Set max locked memory to 0. Without this and without CAP_IPC_LOCK, mlockall will
# succeed but subsequent calls to mmap will fail because the limit is too low. Setting
# this to 0 here will cause mlockall to fail, which cryptsetup ignores.
ulimit -l 0
exec %[1]s "$@" </dev/stdin
`

	cryptsetup, err := exec.LookPath("cryptsetup")
	c.Assert(err, IsNil)

	cryptsetupWrapper := snapd_testutil.MockCommand(c, "cryptsetup", fmt.Sprintf(cryptsetupWrapperBottom, cryptsetup))
	s.AddCleanup(cryptsetupWrapper.Restore)
}

func (s *cryptsetupSuite) createEmptyDiskImage(c *C, sz int) string {
	f, err := os.OpenFile(filepath.Join(c.MkDir(), "disk.img"), os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	c.Assert(f.Truncate(int64(sz)*1024*1024), IsNil)
	return f.Name()
}

func (s *cryptsetupSuite) checkLUKS2Passphrase(c *C, path string, key []byte) {
	cmd := exec.Command("cryptsetup", "open", "--test-passphrase", "--key-file", "-", path)
	cmd.Stdin = bytes.NewReader(key)
	c.Check(cmd.Run(), IsNil)
}

var _ = Suite(&cryptsetupSuite{})

type testFormatData struct {
	label   string
	key     []byte
	options *FormatOptions
}

func (s *cryptsetupSuite) testFormat(c *C, data *testFormatData) {
	devicePath := s.createEmptyDiskImage(c, 20)

	c.Check(Format(devicePath, data.label, data.key, data.options), IsNil)

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)

	c.Check(info.Label, Equals, data.label)

	c.Check(info.Metadata.Keyslots, HasLen, 1)
	keyslot, ok := info.Metadata.Keyslots[0]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.KeySize, Equals, 64)
	c.Check(keyslot.Priority, Equals, SlotPriorityNormal)
	c.Assert(keyslot.KDF, NotNil)
	c.Check(keyslot.KDF.Type, Equals, KDFTypeArgon2i)

	c.Check(info.Metadata.Segments, HasLen, 1)
	segment, ok := info.Metadata.Segments[0]
	c.Assert(ok, Equals, true)
	c.Check(segment.Encryption, Equals, "aes-xts-plain64")

	c.Check(info.Metadata.Tokens, HasLen, 0)

	expectedMetadataSize := uint64(16 * 1024)
	if data.options.MetadataKiBSize > 0 {
		expectedMetadataSize = uint64(data.options.MetadataKiBSize * 1024)
	}
	expectedKeyslotsSize := uint64(16*1024*1024) - (2 * expectedMetadataSize)
	if data.options.KeyslotsAreaKiBSize > 0 {
		expectedKeyslotsSize = uint64(data.options.KeyslotsAreaKiBSize * 1024)
	}

	c.Check(info.Metadata.Config.JSONSize, Equals, expectedMetadataSize-uint64(4*1024))
	c.Check(info.Metadata.Config.KeyslotsSize, Equals, expectedKeyslotsSize)

	expectedKDFTime := 2000 * time.Millisecond
	if data.options.KDFTime > 0 {
		expectedKDFTime = data.options.KDFTime
	}

	start := time.Now()
	s.checkLUKS2Passphrase(c, devicePath, data.key)
	elapsed := time.Now().Sub(start)
	// Check KDF time here with +/-20% tolerance and additional 500ms for cryptsetup exec and other activities
	c.Check(int(elapsed/time.Millisecond), snapd_testutil.IntGreaterThan, int(float64(expectedKDFTime/time.Millisecond)*0.8))
	c.Check(int(elapsed/time.Millisecond), snapd_testutil.IntLessThan, int(float64(expectedKDFTime/time.Millisecond)*1.2)+500)
}

func (s *cryptsetupSuite) TestFormat1(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:   "test",
		key:     key,
		options: &FormatOptions{KDFTime: 100 * time.Millisecond}})
}

func (s *cryptsetupSuite) TestFormat2(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:   "data",
		key:     key,
		options: &FormatOptions{KDFTime: 100 * time.Millisecond}})
}

func (s *cryptsetupSuite) TestFormat3(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label:   "test",
		key:     key,
		options: &FormatOptions{}})
}

func (s *cryptsetupSuite) TestFormat4(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label: "test",
		key:   key,
		options: &FormatOptions{
			KDFTime:         100 * time.Millisecond,
			MetadataKiBSize: 2 * 1024}})
}

func (s *cryptsetupSuite) TestFormat5(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label: "test",
		key:   key,
		options: &FormatOptions{
			KDFTime:             100 * time.Millisecond,
			KeyslotsAreaKiBSize: 2 * 1024}})
}

type testAddKeyData struct {
	key  []byte
	time time.Duration
}

func (s *cryptsetupSuite) testAddKey(c *C, data *testAddKeyData) {
	primaryKey := make([]byte, 32)
	rand.Read(primaryKey)

	devicePath := s.createEmptyDiskImage(c, 20)
	c.Assert(Format(devicePath, "", primaryKey, &FormatOptions{KDFTime: 100 * time.Millisecond}), IsNil)

	startInfo, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)

	c.Check(AddKey(devicePath, primaryKey, data.key, data.time), IsNil)

	endInfo, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)

	newSlotId := -1
	for s := range endInfo.Metadata.Keyslots {
		if _, ok := startInfo.Metadata.Keyslots[s]; !ok {
			newSlotId = int(s)
			break
		}
	}

	c.Assert(newSlotId, snapd_testutil.IntGreaterThan, -1)
	c.Check(endInfo.Metadata.Keyslots, HasLen, 2)
	keyslot, ok := endInfo.Metadata.Keyslots[newSlotId]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.KeySize, Equals, 64)
	c.Check(keyslot.Priority, Equals, SlotPriorityNormal)
	c.Assert(keyslot.KDF, NotNil)
	c.Check(keyslot.KDF.Type, Equals, KDFTypeArgon2i)

	expectedKDFTime := 2000 * time.Millisecond
	if data.time > 0 {
		expectedKDFTime = data.time
	}

	start := time.Now()
	s.checkLUKS2Passphrase(c, devicePath, data.key)
	elapsed := time.Now().Sub(start)
	// Check KDF time here with +/-20% tolerance and additional 500ms for cryptsetup exec and other activities
	c.Check(int(elapsed/time.Millisecond), snapd_testutil.IntGreaterThan, int(float64(expectedKDFTime/time.Millisecond)*0.8))
	c.Check(int(elapsed/time.Millisecond), snapd_testutil.IntLessThan, int(float64(expectedKDFTime/time.Millisecond)*1.2)+500)
}

func (s *cryptsetupSuite) TestAddKey1(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key:  key,
		time: 100 * time.Millisecond})
}

func (s *cryptsetupSuite) TestAddKey2(c *C) {
	s.testAddKey(c, &testAddKeyData{key: []byte("foo")})
}

func (s *cryptsetupSuite) TestAddKeyWithIncorrectExistingKey(c *C) {
	primaryKey := make([]byte, 32)
	rand.Read(primaryKey)

	devicePath := s.createEmptyDiskImage(c, 20)

	c.Assert(Format(devicePath, "", primaryKey, &FormatOptions{KDFTime: 100 * time.Millisecond}), IsNil)

	c.Check(AddKey(devicePath, make([]byte, 32), []byte("foo"), 0), ErrorMatches, "No key available with this passphrase.")

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Keyslots, HasLen, 1)
	_, ok := info.Metadata.Keyslots[0]
	c.Check(ok, Equals, true)

	s.checkLUKS2Passphrase(c, devicePath, primaryKey)
}

type testImportTokenData struct {
	token          *Token
	expectedParams map[string]interface{}
}

func (s *cryptsetupSuite) testImportToken(c *C, data *testImportTokenData) {
	devicePath := s.createEmptyDiskImage(c, 20)
	c.Assert(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFTime: 100 * time.Millisecond}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 32), make([]byte, 32), 100*time.Millisecond), IsNil)

	c.Check(ImportToken(devicePath, data.token), IsNil)

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)

	c.Assert(info.Metadata.Tokens, HasLen, 1)
	token, ok := info.Metadata.Tokens[0]
	c.Assert(ok, Equals, true)
	c.Check(token.Type, Equals, data.token.Type)
	c.Check(token.Keyslots, DeepEquals, data.token.Keyslots)
	c.Check(token.Params, DeepEquals, data.expectedParams)
}

func (s *cryptsetupSuite) TestImportToken1(c *C) {
	data := make([]byte, 128)
	rand.Read(data)

	s.testImportToken(c, &testImportTokenData{
		token: &Token{
			Type:     "secboot-test",
			Keyslots: []int{0},
			Params: map[string]interface{}{
				"secboot-a": 50,
				"secboot-b": data}},
		expectedParams: map[string]interface{}{
			"secboot-a": float64(50),
			"secboot-b": base64.StdEncoding.EncodeToString(data)}})
}

func (s *cryptsetupSuite) TestImportToken2(c *C) {
	data := make([]byte, 128)
	rand.Read(data)

	s.testImportToken(c, &testImportTokenData{
		token: &Token{
			Type:     "secboot-test-2",
			Keyslots: []int{1},
			Params: map[string]interface{}{
				"secboot-a": true,
				"secboot-b": data}},
		expectedParams: map[string]interface{}{
			"secboot-a": true,
			"secboot-b": base64.StdEncoding.EncodeToString(data)}})
}

func (s *cryptsetupSuite) TestImportToken3(c *C) {
	data := make([]byte, 128)
	rand.Read(data)

	s.testImportToken(c, &testImportTokenData{
		token: &Token{
			Type:     "secboot-test",
			Keyslots: []int{0, 1},
			Params: map[string]interface{}{
				"secboot-a": 50,
				"secboot-b": data}},
		expectedParams: map[string]interface{}{
			"secboot-a": float64(50),
			"secboot-b": base64.StdEncoding.EncodeToString(data)}})
}

func (s *cryptsetupSuite) testRemoveToken(c *C, tokenId int) {
	devicePath := s.createEmptyDiskImage(c, 20)
	c.Assert(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFTime: 100 * time.Millisecond}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 32), make([]byte, 32), 100*time.Millisecond), IsNil)
	c.Assert(ImportToken(devicePath, &Token{Type: "secboot-foo", Keyslots: []int{0}}), IsNil)
	c.Assert(ImportToken(devicePath, &Token{Type: "secboot-bar", Keyslots: []int{1}}), IsNil)

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Tokens, HasLen, 2)
	_, ok := info.Metadata.Tokens[tokenId]
	c.Check(ok, Equals, true)

	c.Check(RemoveToken(devicePath, tokenId), IsNil)

	info, err = ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Tokens, HasLen, 1)
	_, ok = info.Metadata.Tokens[tokenId]
	c.Check(ok, Equals, false)
}

func (s *cryptsetupSuite) TestRemoveToken1(c *C) {
	s.testRemoveToken(c, 0)
}

func (s *cryptsetupSuite) TestRemoveToken2(c *C) {
	s.testRemoveToken(c, 1)
}

func (s *cryptsetupSuite) TestRemoveNonExistantToken(c *C) {
	devicePath := s.createEmptyDiskImage(c, 20)
	c.Assert(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFTime: 100 * time.Millisecond}), IsNil)
	c.Assert(ImportToken(devicePath, &Token{Type: "secboot-foo", Keyslots: []int{0}}), IsNil)

	c.Check(RemoveToken(devicePath, 10), ErrorMatches, "Token 10 is not in use.")

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Tokens, HasLen, 1)
	_, ok := info.Metadata.Tokens[0]
	c.Check(ok, Equals, true)
}

type testKillSlotData struct {
	key1    []byte
	key2    []byte
	key     []byte
	slotId  int
	testKey []byte
}

func (s *cryptsetupSuite) testKillSlot(c *C, data *testKillSlotData) {
	devicePath := s.createEmptyDiskImage(c, 20)
	c.Assert(Format(devicePath, "", data.key1, &FormatOptions{KDFTime: 100 * time.Millisecond}), IsNil)
	c.Assert(AddKey(devicePath, data.key1, data.key2, 100*time.Millisecond), IsNil)

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Keyslots, HasLen, 2)
	_, ok := info.Metadata.Keyslots[data.slotId]
	c.Check(ok, Equals, true)

	c.Check(KillSlot(devicePath, data.slotId, data.key), IsNil)

	info, err = ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Keyslots, HasLen, 1)
	_, ok = info.Metadata.Keyslots[data.slotId]
	c.Check(ok, Equals, false)

	s.checkLUKS2Passphrase(c, devicePath, data.testKey)
}

func (s *cryptsetupSuite) TestKillSlot1(c *C) {
	key1 := make([]byte, 32)
	rand.Read(key1)
	key2 := make([]byte, 32)
	rand.Read(key2)

	s.testKillSlot(c, &testKillSlotData{
		key1:    key1,
		key2:    key2,
		key:     key1,
		slotId:  1,
		testKey: key1})
}

func (s *cryptsetupSuite) TestKillSlot2(c *C) {
	key1 := make([]byte, 32)
	rand.Read(key1)
	key2 := make([]byte, 32)
	rand.Read(key2)

	s.testKillSlot(c, &testKillSlotData{
		key1:    key1,
		key2:    key2,
		key:     key2,
		slotId:  0,
		testKey: key2})
}

func (s *cryptsetupSuite) TestKillSlotWithWrongPassphrase(c *C) {
	key1 := make([]byte, 32)
	rand.Read(key1)
	key2 := make([]byte, 32)
	rand.Read(key2)

	devicePath := s.createEmptyDiskImage(c, 20)
	c.Assert(Format(devicePath, "", key1, &FormatOptions{KDFTime: 100 * time.Millisecond}), IsNil)
	c.Assert(AddKey(devicePath, key1, key2, 100*time.Millisecond), IsNil)

	c.Check(KillSlot(devicePath, 1, key2), ErrorMatches, "No key available with this passphrase.")

	s.checkLUKS2Passphrase(c, devicePath, key1)
	s.checkLUKS2Passphrase(c, devicePath, key2)
}

func (s *cryptsetupSuite) TestKillNonExistantSlot(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	devicePath := s.createEmptyDiskImage(c, 20)
	c.Assert(Format(devicePath, "", key, &FormatOptions{KDFTime: 100 * time.Millisecond}), IsNil)

	c.Check(KillSlot(devicePath, 8, key), ErrorMatches, "Keyslot 8 is not active.")

	s.checkLUKS2Passphrase(c, devicePath, key)
}

type testSetSlotPriorityData struct {
	slotId   int
	priority SlotPriority
}

func (s *cryptsetupSuite) testSetSlotPriority(c *C, data *testSetSlotPriorityData) {
	devicePath := s.createEmptyDiskImage(c, 20)
	c.Assert(Format(devicePath, "", make([]byte, 32), &FormatOptions{KDFTime: 100 * time.Millisecond}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 32), make([]byte, 32), 100*time.Millisecond), IsNil)

	info, err := ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	keyslot, ok := info.Metadata.Keyslots[data.slotId]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.Priority, Equals, SlotPriorityNormal)

	c.Check(SetSlotPriority(devicePath, data.slotId, data.priority), IsNil)

	info, err = ReadHeader(devicePath, LockModeBlocking)
	c.Assert(err, IsNil)
	keyslot, ok = info.Metadata.Keyslots[data.slotId]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.Priority, Equals, data.priority)
}

func (s *cryptsetupSuite) TestSetSlotPriority1(c *C) {
	s.testSetSlotPriority(c, &testSetSlotPriorityData{
		slotId:   0,
		priority: SlotPriorityHigh})
}

func (s *cryptsetupSuite) TestSetSlotPriority2(c *C) {
	s.testSetSlotPriority(c, &testSetSlotPriorityData{
		slotId:   1,
		priority: SlotPriorityHigh})
}

func (s *cryptsetupSuite) TestSetSlotPriority3(c *C) {
	s.testSetSlotPriority(c, &testSetSlotPriorityData{
		slotId:   1,
		priority: SlotPriorityIgnore})
}
