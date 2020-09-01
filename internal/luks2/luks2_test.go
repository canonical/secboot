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

package luks2_test

import (
	"encoding/base64"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	. "github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type luks2Suite struct {
	snapd_testutil.BaseTest
}

func (s *luks2Suite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.AddCleanup(testutil.MockRunDir(c.MkDir()))

	cryptsetupWrapper := testutil.WrapCryptsetup(c)
	s.AddCleanup(cryptsetupWrapper.Restore)
}

func (s *luks2Suite) createEmptyDiskImage(c *C) string {
	f, err := os.OpenFile(filepath.Join(c.MkDir(), "disk.img"), os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	c.Assert(f.Truncate(20*1024*1024), IsNil)
	return f.Name()
}

var _ = Suite(&luks2Suite{})

func (s *luks2Suite) TestAcquireSharedLockOnFile(c *C) {
	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	release, err := AcquireLock(path, LockModeShared)
	c.Assert(err, IsNil)

	err = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	c.Check(err, IsNil)

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, ErrorMatches, "resource temporarily unavailable")

	release()

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	c.Check(err, IsNil)
}

func (s *luks2Suite) TestAcquireExclusiveLockOnFile(c *C) {
	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	release, err := AcquireLock(path, LockModeExclusive)
	c.Assert(err, IsNil)

	err = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	c.Check(err, ErrorMatches, "resource temporarily unavailable")

	release()

	err = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	c.Check(err, IsNil)
}

func (s *luks2Suite) TestTryAcquireExclusiveLockOnFile(c *C) {
	path := filepath.Join(c.MkDir(), "disk")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	c.Assert(err, IsNil)
	defer f.Close()

	err = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	c.Assert(err, IsNil)

	_, err = AcquireLock(path, LockModeExclusive|LockModeTry)
	c.Check(err, ErrorMatches, "cannot obtain lock: resource temporarily unavailable")

	err = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	c.Assert(err, IsNil)

	_, err = AcquireLock(path, LockModeExclusive|LockModeTry)
	c.Check(err, IsNil)
}

func (s *luks2Suite) TestAcquireLockOnUnsupportedFile(c *C) {
	_, err := AcquireLock("/dev/null", LockModeShared)
	c.Check(err, ErrorMatches, "unsupported file type")
}

// TODO: Figure out how to test locking against block devices

type testFormatData struct {
	label string
	key   []byte
	kdf   *KDFOptions
}

func (s *luks2Suite) testFormat(c *C, data *testFormatData) {
	devicePath := s.createEmptyDiskImage(c)
	releaseLock, err := AcquireLock(devicePath, LockModeExclusive)
	c.Assert(err, IsNil)

	c.Check(Format(devicePath, data.label, data.key, data.kdf), IsNil)

	info, err := DecodeHdr(devicePath)
	c.Assert(err, IsNil)

	c.Check(info.Label, Equals, data.label)

	c.Check(info.Metadata.Keyslots, HasLen, 1)
	keyslot, ok := info.Metadata.Keyslots[0]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.KeySize, Equals, 64)
	c.Assert(keyslot.Priority, IsNil)
	c.Assert(keyslot.KDF, NotNil)
	c.Check(keyslot.KDF.Type, Equals, "argon2i")
	if data.kdf.Master {
		c.Check(keyslot.KDF.Time, Equals, 4)
		c.Check(keyslot.KDF.Memory, Equals, 32)
	}

	c.Check(info.Metadata.Segments, HasLen, 1)
	segment, ok := info.Metadata.Segments[0]
	c.Assert(ok, Equals, true)
	c.Check(segment.Encryption, Equals, "aes-xts-plain64")

	c.Check(info.Metadata.Tokens, HasLen, 0)

	releaseLock()
	testutil.CheckLUKS2Passphrase(c, devicePath, data.key)
}

func (s *luks2Suite) TestFormat1(c *C) {
	key := make([]byte, 64)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label: "test",
		key:   key,
		kdf:   &KDFOptions{Master: true}})
}

func (s *luks2Suite) TestFormat2(c *C) {
	key := make([]byte, 64)
	rand.Read(key)
	s.testFormat(c, &testFormatData{
		label: "data",
		key:   key,
		kdf:   &KDFOptions{Master: true}})
}

func (s *luks2Suite) TestFormat3(c *C) {
	s.testFormat(c, &testFormatData{
		label: "test",
		key:   []byte("foo"),
		kdf:   &KDFOptions{}})
}

type testAddKeyData struct {
	key []byte
	kdf *KDFOptions
}

func (s *luks2Suite) testAddKey(c *C, data *testAddKeyData) {
	masterKey := make([]byte, 64)
	rand.Read(masterKey)

	devicePath := s.createEmptyDiskImage(c)
	releaseLock, err := AcquireLock(devicePath, LockModeExclusive)
	c.Assert(err, IsNil)
	c.Assert(Format(devicePath, "", masterKey, &KDFOptions{Master: true}), IsNil)

	startInfo, err := DecodeHdr(devicePath)
	c.Assert(err, IsNil)

	c.Check(AddKey(devicePath, masterKey, data.key, data.kdf), IsNil)

	endInfo, err := DecodeHdr(devicePath)
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
	keyslot, ok := endInfo.Metadata.Keyslots[Ints(newSlotId)]
	c.Assert(ok, Equals, true)
	c.Check(keyslot.KeySize, Equals, 64)
	c.Assert(keyslot.Priority, IsNil)
	c.Assert(keyslot.KDF, NotNil)
	c.Check(keyslot.KDF.Type, Equals, "argon2i")
	if data.kdf.Master {
		c.Check(keyslot.KDF.Time, Equals, 4)
		c.Check(keyslot.KDF.Memory, Equals, 32)
	}

	releaseLock()
	testutil.CheckLUKS2Passphrase(c, devicePath, data.key)
}

func (s *luks2Suite) TestAddKey1(c *C) {
	key := make([]byte, 64)
	rand.Read(key)

	s.testAddKey(c, &testAddKeyData{
		key: key,
		kdf: &KDFOptions{Master: true}})
}

func (s *luks2Suite) TestAddKey2(c *C) {
	s.testAddKey(c, &testAddKeyData{
		key: []byte("foo"),
		kdf: &KDFOptions{}})
}

func (s *luks2Suite) TestAddKeyWithIncorrectExistingKey(c *C) {
	masterKey := make([]byte, 64)
	rand.Read(masterKey)

	devicePath := s.createEmptyDiskImage(c)
	releaseLock, err := AcquireLock(devicePath, LockModeExclusive)
	c.Assert(err, IsNil)
	c.Assert(Format(devicePath, "", masterKey, &KDFOptions{Master: true}), IsNil)

	c.Check(AddKey(devicePath, make([]byte, 64), []byte("foo"), &KDFOptions{}), ErrorMatches, "No key available with this passphrase.")

	info, err := DecodeHdr(devicePath)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Keyslots, HasLen, 1)
	_, ok := info.Metadata.Keyslots[0]
	c.Check(ok, Equals, true)

	releaseLock()
	testutil.CheckLUKS2Passphrase(c, devicePath, masterKey)
}

type testImportTokenData struct {
	token          *Token
	expectedParams map[string]interface{}
}

func (s *luks2Suite) testImportToken(c *C, data *testImportTokenData) {
	devicePath := s.createEmptyDiskImage(c)
	_, err := AcquireLock(devicePath, LockModeExclusive)
	c.Assert(err, IsNil)
	c.Assert(Format(devicePath, "", make([]byte, 64), &KDFOptions{Master: true}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 64), make([]byte, 64), &KDFOptions{Master: true}), IsNil)

	c.Check(ImportToken(devicePath, data.token), IsNil)

	info, err := DecodeHdr(devicePath)
	c.Assert(err, IsNil)

	c.Assert(info.Metadata.Tokens, HasLen, 1)
	token, ok := info.Metadata.Tokens[0]
	c.Assert(ok, Equals, true)
	c.Check(token.Type, Equals, data.token.Type)
	c.Check(token.Keyslots, DeepEquals, data.token.Keyslots)
	c.Check(token.Params, DeepEquals, data.expectedParams)
}

func (s *luks2Suite) TestImportToken1(c *C) {
	data := make([]byte, 128)
	rand.Read(data)

	s.testImportToken(c, &testImportTokenData{
		token: &Token{
			Type:     "secboot-test",
			Keyslots: []Ints{Ints(0)},
			Params: map[string]interface{}{
				"secboot-a": 50,
				"secboot-b": data}},
		expectedParams: map[string]interface{}{
			"secboot-a": float64(50),
			"secboot-b": base64.StdEncoding.EncodeToString(data)}})
}

func (s *luks2Suite) TestImportToken2(c *C) {
	data := make([]byte, 128)
	rand.Read(data)

	s.testImportToken(c, &testImportTokenData{
		token: &Token{
			Type:     "secboot-test-2",
			Keyslots: []Ints{Ints(1)},
			Params: map[string]interface{}{
				"secboot-a": true,
				"secboot-b": data}},
		expectedParams: map[string]interface{}{
			"secboot-a": true,
			"secboot-b": base64.StdEncoding.EncodeToString(data)}})
}

func (s *luks2Suite) TestImportToken3(c *C) {
	data := make([]byte, 128)
	rand.Read(data)

	s.testImportToken(c, &testImportTokenData{
		token: &Token{
			Type:     "secboot-test",
			Keyslots: []Ints{Ints(0), Ints(1)},
			Params: map[string]interface{}{
				"secboot-a": 50,
				"secboot-b": data}},
		expectedParams: map[string]interface{}{
			"secboot-a": float64(50),
			"secboot-b": base64.StdEncoding.EncodeToString(data)}})
}

func (s *luks2Suite) testRemoveToken(c *C, tokenId int) {
	devicePath := s.createEmptyDiskImage(c)
	_, err := AcquireLock(devicePath, LockModeExclusive)
	c.Assert(err, IsNil)
	c.Assert(Format(devicePath, "", make([]byte, 64), &KDFOptions{Master: true}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 64), make([]byte, 64), &KDFOptions{Master: true}), IsNil)
	c.Assert(ImportToken(devicePath, &Token{Type: "secboot-foo", Keyslots: []Ints{Ints(0)}}), IsNil)
	c.Assert(ImportToken(devicePath, &Token{Type: "secboot-bar", Keyslots: []Ints{Ints(1)}}), IsNil)

	info, err := DecodeHdr(devicePath)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Tokens, HasLen, 2)
	_, ok := info.Metadata.Tokens[Ints(tokenId)]
	c.Check(ok, Equals, true)

	c.Check(RemoveToken(devicePath, tokenId), IsNil)

	info, err = DecodeHdr(devicePath)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Tokens, HasLen, 1)
	_, ok = info.Metadata.Tokens[Ints(tokenId)]
	c.Check(ok, Equals, false)
}

func (s *luks2Suite) TestRemoveToken1(c *C) {
	s.testRemoveToken(c, 0)
}

func (s *luks2Suite) TestRemoveToken2(c *C) {
	s.testRemoveToken(c, 1)
}

func (s *luks2Suite) TestRemoveNonExistantToken(c *C) {
	devicePath := s.createEmptyDiskImage(c)
	c.Assert(Format(devicePath, "", make([]byte, 64), &KDFOptions{Master: true}), IsNil)
	c.Assert(ImportToken(devicePath, &Token{Type: "secboot-foo", Keyslots: []Ints{Ints(0)}}), IsNil)

	c.Check(RemoveToken(devicePath, 10), ErrorMatches, "Token 10 is not in use.")

	info, err := DecodeHdr(devicePath)
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

func (s *luks2Suite) testKillSlot(c *C, data *testKillSlotData) {
	devicePath := s.createEmptyDiskImage(c)
	releaseLock, err := AcquireLock(devicePath, LockModeExclusive)
	c.Assert(err, IsNil)
	c.Assert(Format(devicePath, "", data.key1, &KDFOptions{Master: true}), IsNil)
	c.Assert(AddKey(devicePath, data.key1, data.key2, &KDFOptions{Master: true}), IsNil)

	info, err := DecodeHdr(devicePath)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Keyslots, HasLen, 2)
	_, ok := info.Metadata.Keyslots[Ints(data.slotId)]
	c.Check(ok, Equals, true)

	c.Check(KillSlot(devicePath, data.slotId, data.key), IsNil)

	info, err = DecodeHdr(devicePath)
	c.Assert(err, IsNil)
	c.Check(info.Metadata.Keyslots, HasLen, 1)
	_, ok = info.Metadata.Keyslots[Ints(data.slotId)]
	c.Check(ok, Equals, false)

	releaseLock()
	testutil.CheckLUKS2Passphrase(c, devicePath, data.testKey)
}

func (s *luks2Suite) TestKillSlot1(c *C) {
	key1 := make([]byte, 64)
	rand.Read(key1)
	key2 := make([]byte, 64)
	rand.Read(key2)

	s.testKillSlot(c, &testKillSlotData{
		key1:    key1,
		key2:    key2,
		key:     key1,
		slotId:  1,
		testKey: key1})
}

func (s *luks2Suite) TestKillSlot2(c *C) {
	key1 := make([]byte, 64)
	rand.Read(key1)
	key2 := make([]byte, 64)
	rand.Read(key2)

	s.testKillSlot(c, &testKillSlotData{
		key1:    key1,
		key2:    key2,
		key:     key2,
		slotId:  0,
		testKey: key2})
}

func (s *luks2Suite) TestKillSlotWithWrongPassphrase(c *C) {
	key1 := make([]byte, 64)
	rand.Read(key1)
	key2 := make([]byte, 64)
	rand.Read(key2)

	devicePath := s.createEmptyDiskImage(c)
	releaseLock, err := AcquireLock(devicePath, LockModeExclusive)
	c.Assert(err, IsNil)
	c.Assert(Format(devicePath, "", key1, &KDFOptions{Master: true}), IsNil)
	c.Assert(AddKey(devicePath, key1, key2, &KDFOptions{Master: true}), IsNil)

	c.Check(KillSlot(devicePath, 1, key2), ErrorMatches, "No key available with this passphrase.")

	releaseLock()
	testutil.CheckLUKS2Passphrase(c, devicePath, key1)
	testutil.CheckLUKS2Passphrase(c, devicePath, key2)
}

func (s *luks2Suite) TestKillNonExistantSlot(c *C) {
	key := make([]byte, 64)
	rand.Read(key)

	devicePath := s.createEmptyDiskImage(c)
	releaseLock, err := AcquireLock(devicePath, LockModeExclusive)
	c.Assert(err, IsNil)
	c.Assert(Format(devicePath, "", key, &KDFOptions{Master: true}), IsNil)

	c.Check(KillSlot(devicePath, 8, key), ErrorMatches, "Keyslot 8 is not active.")

	releaseLock()
	testutil.CheckLUKS2Passphrase(c, devicePath, key)
}

type testSetKeyslotPriorityData struct {
	slotId   int
	priority string
	expected int
}

func (s *luks2Suite) testSetKeyslotPriority(c *C, data *testSetKeyslotPriorityData) {
	devicePath := s.createEmptyDiskImage(c)
	_, err := AcquireLock(devicePath, LockModeExclusive)
	c.Assert(err, IsNil)
	c.Assert(Format(devicePath, "", make([]byte, 64), &KDFOptions{Master: true}), IsNil)
	c.Assert(AddKey(devicePath, make([]byte, 64), make([]byte, 64), &KDFOptions{Master: true}), IsNil)

	info, err := DecodeHdr(devicePath)
	c.Assert(err, IsNil)
	keyslot, ok := info.Metadata.Keyslots[Ints(data.slotId)]
	c.Assert(ok, Equals, true)
	c.Assert(keyslot.Priority, IsNil)

	c.Check(SetKeyslotPriority(devicePath, data.slotId, data.priority), IsNil)

	info, err = DecodeHdr(devicePath)
	c.Assert(err, IsNil)
	keyslot, ok = info.Metadata.Keyslots[Ints(data.slotId)]
	c.Assert(ok, Equals, true)
	c.Assert(keyslot.Priority, NotNil)
	c.Check(*keyslot.Priority, Equals, data.expected)
}

func (s *luks2Suite) TestSetKeyslotPriority1(c *C) {
	s.testSetKeyslotPriority(c, &testSetKeyslotPriorityData{
		slotId:   0,
		priority: "prefer",
		expected: 2})
}

func (s *luks2Suite) TestSetKeyslotPriority2(c *C) {
	s.testSetKeyslotPriority(c, &testSetKeyslotPriorityData{
		slotId:   1,
		priority: "prefer",
		expected: 2})
}

func (s *luks2Suite) TestSetKeyslotPriority3(c *C) {
	s.testSetKeyslotPriority(c, &testSetKeyslotPriorityData{
		slotId:   1,
		priority: "ignore",
		expected: 0})
}