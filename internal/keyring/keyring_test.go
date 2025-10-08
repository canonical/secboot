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

package keyring_test

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	. "github.com/snapcore/secboot/internal/keyring"
	"github.com/snapcore/secboot/internal/keyring/keyringtest"
	"github.com/snapcore/secboot/internal/testutil"
	snapd_testutil "github.com/snapcore/snapd/testutil"
	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type keyringSuite struct {
	snapd_testutil.BaseTest
	keyringtest.TestMixin

	MaybeCheckAndPrepareAttachedKeyringCalls []KeyID
	osThreadLockCount                        int
}

func (s *keyringSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.MaybeCheckAndPrepareAttachedKeyringCalls = nil

	MaybeCheckAndPrepareAttachedKeyring := MaybeCheckAndPrepareAttachedKeyring
	restore := MockMaybeCheckAndPrepareAttachedKeyring(func(id KeyID) (func(), error) {
		s.MaybeCheckAndPrepareAttachedKeyringCalls = append(s.MaybeCheckAndPrepareAttachedKeyringCalls, id)

		wrapUnlockOSThreadIfNeeded := func(fn func()) func() {
			return func() {
				fn()
				s.osThreadLockCount -= 1
			}
		}

		unlockOSThreadIfNeeded, err := MaybeCheckAndPrepareAttachedKeyring(id)
		if err != nil {
			return wrapUnlockOSThreadIfNeeded(unlockOSThreadIfNeeded), err
		}

		s.osThreadLockCount += 1
		return wrapUnlockOSThreadIfNeeded(unlockOSThreadIfNeeded), nil
	})
	s.AddCleanup(restore)
}

func (s *keyringSuite) TearDownTest(c *C) {
	c.Check(s.osThreadLockCount, Equals, 0)
	s.BaseTest.TearDownTest(c)
}

func (s *keyringSuite) checkMaybeCheckAndPrepareAttachedKeyringCalls(c *C, ids ...KeyID) {
	c.Check(ids, DeepEquals, s.MaybeCheckAndPrepareAttachedKeyringCalls)
}

var _ = Suite(&keyringSuite{})

func (s *keyringSuite) TestMaybeCheckAndPrepareAttachedKeyringUserKeyring(c *C) {
	var lockCount int
	restore := MockRuntimeLockOSThread(func() {
		runtime.LockOSThread()
		lockCount += 1
	})
	defer restore()

	restore = MockRuntimeUnlockOSThread(func() {
		runtime.UnlockOSThread()
		lockCount -= 1
	})
	defer restore()

	SetProcessKeyringID(0)
	SetSessionKeyringID(0)

	unlockOSThreadIfNeeded, err := MaybeCheckAndPrepareAttachedKeyring(UserKeyring)
	c.Assert(err, IsNil)
	c.Check(lockCount, Equals, 0)
	c.Assert(unlockOSThreadIfNeeded, NotNil)

	c.Check(GetProcessKeyringID(), Equals, KeyID(0))
	c.Check(GetSessionKeyringID(), Equals, KeyID(0))

	unlockOSThreadIfNeeded()
	c.Check(lockCount, Equals, 0)
}

func (s *keyringSuite) TestMaybeCheckAndPrepareAttachedKeyringSessionKeyring(c *C) {
	var lockCount int
	restore := MockRuntimeLockOSThread(func() {
		runtime.LockOSThread()
		lockCount += 1
	})
	defer restore()

	restore = MockRuntimeUnlockOSThread(func() {
		runtime.UnlockOSThread()
		lockCount -= 1
	})
	defer restore()

	SetProcessKeyringID(0)
	SetSessionKeyringID(0)

	expectedId, err := unix.KeyctlGetKeyringID(int(SessionKeyring), false)
	c.Check(err, IsNil)

	unlockOSThreadIfNeeded, err := MaybeCheckAndPrepareAttachedKeyring(SessionKeyring)
	c.Assert(err, IsNil)
	c.Check(lockCount, Equals, 1)
	c.Assert(unlockOSThreadIfNeeded, NotNil)

	c.Check(GetProcessKeyringID(), Equals, KeyID(0))
	c.Check(GetSessionKeyringID(), Equals, KeyID(expectedId))

	unlockOSThreadIfNeeded()
	c.Check(lockCount, Equals, 0)
}

func (s *keyringSuite) TestMaybeCheckAndPrepareAttachedKeyringSessionKeyringPanicsOnChange(c *C) {
	var lockCount int
	restore := MockRuntimeLockOSThread(func() {
		runtime.LockOSThread()
		lockCount += 1
	})
	defer restore()

	restore = MockRuntimeUnlockOSThread(func() {
		runtime.UnlockOSThread()
		lockCount -= 1
	})
	defer restore()

	SetProcessKeyringID(0)
	SetSessionKeyringID(1)

	c.Check(func() { MaybeCheckAndPrepareAttachedKeyring(SessionKeyring) }, PanicMatches, `session keyring changed or multiple session keyrings, don't use KEYCTL_JOIN_SESSION_KEYRING or maybe try importing the forcesessioninit sub-package to start with a new anonymous session keyring`)
	c.Check(lockCount, Equals, 0)
}

func (s *keyringSuite) TestMaybeCheckAndPrepareAttachedKeyringProcessKeyring(c *C) {
	var lockCount int
	restore := MockRuntimeLockOSThread(func() {
		runtime.LockOSThread()
		lockCount += 1
	})
	defer restore()

	restore = MockRuntimeUnlockOSThread(func() {
		runtime.UnlockOSThread()
		lockCount -= 1
	})
	defer restore()

	SetProcessKeyringID(0)
	SetSessionKeyringID(0)

	expectedId, err := unix.KeyctlGetKeyringID(int(ProcessKeyring), false)
	c.Check(err, IsNil)

	unlockOSThreadIfNeeded, err := MaybeCheckAndPrepareAttachedKeyring(ProcessKeyring)
	c.Assert(err, IsNil)
	c.Check(lockCount, Equals, 0)
	c.Assert(unlockOSThreadIfNeeded, NotNil)

	c.Check(GetProcessKeyringID(), Equals, KeyID(expectedId))
	c.Check(GetSessionKeyringID(), Equals, KeyID(0))

	unlockOSThreadIfNeeded()
	c.Check(lockCount, Equals, 0)
}

func (s *keyringSuite) TestMaybeCheckAndPrepareAttachedKeyringProcessKeyringNotCreatedYet(c *C) {
	var lockCount int
	restore := MockRuntimeLockOSThread(func() {
		runtime.LockOSThread()
		lockCount += 1
	})
	defer restore()

	restore = MockRuntimeUnlockOSThread(func() {
		runtime.UnlockOSThread()
		lockCount -= 1
	})
	defer restore()

	// Mock internalGetKeyringID to swap ProcessKeyring with an ID that
	// doesn't exist.
	var b [4]byte
	_, err := rand.Read(b[:])
	c.Assert(err, IsNil)
	mockId := binary.BigEndian.Uint32(b[:])
	mockId &= math.MaxInt32 // Only special IDs can be negative
	for {
		if mockId&0x80000000 != 0 || mockId == 0 {
			mockId = 1
		}
		if _, err := GetKeyringID(KeyID(mockId)); err == ErrKeyNotExist {
			break
		}
		mockId += 1
	}

	restore = MockInternalGetKeyringID(func(id KeyID) (KeyID, error) {
		if id == ProcessKeyring {
			id = KeyID(mockId)
		}
		return InternalGetKeyringID(id)
	})
	defer restore()

	SetProcessKeyringID(0)
	SetSessionKeyringID(0)

	_, err = MaybeCheckAndPrepareAttachedKeyring(ProcessKeyring)
	c.Check(err, ErrorMatches, `cannot complete operation because a specified key does not exist`)
	c.Check(err, Equals, ErrKeyNotExist)
	c.Check(lockCount, Equals, 0)

	c.Check(GetProcessKeyringID(), Equals, KeyID(0))
	c.Check(GetSessionKeyringID(), Equals, KeyID(0))
}

func (s *keyringSuite) TestMaybeCheckAndPrepareAttachedKeyringProcessKeyringPanicsOnChange(c *C) {
	var lockCount int
	restore := MockRuntimeLockOSThread(func() {
		runtime.LockOSThread()
		lockCount += 1
	})
	defer restore()

	restore = MockRuntimeUnlockOSThread(func() {
		runtime.UnlockOSThread()
		lockCount -= 1
	})
	defer restore()

	SetProcessKeyringID(1)
	SetSessionKeyringID(0)

	c.Check(func() { MaybeCheckAndPrepareAttachedKeyring(ProcessKeyring) }, PanicMatches, `multiple process keyrings, try importing the processinit sub-package`)
	c.Check(lockCount, Equals, 0)
}

type testAddKeyParams struct {
	key       []byte
	keyType   KeyType
	desc      string
	keyringId KeyID
}

func (s *keyringSuite) testAddKey(c *C, params *testAddKeyParams) error {
	// Call the AddKey API
	id, err := AddKey(params.key, params.keyType, params.desc, params.keyringId)
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		keyringtest.InvalidateKeysAndWaitForGC(c, ctx, id)
		cancel()
	}()

	s.checkMaybeCheckAndPrepareAttachedKeyringCalls(c, params.keyringId)

	// Read back the payload and check it.
	key, err := ReadKey(context.Background(), id)
	c.Assert(err, IsNil)
	c.Check(key, DeepEquals, params.key)

	// Check the key description
	desc, err := DescribeKey(id)
	c.Assert(err, IsNil)
	c.Check(desc.Type, Equals, params.keyType)
	c.Check(desc.UID, Equals, uint32(os.Getuid()))
	c.Check(desc.GID, Equals, uint32(os.Getgid()))
	c.Check(desc.Perm, Equals, KeyPossessorAllPerms|KeyUserViewPerm)
	c.Check(desc.Desc, Equals, params.desc)

	keyringtest.CheckKeyInKeyring(c, id, params.keyringId)

	return nil
}

func (s *keyringSuite) TestAddKey(c *C) {
	err := s.testAddKey(c, &testAddKeyParams{
		key:       testutil.DecodeHexString(c, "f72a1c45f27c9b12a0374e4ec00ad6702dd4c7a85f0be6577ef5cc67580f5de3"),
		keyType:   UserKeyType,
		desc:      "foo",
		keyringId: ProcessKeyring,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestAddKeyDifferentKey(c *C) {
	err := s.testAddKey(c, &testAddKeyParams{
		key:       testutil.DecodeHexString(c, "0a0927c145175e1b11e236e77acb02104c27f5cf4bf9cecf696d5f22164899c3"),
		keyType:   UserKeyType,
		desc:      "foo",
		keyringId: ProcessKeyring,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestAddKeyDifferentType(c *C) {
	err := s.testAddKey(c, &testAddKeyParams{
		keyType:   KeyringKeyType,
		desc:      "foo",
		keyringId: ProcessKeyring,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestAddKeyDifferentDesc(c *C) {
	err := s.testAddKey(c, &testAddKeyParams{
		key:       testutil.DecodeHexString(c, "f72a1c45f27c9b12a0374e4ec00ad6702dd4c7a85f0be6577ef5cc67580f5de3"),
		keyType:   UserKeyType,
		desc:      "bar",
		keyringId: ProcessKeyring,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestAddKeyDifferentKeyring(c *C) {
	runtime.LockOSThread() // Required to use the thread keyring
	defer runtime.UnlockOSThread()

	err := s.testAddKey(c, &testAddKeyParams{
		key:       testutil.DecodeHexString(c, "f72a1c45f27c9b12a0374e4ec00ad6702dd4c7a85f0be6577ef5cc67580f5de3"),
		keyType:   UserKeyType,
		desc:      "foo",
		keyringId: ThreadKeyring,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestAddKeyErr(c *C) {
	err := s.testAddKey(c, &testAddKeyParams{
		key:       testutil.DecodeHexString(c, "f72a1c45f27c9b12a0374e4ec00ad6702dd4c7a85f0be6577ef5cc67580f5de3"),
		keyType:   LogonKeyType,
		desc:      "foo",
		keyringId: ProcessKeyring,
	})
	c.Check(err, Equals, ErrInvalidArgs)
}

type testReadKeyParams struct {
	payload []byte
	ctx     context.Context
}

func (s *keyringSuite) testReadKey(c *C, params *testReadKeyParams) error {
	id := s.AddKey(c, params.payload, UserKeyType, "foo", ProcessKeyring)

	ctx := context.Background()
	if params.ctx != nil {
		ctx = params.ctx
	}

	// Test the ReadKey API using the ID of the key we just added
	// and verify that the returned payload is as expected.
	key, err := ReadKey(ctx, id)
	if err != nil {
		return err
	}
	c.Check(key, DeepEquals, params.payload)
	s.checkMaybeCheckAndPrepareAttachedKeyringCalls(c, ProcessKeyring, id)

	return nil
}

func (s *keyringSuite) TestReadKey(c *C) {
	err := s.testReadKey(c, &testReadKeyParams{
		payload: testutil.DecodeHexString(c, "afd38d2fcaa051337b29b9a2bdec67a9acc112336afdb5d219e2d733e582c467"),
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestReadKeyDifferentPayload(c *C) {
	err := s.testReadKey(c, &testReadKeyParams{
		payload: testutil.DecodeHexString(c, "50724893259edf60aea73f47acd9cb29851e545919b9f0e7145402486e7ecaaa"),
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestReadKeyCanceledContext(c *C) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.testReadKey(c, &testReadKeyParams{
		payload: testutil.DecodeHexString(c, "afd38d2fcaa051337b29b9a2bdec67a9acc112336afdb5d219e2d733e582c467"),
		ctx:     ctx,
	})
	c.Check(err, Equals, context.Canceled)
}

func (s *keyringSuite) TestReadKeyErr(c *C) {
	id := s.AddKey(c, testutil.DecodeHexString(c, "afd38d2fcaa051337b29b9a2bdec67a9acc112336afdb5d219e2d733e582c467"), UserKeyType, "foo", ProcessKeyring)

	// Invalidate key straight away so that ReadKey fails.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	keyringtest.InvalidateKeysAndWaitForGC(c, ctx, id)
	cancel()

	_, err := ReadKey(context.Background(), id)
	c.Check(errors.Is(err, ErrKeyNotExist), testutil.IsTrue)
	c.Check(err, ErrorMatches, `cannot complete operation because a specified key does not exist`)
}

func (s *keyringSuite) testListKeyringKeys(c *C, keyringId KeyID) {
	var expectedIds []KeyID
	id := s.AddKey(c, []byte{1}, UserKeyType, "foo", keyringId)
	expectedIds = append(expectedIds, id)

	id = s.AddKey(c, []byte{1}, UserKeyType, "bar", keyringId)
	expectedIds = append(expectedIds, id)

	sort.Slice(expectedIds, func(i, j int) bool {
		return expectedIds[i] < expectedIds[j]
	})

	ids, err := ListKeyringKeys(context.Background(), keyringId)
	c.Check(err, IsNil)
	c.Check(ids, DeepEquals, expectedIds)
	s.checkMaybeCheckAndPrepareAttachedKeyringCalls(c, keyringId, keyringId, keyringId)
}

func (s *keyringSuite) TestListKeyringKeys(c *C) {
	s.testListKeyringKeys(c, ProcessKeyring)
}

func (s *keyringSuite) TestListKeyringKeysDifferentKeyring(c *C) {
	runtime.LockOSThread() // Required to use the thread keyring
	defer func() {
		s.InvalidateKeysAndWaitForGC(c)
		runtime.UnlockOSThread()
	}()
	s.testListKeyringKeys(c, ThreadKeyring)
}

func (s *keyringSuite) TestListKeyringKeysInvalidKeyring(c *C) {
	id := s.AddKey(c, []byte{1}, UserKeyType, "foo", ProcessKeyring)

	_, err := ListKeyringKeys(context.Background(), id)
	c.Check(err, ErrorMatches, `cannot complete operation because one or more key ID arguments was expected to reference a keyring but didn't`)
	c.Check(errors.Is(err, ErrExpectedKeyring), testutil.IsTrue)
}

func (s *keyringSuite) TestListKeyringKeysCanceledContext(c *C) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ListKeyringKeys(ctx, ProcessKeyring)
	c.Check(err, ErrorMatches, `context canceled`)
	c.Check(errors.Is(err, context.Canceled), testutil.IsTrue)
}

type testSearchKeyParams struct {
	keyringId         KeyID
	keyType           KeyType
	desc              string
	payload           []byte
	destinationRingId KeyID
}

func (s *keyringSuite) testSearchKey(c *C, params *testSearchKeyParams) error {
	expectedId := s.AddKey(c, params.payload, params.keyType, params.desc, params.keyringId)

	// Test the SearchKey API and check it returns the expected key ID.
	id, err := SearchKey(params.keyringId, params.keyType, params.desc, params.destinationRingId)
	if err != nil {
		return err
	}
	c.Check(id, Equals, expectedId)
	s.checkMaybeCheckAndPrepareAttachedKeyringCalls(c, params.keyringId, params.destinationRingId)

	// If a destination keyring ID was specified, read the contents of it to make sure it contains
	// the ID of the key we created.
	if params.destinationRingId != 0 {
		keyringtest.CheckKeyInKeyring(c, id, params.destinationRingId)
	}

	return nil
}

func (s *keyringSuite) TestSearchKey(c *C) {
	err := s.testSearchKey(c, &testSearchKeyParams{
		keyringId: ProcessKeyring,
		keyType:   UserKeyType,
		desc:      "foo",
		payload:   []byte{0},
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestSearchKeyDifferentKeyring(c *C) {
	runtime.LockOSThread() // Required to use the thread keyring
	defer func() {
		s.InvalidateKeysAndWaitForGC(c)
		runtime.UnlockOSThread()
	}()

	err := s.testSearchKey(c, &testSearchKeyParams{
		keyringId: ThreadKeyring,
		keyType:   UserKeyType,
		desc:      "foo",
		payload:   []byte{0},
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestSearchKeyDifferentKeyType(c *C) {
	err := s.testSearchKey(c, &testSearchKeyParams{
		keyringId: ProcessKeyring,
		keyType:   KeyringKeyType,
		desc:      "foo",
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestSearchKeyDifferentDesc(c *C) {
	err := s.testSearchKey(c, &testSearchKeyParams{
		keyringId: ProcessKeyring,
		keyType:   UserKeyType,
		desc:      "bar",
		payload:   []byte{0},
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestSearchKeyWithDestination(c *C) {
	runtime.LockOSThread() // Required to use the thread keyring
	defer func() {
		s.InvalidateKeysAndWaitForGC(c)
		runtime.UnlockOSThread()
	}()

	err := s.testSearchKey(c, &testSearchKeyParams{
		keyringId:         ProcessKeyring,
		keyType:           UserKeyType,
		desc:              "foo",
		payload:           []byte{0},
		destinationRingId: ThreadKeyring,
	})
	c.Check(err, IsNil)
}

func (s *keyringSuite) TestSearchKeyError(c *C) {
	err := s.testSearchKey(c, &testSearchKeyParams{
		keyringId:         ProcessKeyring,
		keyType:           UserKeyType,
		desc:              "foo",
		payload:           []byte{0},
		destinationRingId: KeyID(-30),
	})
	c.Check(err, Equals, ErrInvalidArgs)
}

func (s *keyringSuite) testGetKeyringID(c *C, id KeyID) error {
	realId, err := GetKeyringID(id)
	if err != nil {
		return err
	}

	keyId := s.AddKey(c, []byte{1, 2, 3, 4}, UserKeyType, "foo", id)

	// Make sure the key we created is linked to the desired keyring, identified
	// by both its special ID and real ID.
	for _, id := range []KeyID{id, realId} {
		keyringtest.CheckKeyInKeyring(c, keyId, id)
	}

	return nil
}

func (s *keyringSuite) TestGetKeyringID(c *C) {
	runtime.LockOSThread() // Required to use the thread keyring
	defer func() {
		s.InvalidateKeysAndWaitForGC(c)
		runtime.UnlockOSThread()
	}()

	c.Check(s.testGetKeyringID(c, ThreadKeyring), IsNil)
}

func (s *keyringSuite) TestGetKeyringIDDifferentID(c *C) {
	c.Check(s.testGetKeyringID(c, ProcessKeyring), IsNil)
}

func (s *keyringSuite) TestGetKeyringIDError(c *C) {
	c.Check(s.testGetKeyringID(c, KeyID(-25)), Equals, ErrInvalidArgs)
}

type testLinkKeyParams struct {
	creationKeyringId   KeyID
	linkTargetKeyringId KeyID
}

func (s *keyringSuite) testLinkKey(c *C, params *testLinkKeyParams) error {
	id := s.AddKey(c, []byte{1, 2, 3, 4}, UserKeyType, "foo", params.creationKeyringId)

	// Test the LinkKey API.
	if err := LinkKey(id, params.linkTargetKeyringId); err != nil {
		return err
	}

	s.checkMaybeCheckAndPrepareAttachedKeyringCalls(c, params.creationKeyringId, id, params.linkTargetKeyringId)
	keyringtest.CheckKeyInKeyring(c, id, params.linkTargetKeyringId)

	return nil
}

func (s *keyringSuite) TestLinkKey1(c *C) {
	runtime.LockOSThread() // Required to use the thread keyring
	defer func() {
		s.InvalidateKeysAndWaitForGC(c)
		runtime.UnlockOSThread()
	}()

	c.Check(s.testLinkKey(c, &testLinkKeyParams{
		creationKeyringId:   ProcessKeyring,
		linkTargetKeyringId: ThreadKeyring,
	}), IsNil)
}

func (s *keyringSuite) TestLinkKey2(c *C) {
	runtime.LockOSThread() // Required to use the thread keyring
	defer func() {
		s.InvalidateKeysAndWaitForGC(c)
		runtime.UnlockOSThread()
	}()

	c.Check(s.testLinkKey(c, &testLinkKeyParams{
		creationKeyringId:   ThreadKeyring,
		linkTargetKeyringId: ProcessKeyring,
	}), IsNil)
}

func (s *keyringSuite) TestLinkKeyError(c *C) {
	c.Check(s.testLinkKey(c, &testLinkKeyParams{
		creationKeyringId:   ProcessKeyring,
		linkTargetKeyringId: KeyID(-40),
	}), Equals, ErrInvalidArgs)
}

func (s *keyringSuite) testUnlinkKey(c *C, keyringId KeyID) {
	id := s.AddKey(c, []byte{1, 2, 3, 4}, UserKeyType, "foo", keyringId)

	// Add user search permission so that KEYCTL_INVALIDATE works even
	// once the key has been unlinked from our process keyring set.
	desc, err := DescribeKey(id)
	c.Assert(err, IsNil)

	perm := desc.Perm | KeyUserSearchPerm
	c.Assert(SetPerm(id, perm), IsNil)

	// Test the UnlinkKey API.
	c.Check(UnlinkKey(id, keyringId), IsNil)
	keyringtest.CheckKeyNotInKeyring(c, id, keyringId)
}

func (s *keyringSuite) TestUnlinkKey1(c *C) {
	s.testUnlinkKey(c, ProcessKeyring)
}

func (s *keyringSuite) TestUnlinkKey2(c *C) {
	runtime.LockOSThread() // Required to use the thread keyring
	defer func() {
		s.InvalidateKeysAndWaitForGC(c)
		runtime.UnlockOSThread()
	}()

	s.testUnlinkKey(c, ThreadKeyring)
}

func (s *keyringSuite) TestUnlinkKeyError(c *C) {
	c.Check(UnlinkKey(UserKeyring, ProcessKeyring), Equals, ErrKeyNotExist)
}

func (s *keyringSuite) TestKeyPermString(c *C) {
	perm := KeyPossessorAllPerms | KeyUserViewPerm
	c.Check(perm.String(), Equals, "--alswrv|-------v|--------|--------")

	perm = KeyPossessorLinkPerm | KeyPossessorSearchPerm | KeyPossessorWritePerm | KeyPossessorReadPerm | KeyPossessorViewPerm | KeyUserAllPerms
	c.Check(perm.String(), Equals, "---lswrv|--alswrv|--------|--------")

	perm = KeyPossessorAllPerms | KeyUserReadPerm | KeyUserViewPerm
	c.Check(perm.String(), Equals, "--alswrv|------rv|--------|--------")

	perm = KeyPossessorAllPerms | KeyUserSearchPerm | KeyUserReadPerm | KeyUserViewPerm | KeyGroupViewPerm | KeyOtherViewPerm
	c.Check(perm.String(), Equals, "--alswrv|----s-rv|-------v|-------v")
}

func (s *keyringSuite) TestKeyDescriptionString(c *C) {
	desc := KeyDescription{
		Type: UserKeyType,
		UID:  1001,
		GID:  1001,
		Perm: KeyPossessorAllPerms | KeyUserViewPerm,
		Desc: "foo",
	}
	c.Check(desc.String(), Equals, "--alswrv|-------v|--------|-------- 1001 1001 user: foo")

	desc = KeyDescription{
		Type: KeyringKeyType,
		UID:  1000,
		GID:  1000,
		Perm: KeyPossessorLinkPerm | KeyPossessorSearchPerm | KeyPossessorWritePerm | KeyPossessorReadPerm | KeyPossessorViewPerm | KeyUserAllPerms,
		Desc: "_uid.1000",
	}
	c.Check(desc.String(), Equals, "---lswrv|--alswrv|--------|-------- 1000 1000 keyring: _uid.1000")

	desc = KeyDescription{
		Type: KeyringKeyType,
		UID:  0,
		GID:  0,
		Perm: KeyPossessorAllPerms | KeyUserReadPerm | KeyUserViewPerm,
		Desc: "_ses",
	}
	c.Check(desc.String(), Equals, "--alswrv|------rv|--------|-------- 0 0 keyring: _ses")
}
