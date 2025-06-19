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
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"

	. "github.com/snapcore/secboot/internal/keyring"
	"github.com/snapcore/secboot/internal/keyring/keyringtest"
	"github.com/snapcore/secboot/internal/testutil"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type keyringSuite struct {
	keyringtest.KeyringTestMixin
}

var _ = Suite(&keyringSuite{})

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
	s.AddKeyToInvalidate(id) // Make sure this key is invalidated during test tear-down.

	// Use the raw syscall to read the payload back and check it is as expected.
	key := make([]byte, len(params.key))
	sz, err := unix.KeyctlBuffer(unix.KEYCTL_READ, int(id), key, 0)
	c.Assert(err, IsNil)
	c.Check(sz, Equals, len(params.key))
	c.Check(key, DeepEquals, params.key)

	// Use the raw syscall to check the description of the key is as expected.
	desc, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, int(id))
	c.Assert(err, IsNil)
	c.Check(desc, Equals, fmt.Sprintf("%s;%d;%d;3f010000;%s", params.keyType, os.Getuid(), os.Getgid(), params.desc))

	s.CheckKeyInKeyring(c, id, params.keyringId)

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
		key:       []byte{},
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
	runtime.LockOSThread()
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
	prepare func()
	ctx     context.Context
}

func (s *keyringSuite) testReadKey(c *C, params *testReadKeyParams) error {
	// Use the raw syscall to add a user key with a fixed description to the process keyring.
	id, err := unix.AddKey(string(UserKeyType), "foo", params.payload, int(ProcessKeyring))
	c.Assert(err, IsNil)
	s.AddKeyToInvalidate(KeyID(id)) // Make sure this key is invalidated during test tear-down.

	if params.prepare != nil {
		// Per-test customization
		params.prepare()
	}

	ctx := context.Background()
	if params.ctx != nil {
		ctx = params.ctx
	}

	// Test the ReadKey API using the ID of the key we just added
	// and verify that the returned payload is as expected.
	key, err := ReadKey(ctx, KeyID(id))
	if err != nil {
		return err
	}
	c.Check(key, DeepEquals, params.payload)

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

func (s *keyringSuite) TestReadKeyErr(c *C) {
	err := s.testReadKey(c, &testReadKeyParams{
		payload: testutil.DecodeHexString(c, "afd38d2fcaa051337b29b9a2bdec67a9acc112336afdb5d219e2d733e582c467"),
		prepare: func() {
			// Find the key we added and then invalidate it
			id, err := unix.KeyctlSearch(int(ProcessKeyring), string(UserKeyType), "foo", 0)
			c.Assert(err, IsNil)
			_, err = unix.KeyctlInt(unix.KEYCTL_INVALIDATE, id, 0, 0, 0)
			c.Assert(err, IsNil)
		},
	})

	// We could get more than one error here, depending on how quickly the
	// invalidated key is garbage collected.
	switch {
	case errors.Is(err, ErrKeyNotExist):
		c.Check(err, ErrorMatches, `cannot read key payload with buffer size [[:digit:]]+: cannot complete operation because a specified key does not exist`)
	case errors.Is(err, ErrPermission):
		c.Check(err, ErrorMatches, `cannot read key payload with buffer size [[:digit:]]+: cannot complete operation because of insufficient permissions`)
	default:
		c.Errorf("unexpected error: %v", err)
	}
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

type testSearchKeyParams struct {
	keyringId         KeyID
	keyType           KeyType
	desc              string
	payload           []byte
	destinationRingId KeyID
}

func (s *keyringSuite) testSearchKey(c *C, params *testSearchKeyParams) error {
	// Use the raw syscall to add a key.
	expectedId, err := unix.AddKey(string(params.keyType), params.desc, params.payload, int(params.keyringId))
	c.Assert(err, IsNil)
	s.AddKeyToInvalidate(KeyID(expectedId)) // Make sure this key is invalidated during test tear-down.

	// Test the SearchKey API and check it returns the expected key ID.
	id, err := SearchKey(params.keyringId, params.keyType, params.desc, params.destinationRingId)
	if err != nil {
		return err
	}
	c.Check(id, Equals, KeyID(expectedId))

	// If a destination keyring ID was specified, read the contents of it to make sure it contains
	// the ID of the key we created.
	if params.destinationRingId != 0 {
		s.CheckKeyInKeyring(c, id, params.destinationRingId)
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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
	// Test the GetKeyringID API andsave the real ID. We
	// can't really test with create==false because we have no
	// way of detaching this executables keyrings - we would
	// need to execute a new process to do these test.
	realId, err := GetKeyringID(id, true)
	if err != nil {
		return err
	}

	// Use the raw syscall to add a user key with a fixed description and
	// payload, to the desired keyring ID.
	keyId, err := unix.AddKey(string(UserKeyType), "foo", []byte{1, 2, 3, 4}, int(id))
	c.Assert(err, IsNil)
	s.AddKeyToInvalidate(KeyID(keyId)) // Make sure this key is invalidated during test tear-down.

	// Make sure the key we created is linked to the desired keyring, identified
	// by both its special ID and real ID.
	for _, id := range []KeyID{id, realId} {
		s.CheckKeyInKeyring(c, KeyID(keyId), id)
	}

	return nil
}

func (s *keyringSuite) TestGetKeyringID(c *C) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	c.Check(s.testGetKeyringID(c, ThreadKeyring), IsNil)
}

func (s *keyringSuite) TestGetKeyringIDDifferentID(c *C) {
	c.Check(s.testGetKeyringID(c, ProcessKeyring), IsNil)
}

func (s *keyringSuite) TestGetKeyringIDError(c *C) {
	c.Check(s.testGetKeyringID(c, KeyID(-25)), Equals, ErrInvalidArgs)
}

func (s *keyringSuite) testLinkKey(c *C, creationKeyringId, linkTargetKeyringId KeyID) error {
	// Use the raw syscall to add a key with a fixed type, description, payload,
	// and a specified initial keyring to link it into.
	id, err := unix.AddKey(string(UserKeyType), "foo", []byte{1, 2, 3, 4}, int(creationKeyringId))
	c.Assert(err, IsNil)
	s.AddKeyToInvalidate(KeyID(id)) // Make sure this key is invalidated during test tear-down.

	// Test the LinkKey API.
	if err := LinkKey(KeyID(id), linkTargetKeyringId); err != nil {
		return err
	}

	s.CheckKeyInKeyring(c, KeyID(id), linkTargetKeyringId)

	return nil
}

func (s *keyringSuite) TestLinkKey1(c *C) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	c.Check(s.testLinkKey(c, ProcessKeyring, ThreadKeyring), IsNil)
}

func (s *keyringSuite) TestLinkKey2(c *C) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	c.Check(s.testLinkKey(c, ThreadKeyring, ProcessKeyring), IsNil)
}

func (s *keyringSuite) TestLinkKeyError(c *C) {
	c.Check(s.testLinkKey(c, ProcessKeyring, KeyID(-40)), Equals, ErrInvalidArgs)
}

func (s *keyringSuite) testUnlinkKey(c *C, keyringId KeyID) {
	// Use the raw syscall to add a key with a fixed type, description, payload,
	// and a specified initial keyring to link it into.
	id, err := unix.AddKey(string(UserKeyType), "foo", []byte{1, 2, 3, 4}, int(keyringId))
	c.Assert(err, IsNil)
	s.AddKeyToInvalidate(KeyID(id)) // Make sure this key is invalidated during test tear-down.

	// Test the LinkKey API.
	c.Assert(UnlinkKey(KeyID(id), keyringId), IsNil)
	s.CheckKeyNotInKeyring(c, KeyID(id), keyringId)
}

func (s *keyringSuite) TestUnlinkKey1(c *C) {
	s.testUnlinkKey(c, ProcessKeyring)
}

func (s *keyringSuite) TestUnlinkKey2(c *C) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	s.testUnlinkKey(c, ThreadKeyring)
}

func (s *keyringSuite) TestUnlinkKeyError(c *C) {
	c.Check(UnlinkKey(KeyID(UserKeyring), KeyID(ProcessKeyring)), Equals, ErrKeyNotExist)
}
