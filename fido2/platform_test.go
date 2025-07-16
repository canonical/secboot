// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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

package fido2_test

import (
	"crypto/rand"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	. "github.com/snapcore/secboot/fido2"

	testutil "github.com/snapcore/secboot/internal/testutil"
)

type platformSuite struct {
}

var _ = Suite(&platformSuite{})

func (s *platformSuite) TestPlatformName(c *C) {
	c.Check(PlatformName, Equals, "fido2")
}

func (s *platformSuite) TestRecoverKeys(c *C) {
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)

	salt := make([]byte, 32)
	rand.Read(salt)

	// Using a physical FIDO2 authenticator with 12345 set as the PIN
	authRequestor := &testutil.MockFidoAuthRequestor{Pin: "12345"}

	authenticator, err := ConnectToFIDO2Authenticator(authRequestor)
	c.Assert(err, IsNil)

	kd, expectedPrimaryKey, expectedUnlockKey, err := NewFIDO2ProtectedKey(authenticator, "", salt, primaryKey)
	c.Assert(err, IsNil)

	flags := secboot.PlatformKeyDataHandlerFlags(0).AddPlatformFlags(1)
	secboot.RegisterPlatformKeyDataHandler(PlatformName, testutil.NewPlainFidoSaltProvider(salt, authRequestor), flags)

	unlockKey, primaryKey, err := kd.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(unlockKey, DeepEquals, expectedUnlockKey)
	c.Check(primaryKey, DeepEquals, expectedPrimaryKey)
}

func (s *platformSuite) TestRecoverKeysBio(c *C) {
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)

	salt := make([]byte, 32)
	rand.Read(salt)

	// Using a physical FIDO2 authenticator with 12345 set as the PIN and a fingerprint enrolled
	// but not passing the PIN.
	// Fingerprint reading failure causes this test to fail.
	authRequestor := &testutil.MockFidoAuthRequestor{Pin: ""}

	authenticator, err := ConnectToFIDO2Authenticator(authRequestor)
	c.Assert(err, IsNil)

	kd, expectedPrimaryKey, expectedUnlockKey, err := NewFIDO2ProtectedKey(authenticator, "", salt, primaryKey)
	c.Assert(err, IsNil)

	flags := secboot.PlatformKeyDataHandlerFlags(0).AddPlatformFlags(1)
	secboot.RegisterPlatformKeyDataHandler(PlatformName, testutil.NewPlainFidoSaltProvider(salt, authRequestor), flags)

	unlockKey, primaryKey, err := kd.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(unlockKey, DeepEquals, expectedUnlockKey)
	c.Check(primaryKey, DeepEquals, expectedPrimaryKey)
}

// TODO
// func (s *platformSuite) TestRecoverKeysWithSaltProvider(c *C) {
// }
