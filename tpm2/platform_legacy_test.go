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

package tpm2_test

import (
	"math/rand"
	"path/filepath"

	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	. "github.com/snapcore/secboot/tpm2"
)

type platformLegacySuite struct {
	testutil.TPMSimulatorTestBase
}

func (s *platformLegacySuite) SetUpTest(c *C) {
	s.TPMSimulatorTestBase.SetUpTest(c)

	origConnect := ConnectToTPM
	ConnectToTPM = func() (*Connection, error) { return s.TPM, nil }
	s.AddCleanup(func() { ConnectToTPM = origConnect })
}

var _ = Suite(&platformLegacySuite{})

func (s *platformLegacySuite) TestRecoverKeys(c *C) {
	c.Assert(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)
	keyFile := filepath.Join(c.MkDir(), "keydata")

	authPrivateKey, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)

	k, err := NewKeyDataFromSealedKeyObjectFile(keyFile)
	c.Assert(err, IsNil)

	// Note that this closes the TPM connection
	recoveredKey, recoveredAuthPrivateKey, err := k.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(recoveredKey, DeepEquals, key)
	c.Check(recoveredAuthPrivateKey, DeepEquals, secboot.AuxiliaryKey(authPrivateKey))
}

func (s *platformLegacySuite) TestRecoverKeysNoTPMConnection(c *C) {
	c.Assert(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)
	keyFile := filepath.Join(c.MkDir(), "keydata")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)

	ConnectToTPM = func() (*Connection, error) { return nil, ErrNoTPM2Device }

	k, err := NewKeyDataFromSealedKeyObjectFile(keyFile)
	c.Assert(err, IsNil)

	_, _, err = k.RecoverKeys()
	c.Check(err, ErrorMatches, "the platform's secure device is unavailable: no TPM2 device is available")
}

func (s *platformLegacySuite) TestRecoverKeysInvalidPCRPolicy(c *C) {
	c.Assert(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)
	keyFile := filepath.Join(c.MkDir(), "keydata")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)

	_, err = s.TPM.PCREvent(s.TPM.PCRHandleContext(7), tpm2.Event("foo"), nil)
	c.Check(err, IsNil)

	k, err := NewKeyDataFromSealedKeyObjectFile(keyFile)
	c.Assert(err, IsNil)

	// Note that this closes the TPM connection
	_, _, err = k.RecoverKeys()
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: "+
		"cannot complete OR assertions: current session digest not found in policy data")
}

func (s *platformLegacySuite) TestRecoverKeysTPMLockout(c *C) {
	c.Assert(s.TPM.EnsureProvisioned(ProvisionModeFull, nil), IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)
	keyFile := filepath.Join(c.MkDir(), "keydata")

	_, err := SealKeyToTPM(s.TPM, key, keyFile, &KeyCreationParams{PCRProfile: getTestPCRProfile(), PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)

	// Put the TPM in DA lockout mode
	c.Check(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)

	k, err := NewKeyDataFromSealedKeyObjectFile(keyFile)
	c.Assert(err, IsNil)

	// Note that this closes the TPM connection
	_, _, err = k.RecoverKeys()
	c.Check(err, ErrorMatches, "the platform's secure device is unavailable: the TPM is in DA lockout mode")
}

// TODO: Test the ErrTPMProvisioning path.
//  The only way to properly do this is to delete the persistent SRK
//  and then prevent the use of the storage hierarchy by changing its
//  auth value. Changing the auth value must be restored at the end of
//  the test though, but the platform handler closes the TPM connection
//  before we get a chance to do that.
//
//  This will be possible by porting the test code to
//  github.com/canonical/go-tpm2/testutil, which has a mechanism to
//  revert changes when the connection is closed by providing a special
//  transmission interface.
