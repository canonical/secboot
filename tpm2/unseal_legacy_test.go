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

package tpm2_test

import (
	"math/rand"
	"path/filepath"

	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type unsealSuite struct {
	tpm2test.TPMTest
}

func (s *unsealSuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeatureLockoutHierarchy | // Allow the test fixture to reset the DA counter
		tpm2test.TPMFeaturePCR |
		tpm2test.TPMFeatureNV
}

func (s *unsealSuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)
	c.Assert(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil),
		testutil.InSlice(Equals), []error{ErrTPMProvisioningRequiresLockout, nil})
}

var _ = Suite(&unsealSuite{})

func (s *unsealSuite) testUnsealFromTPM(c *C, params *KeyCreationParams) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	path := filepath.Join(c.MkDir(), "key")

	authKey, err := SealKeyToTPM(s.TPM(), key, path, params)
	c.Check(err, IsNil)

	k, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	keyUnsealed, authKeyUnsealed, err := k.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)
}

func (s *unsealSuite) TestUnsealFromTPMSimplePCRProfile(c *C) {
	s.testUnsealFromTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)})
}

func (s *unsealSuite) TestUnsealFromTPMNilPCRProfile(c *C) {
	s.testUnsealFromTPM(c, &KeyCreationParams{
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)})
}

func (s *unsealSuite) TestUnsealFromTPMNoPCRPolicyCounter(c *C) {
	s.testUnsealFromTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *unsealSuite) testUnsealFromTPMNoValidSRK(c *C, prepareSrk func()) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	path := filepath.Join(c.MkDir(), "key")
	params := &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	authKey, err := SealKeyToTPM(s.TPM(), key, path, params)
	c.Check(err, IsNil)

	prepareSrk()

	k, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	keyUnsealed, authKeyUnsealed, err := k.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)
}

func (s *unsealSuite) TestUnsealFromTPMMissingSRK(c *C) {
	s.testUnsealFromTPMNoValidSRK(c, func() {
		srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
		c.Assert(err, IsNil)
		s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())
	})
}

func (s *unsealSuite) TestUnsealFromTPMWrongSRK(c *C) {
	s.testUnsealFromTPMNoValidSRK(c, func() {
		srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
		c.Assert(err, IsNil)
		s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

		srkTemplate := tcg.MakeDefaultSRKTemplate()
		srkTemplate.Unique.RSA = nil
		srk = s.CreatePrimary(c, tpm2.HandleOwner, srkTemplate)
		s.EvictControl(c, tpm2.HandleOwner, srk, tcg.SRKHandle)
	})
}

func (s *unsealSuite) testUnsealImportableFromTPM(c *C, params *KeyCreationParams) {
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)

	srkPub, _, _, err := s.TPM().ReadPublic(srk)
	c.Assert(err, IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	path := filepath.Join(c.MkDir(), "key")

	authKey, err := SealKeyToExternalTPMStorageKey(srkPub, key, path, params)
	c.Check(err, IsNil)

	k, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	keyUnsealed, authKeyUnsealed, err := k.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)
}

func (s *unsealSuite) TestUnsealImportableFromTPMSimplePCRProfile(c *C) {
	s.testUnsealImportableFromTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *unsealSuite) TestUnsealImportableFromTPMNilPCRProfile(c *C) {
	s.testUnsealImportableFromTPM(c, &KeyCreationParams{PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *unsealSuite) testUnsealFromTPMErrorHandling(c *C, prepare func(string, secboot.PrimaryKey)) error {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	path := filepath.Join(c.MkDir(), "key")
	params := &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	authKey, err := SealKeyToTPM(s.TPM(), key, path, params)
	c.Check(err, IsNil)

	prepare(path, authKey)

	k, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	_, _, err = k.UnsealFromTPM(s.TPM())
	return err
}

func (s *unsealSuite) TestUnsealFromTPMErrorHandlingLockout(c *C) {
	err := s.testUnsealFromTPMErrorHandling(c, func(_ string, _ secboot.PrimaryKey) {
		// Put the TPM in DA lockout mode
		c.Check(s.TPM().DictionaryAttackParameters(s.TPM().LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	})
	c.Check(err, Equals, ErrTPMLockout)
}

func (s *unsealSuite) TestUnsealFromTPMErrorHandlingInvalidPCRProfile(c *C) {
	err := s.testUnsealFromTPMErrorHandling(c, func(_ string, _ secboot.PrimaryKey) {
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
		c.Check(err, IsNil)
	})
	c.Check(err, testutil.ConvertibleTo, InvalidKeyDataError{})
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
		"cannot execute PolicyOR assertions: current session digest not found in policy data")
}

func (s *unsealSuite) TestUnsealFromTPMErrorHandlingRevokedPolicy(c *C) {
	err := s.testUnsealFromTPMErrorHandling(c, func(path string, authKey secboot.PrimaryKey) {
		k, err := ReadSealedKeyObjectFromFile(path)
		c.Assert(err, IsNil)
		c.Check(k.UpdatePCRProtectionPolicy(s.TPM(), authKey, nil), IsNil)
		c.Check(k.RevokeOldPCRProtectionPolicies(s.TPM(), authKey), IsNil)
	})
	c.Check(err, testutil.ConvertibleTo, InvalidKeyDataError{})
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: "+
		"the PCR policy has been revoked")
}

func (s *unsealSuite) TestUnsealFromTPMErrorHandlingSealedKeyAccessLocked(c *C) {
	err := s.testUnsealFromTPMErrorHandling(c, func(_ string, _ secboot.PrimaryKey) {
		c.Check(BlockPCRProtectionPolicies(s.TPM(), []int{23}), IsNil)
	})
	c.Check(err, testutil.ConvertibleTo, InvalidKeyDataError{})
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
		"cannot execute PolicyOR assertions: current session digest not found in policy data")
}
