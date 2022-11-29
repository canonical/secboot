// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2022 Canonical Ltd
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/rand"
	"path/filepath"

	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type updateSuite struct {
	tpm2test.TPMTest
	primaryKeyMixin
}

func (s *updateSuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeatureLockoutHierarchy | // Allow the test fixture to reset the DA counter
		tpm2test.TPMFeaturePCR |
		tpm2test.TPMFeatureNV
}

func (s *updateSuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)

	s.primaryKeyMixin.tpmTest = &s.TPMTest.TPMTest
	c.Assert(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil),
		testutil.InSlice(Equals), []error{ErrTPMProvisioningRequiresLockout, nil})
}

var _ = Suite(&updateSuite{})

func (s *updateSuite) testUpdatePCRProtectionPolicy(c *C, params *KeyCreationParams) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	dir := c.MkDir()
	path := filepath.Join(dir, "key")

	authKey, err := SealKeyToTPM(s.TPM(), key, path, params)
	c.Check(err, IsNil)

	k, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	c.Check(k.UpdatePCRProtectionPolicy(s.TPM(), authKey, tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23})), IsNil)

	_, _, err = k.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)

	_, err = s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)
	_, _, err = k.UnsealFromTPM(s.TPM())
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
		"cannot execute PolicyOR assertions: current session digest not found in policy data")
}

func (s *updateSuite) TestUpdatePCRProtectionPolicyWithPCRPolicyCounter(c *C) {
	s.testUpdatePCRProtectionPolicy(c, &KeyCreationParams{PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
}

func (s *updateSuite) TestUpdatePCRProtectionPolicyNoPCRPolicyCounter(c *C) {
	s.testUpdatePCRProtectionPolicy(c, &KeyCreationParams{PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *updateSuite) TestUpdatePCRProtectionPolicyWithProvidedAuthKey(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Check(err, IsNil)

	s.testUpdatePCRProtectionPolicy(c, &KeyCreationParams{
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		AuthKey:                authKey})
}

func (s *updateSuite) testRevokeOldPCRProtectionPolicies(c *C, params *KeyCreationParams) error {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	dir := c.MkDir()
	path := filepath.Join(dir, "key")

	authKey, err := SealKeyToTPM(s.TPM(), key, path, params)
	c.Check(err, IsNil)

	k2, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	c.Check(k2.UpdatePCRProtectionPolicy(s.TPM(), authKey, params.PCRProfile), IsNil)

	k1, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	_, _, err = k1.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)
	_, _, err = k2.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)

	c.Check(k1.RevokeOldPCRProtectionPolicies(s.TPM(), authKey), IsNil)

	_, _, err = k1.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)
	_, _, err = k2.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)

	c.Check(k2.RevokeOldPCRProtectionPolicies(s.TPM(), authKey), IsNil)

	_, _, err = k2.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)
	_, _, err = k1.UnsealFromTPM(s.TPM())
	return err
}

func (s *updateSuite) TestRevokeOldPCRProtectionPoliciesWithPCRPolicyCounter(c *C) {
	err := s.testRevokeOldPCRProtectionPolicies(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: the PCR policy has been revoked")
}

func (s *updateSuite) TestRevokeOldPCRProtectionPoliciesWithoutPCRPolicyCounter(c *C) {
	err := s.testRevokeOldPCRProtectionPolicies(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)
}
