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
	"math/rand"

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

type testUpdatePCRProtectionPolicyData struct {
	pcrPolicyCounterHandle tpm2.Handle
	primaryKey             secboot.PrimaryKey
}

func (s *updateSuite) testUpdatePCRProtectionPolicy(c *C, data *testUpdatePCRProtectionPolicyData) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	// Protect the key with an initial PCR policy that can't be satisfied
	params := &ProtectKeyParams{
		PCRProfile:             NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
		PCRPolicyCounterHandle: data.pcrPolicyCounterHandle,
		PrimaryKey:             data.primaryKey,
		Role:                   "foo",
		NameAlg:                tpm2.HashAlgorithmSHA256}
	k, primaryKey, _, err := NewTPMProtectedKey(s.TPM(), params)
	c.Assert(err, IsNil)

	restore := s.CloseMockConnection(c)

	_, _, err = k.RecoverKeys()
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
		"cannot execute PolicyOR assertions: current session digest not found in policy data")

	restore()

	skd, err := NewSealedKeyData(k)
	c.Assert(err, IsNil)

	c.Check(skd.UpdatePCRProtectionPolicy(s.TPM(), primaryKey, tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}), NoNewPCRPolicyVersion), IsNil)

	restore = s.CloseMockConnection(c)
	defer restore()

	_, _, err = k.RecoverKeys()
	c.Check(err, IsNil)

	_, err = s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)
	_, _, err = k.RecoverKeys()
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
		"cannot execute PolicyOR assertions: current session digest not found in policy data")
}

func (s *updateSuite) TestUpdatePCRProtectionPolicyWithPCRPolicyCounter(c *C) {
	s.testUpdatePCRProtectionPolicy(c, &testUpdatePCRProtectionPolicyData{
		pcrPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
}

func (s *updateSuite) TestUpdatePCRProtectionPolicyNoPCRPolicyCounter(c *C) {
	s.testUpdatePCRProtectionPolicy(c, &testUpdatePCRProtectionPolicyData{
		pcrPolicyCounterHandle: tpm2.HandleNull})
}

func (s *updateSuite) TestUpdatePCRProtectionPolicyWithProvidedAuthKey(c *C) {
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)

	s.testUpdatePCRProtectionPolicy(c, &testUpdatePCRProtectionPolicyData{
		pcrPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		primaryKey:             primaryKey})
}

func (s *updateSuite) testRevokeOldPCRProtectionPolicies(c *C, params *ProtectKeyParams) error {
	k1, primaryKey, _, err := NewTPMProtectedKey(s.TPM(), params)
	c.Assert(err, IsNil)

	w := newMockKeyDataWriter()
	c.Check(k1.WriteAtomic(w), IsNil)

	k2, err := secboot.ReadKeyData(w.Reader())
	c.Assert(err, IsNil)

	skd, err := NewSealedKeyData(k2)
	c.Assert(err, IsNil)
	c.Check(skd.UpdatePCRProtectionPolicy(s.TPM(), primaryKey, params.PCRProfile, NewPCRPolicyVersion), IsNil)

	restore := s.CloseMockConnection(c)

	_, _, err = k1.RecoverKeys()
	c.Check(err, IsNil)
	_, _, err = k2.RecoverKeys()
	c.Check(err, IsNil)

	restore()

	skd, err = NewSealedKeyData(k1)
	c.Assert(err, IsNil)
	c.Check(skd.RevokeOldPCRProtectionPolicies(s.TPM(), primaryKey), IsNil)

	restore = s.CloseMockConnection(c)

	_, _, err = k1.RecoverKeys()
	c.Check(err, IsNil)
	_, _, err = k2.RecoverKeys()
	c.Check(err, IsNil)

	restore()

	skd, err = NewSealedKeyData(k2)
	c.Assert(err, IsNil)
	c.Check(skd.RevokeOldPCRProtectionPolicies(s.TPM(), primaryKey), IsNil)

	restore = s.CloseMockConnection(c)
	defer restore()

	_, _, err = k2.RecoverKeys()
	c.Check(err, IsNil)
	_, _, err = k1.RecoverKeys()
	return err
}

func (s *updateSuite) TestRevokeOldPCRProtectionPoliciesWithPCRPolicyCounter(c *C) {
	err := s.testRevokeOldPCRProtectionPolicies(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		NameAlg:                tpm2.HashAlgorithmSHA256})
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: the PCR policy has been revoked")
}

func (s *updateSuite) TestRevokeOldPCRProtectionPoliciesWithoutPCRPolicyCounter(c *C) {
	err := s.testRevokeOldPCRProtectionPolicies(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
		NameAlg:                tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *updateSuite) TestUpdateKeyDataPCRProtectionPolicy(c *C) {
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)

	// Protect the keys with an initial PCR policy that can't be satisfied
	params := &ProtectKeyParams{
		PCRProfile:             NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		PrimaryKey:             primaryKey,
		Role:                   "bar",
		NameAlg:                tpm2.HashAlgorithmSHA256,
	}

	var keys []*secboot.KeyData
	for i := 0; i < 2; i++ {
		k, _, _, err := NewTPMProtectedKey(s.TPM(), params)
		c.Assert(err, IsNil)

		restore := s.CloseMockConnection(c)
		_, _, err = k.RecoverKeys()
		c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
			"cannot execute PolicyOR assertions: current session digest not found in policy data")
		restore()

		keys = append(keys, k)
	}

	c.Check(UpdateKeyDataPCRProtectionPolicy(s.TPM(), primaryKey, tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}), NoNewPCRPolicyVersion, keys...), IsNil)

	restore := s.CloseMockConnection(c)
	defer restore()

	for _, k := range keys {
		_, _, err := k.RecoverKeys()
		c.Check(err, IsNil)
	}

	_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	for _, k := range keys {
		_, _, err := k.RecoverKeys()
		c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
			"cannot execute PolicyOR assertions: current session digest not found in policy data")
	}
}
