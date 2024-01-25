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
	authKey                secboot.PrimaryKey
}

func (s *updateSuite) testUpdatePCRProtectionPolicy(c *C, data *testUpdatePCRProtectionPolicyData) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	// Protect the key with an initial PCR policy that can't be satisfied
	params := &ProtectKeyParams{
		PCRProfile:             NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
		PCRPolicyCounterHandle: data.pcrPolicyCounterHandle,
		AuthKey:                data.authKey}
	k, authKey, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	_, _, err = k.RecoverKeys()
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
		"cannot execute PolicyOR assertions: current session digest not found in policy data")

	skd, err := NewSealedKeyData(k)
	c.Assert(err, IsNil)

	c.Check(skd.UpdatePCRProtectionPolicy(s.TPM(), authKey, tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23})), IsNil)

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
	authKey := make(secboot.PrimaryKey, 32)
	rand.Read(authKey)

	s.testUpdatePCRProtectionPolicy(c, &testUpdatePCRProtectionPolicyData{
		pcrPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		authKey:                authKey})
}

func (s *updateSuite) testRevokeOldPCRProtectionPolicies(c *C, params *ProtectKeyParams) error {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	k1, authKey, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	w := newMockKeyDataWriter()
	c.Check(k1.WriteAtomic(w), IsNil)

	k2, err := secboot.ReadKeyData(w.Reader())
	c.Assert(err, IsNil)

	skd, err := NewSealedKeyData(k2)
	c.Assert(err, IsNil)
	c.Check(skd.UpdatePCRProtectionPolicy(s.TPM(), authKey, params.PCRProfile), IsNil)

	_, _, err = k1.RecoverKeys()
	c.Check(err, IsNil)
	_, _, err = k2.RecoverKeys()
	c.Check(err, IsNil)

	skd, err = NewSealedKeyData(k1)
	c.Assert(err, IsNil)
	c.Check(skd.RevokeOldPCRProtectionPolicies(s.TPM(), authKey), IsNil)

	_, _, err = k1.RecoverKeys()
	c.Check(err, IsNil)
	_, _, err = k2.RecoverKeys()
	c.Check(err, IsNil)

	skd, err = NewSealedKeyData(k2)
	c.Assert(err, IsNil)
	c.Check(skd.RevokeOldPCRProtectionPolicies(s.TPM(), authKey), IsNil)

	_, _, err = k2.RecoverKeys()
	c.Check(err, IsNil)
	_, _, err = k1.RecoverKeys()
	return err
}

func (s *updateSuite) TestRevokeOldPCRProtectionPoliciesWithPCRPolicyCounter(c *C) {
	err := s.testRevokeOldPCRProtectionPolicies(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: the PCR policy has been revoked")
}

func (s *updateSuite) TestRevokeOldPCRProtectionPoliciesWithoutPCRPolicyCounter(c *C) {
	err := s.testRevokeOldPCRProtectionPolicies(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)
}

func (s *updateSuite) testUpdateKeyDataPCRProtectionPolicy(c *C, n int) {
	var keys []secboot.DiskUnlockKey
	for i := 0; i < n; i++ {
		key := make(secboot.DiskUnlockKey, 32)
		rand.Read(key)
		keys = append(keys, key)
	}

	// Protect the key with an initial PCR policy that can't be satisfied
	params := &ProtectKeyParams{
		PCRProfile:             NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
		PCRPolicyCounterHandle: tpm2.HandleNull}
	ks, authKey, err := ProtectKeysWithTPM(s.TPM(), keys, params)
	c.Assert(err, IsNil)

	for _, k := range ks {
		_, _, err = k.RecoverKeys()
		c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
			"cannot execute PolicyOR assertions: current session digest not found in policy data")
	}

	c.Check(UpdateKeyDataPCRProtectionPolicy(s.TPM(), authKey, tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}), ks...), IsNil)

	for _, k := range ks {
		_, _, err = k.RecoverKeys()
		c.Check(err, IsNil)
	}

	_, err = s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	for _, k := range ks {
		_, _, err = k.RecoverKeys()
		c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
			"cannot execute PolicyOR assertions: current session digest not found in policy data")
	}
}

func (s *updateSuite) TestUpdateKeyDataPCRProtectionPolicy1(c *C) {
	s.testUpdateKeyDataPCRProtectionPolicy(c, 1)
}

func (s *updateSuite) TestUpdateKeyDataPCRProtectionPolicy2(c *C) {
	s.testUpdateKeyDataPCRProtectionPolicy(c, 2)
}

func (s *updateSuite) TestUpdateKeyDataPCRProtectionPolicy3(c *C) {
	s.testUpdateKeyDataPCRProtectionPolicy(c, 3)
}

func (s *updateSuite) TestUpdateKeyDataPCRProtectionPolicyUnrelated1(c *C) {
	var keys []secboot.DiskUnlockKey
	for i := 0; i < 2; i++ {
		key := make(secboot.DiskUnlockKey, 32)
		rand.Read(key)
		keys = append(keys, key)
	}

	authKey := make(secboot.PrimaryKey, 32)
	rand.Read(authKey)

	var ks []*secboot.KeyData
	for i := 0; i < 2; i++ {
		params := &ProtectKeyParams{
			PCRProfile:             NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181ff00+tpm2.Handle(i)),
			AuthKey:                authKey}
		k, _, err := ProtectKeyWithTPM(s.TPM(), keys[i], params)
		c.Assert(err, IsNil)
		ks = append(ks, k)
	}

	err := UpdateKeyDataPCRProtectionPolicy(s.TPM(), authKey, tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}), ks...)
	c.Check(err, ErrorMatches, "invalid key data: key data at index 1 is not related to the primary key data")
}

func (s *updateSuite) TestUpdateKeyDataPCRProtectionPolicyUnrelated2(c *C) {
	var keys []secboot.DiskUnlockKey
	var authKeys []secboot.PrimaryKey
	for i := 0; i < 2; i++ {
		key := make(secboot.DiskUnlockKey, 32)
		rand.Read(key)
		keys = append(keys, key)

		authKey := make(secboot.PrimaryKey, 32)
		rand.Read(authKey)
		authKeys = append(authKeys, authKey)
	}

	var ks []*secboot.KeyData
	for i := 0; i < 2; i++ {
		params := &ProtectKeyParams{
			PCRProfile:             NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
			PCRPolicyCounterHandle: tpm2.HandleNull,
			AuthKey:                authKeys[i]}
		k, _, err := ProtectKeyWithTPM(s.TPM(), keys[i], params)
		c.Assert(err, IsNil)
		ks = append(ks, k)
	}

	err := UpdateKeyDataPCRProtectionPolicy(s.TPM(), authKeys[0], tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}), ks...)
	c.Check(err, ErrorMatches, "invalid key data: key data at index 1 is not related to the primary key data")
}
