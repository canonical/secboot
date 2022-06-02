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
	"fmt"
	"math/rand"
	"path/filepath"

	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type updateLegacySuite struct {
	tpm2test.TPMTest
	primaryKeyMixin
}

func (s *updateLegacySuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeatureLockoutHierarchy | // Allow the test fixture to reset the DA counter
		tpm2test.TPMFeaturePCR |
		tpm2test.TPMFeatureNV
}

func (s *updateLegacySuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)

	s.primaryKeyMixin.tpmTest = &s.TPMTest.TPMTest
	c.Assert(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil),
		tpm2_testutil.InSlice(Equals), []error{ErrTPMProvisioningRequiresLockout, nil})
}

var _ = Suite(&updateLegacySuite{})

func (s *updateLegacySuite) TestUpdateKeyPCRProtectionPolicyMultiple(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	dir := c.MkDir()

	var requests []*SealKeyRequest
	for i := 0; i < 2; i++ {
		requests = append(requests, &SealKeyRequest{Key: key, Path: filepath.Join(dir, fmt.Sprintf("key%d", i))})
	}

	authKey, err := SealKeyToTPMMultiple(s.TPM(), requests, &KeyCreationParams{PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Check(err, IsNil)

	var keys []*SealedKeyObject
	for _, r := range requests {
		k, err := ReadSealedKeyObjectFromFile(r.Path)
		c.Assert(err, IsNil)
		keys = append(keys, k)
	}

	c.Check(UpdateKeyPCRProtectionPolicyMultiple(s.TPM(), keys, authKey, tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23})), IsNil)

	for _, k := range keys {
		_, _, err := k.UnsealFromTPM(s.TPM())
		c.Check(err, IsNil)
	}

	_, err = s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	for _, k := range keys {
		_, _, err = k.UnsealFromTPM(s.TPM())
		c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
			"cannot execute PolicyOR assertions: current session digest not found in policy data")
	}
}

func (s *updateLegacySuite) TestUpdateKeyPCRProtectionPolicyMultipleUnrelated1(c *C) {
	// Test that UpdateKeyPCRProtectionPolicyMultiple rejects keys that have the
	// same auth key, but different policies because they use independent PCR policy
	// counters.
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)

	dir := c.MkDir()

	var keys []*SealedKeyObject
	for i := 0; i < 3; i++ {
		path := filepath.Join(dir, fmt.Sprintf("key%d", i))
		params := &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000+tpm2.Handle(i)),
			AuthKey:                authKey}
		_, err := SealKeyToTPM(s.TPM(), key, path, params)
		c.Check(err, IsNil)

		k, err := ReadSealedKeyObjectFromFile(path)
		c.Assert(err, IsNil)

		keys = append(keys, k)
	}

	err = UpdateKeyPCRProtectionPolicyMultiple(s.TPM(), keys, authKey.D.Bytes(), nil)
	c.Check(err, ErrorMatches, "invalid key data: key data at index 0 is not related to the primary key data")
}

func (s *updateLegacySuite) TestUpdateKeyPCRProtectionPolicyMultipleUnrelated2(c *C) {
	// Test that UpdateKeyPCRProtectionPolicyMultiple rejects keys that use different
	// auth keys.
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	dir := c.MkDir()

	var keys []*SealedKeyObject

	path := filepath.Join(dir, "key")
	params := &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull}
	authKey, err := SealKeyToTPM(s.TPM(), key, path, params)
	c.Check(err, IsNil)

	k, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	keys = append(keys, k)

	for i := 0; i < 2; i++ {
		path := filepath.Join(dir, fmt.Sprintf("key%d", i))
		_, err := SealKeyToTPM(s.TPM(), key, path, params)
		c.Check(err, IsNil)

		k, err := ReadSealedKeyObjectFromFile(path)
		c.Assert(err, IsNil)

		keys = append(keys, k)
	}

	err = UpdateKeyPCRProtectionPolicyMultiple(s.TPM(), keys, authKey, nil)
	c.Check(err, ErrorMatches, "invalid key data: key data at index 0 is not related to the primary key data")
}
