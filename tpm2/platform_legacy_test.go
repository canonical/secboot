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
	"os"
	"path/filepath"
	"syscall"

	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type platformLegacySuite struct {
	tpm2test.TPMTest
}

func (s *platformLegacySuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeatureLockoutHierarchy |
		tpm2test.TPMFeaturePCR |
		tpm2test.TPMFeatureNV
}

func (s *platformLegacySuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)

	c.Check(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil), Equals, ErrTPMProvisioningRequiresLockout)
}

var _ = Suite(&platformLegacySuite{})

func (s *platformLegacySuite) TestRecoverKeys(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)
	keyFile := filepath.Join(c.MkDir(), "keydata")

	authPrivateKey, err := SealKeyToTPM(s.TPM(), key, keyFile, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)

	k, err := NewKeyDataFromSealedKeyObjectFile(keyFile)
	c.Assert(err, IsNil)

	recoveredKey, recoveredAuthPrivateKey, err := k.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(recoveredKey, DeepEquals, key)
	c.Check(recoveredAuthPrivateKey, DeepEquals, secboot.PrimaryKey(authPrivateKey))
}

func (s *platformLegacySuite) TestRecoverKeysNoTPMConnection(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)
	keyFile := filepath.Join(c.MkDir(), "keydata")

	_, err := SealKeyToTPM(s.TPM(), key, keyFile, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)

	restore := tpm2test.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		return nil, &os.PathError{Op: "open", Path: "/dev/tpm0", Err: syscall.ENOENT}
	})
	s.AddCleanup(restore)

	k, err := NewKeyDataFromSealedKeyObjectFile(keyFile)
	c.Assert(err, IsNil)

	_, _, err = k.RecoverKeys()
	c.Check(err, ErrorMatches, "the platform's secure device is unavailable: no TPM2 device is available")
}

func (s *platformLegacySuite) TestRecoverKeysInvalidPCRPolicy(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)
	keyFile := filepath.Join(c.MkDir(), "keydata")

	_, err := SealKeyToTPM(s.TPM(), key, keyFile, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)

	_, err = s.TPM().PCREvent(s.TPM().PCRHandleContext(7), tpm2.Event("foo"), nil)
	c.Check(err, IsNil)

	k, err := NewKeyDataFromSealedKeyObjectFile(keyFile)
	c.Assert(err, IsNil)

	_, _, err = k.RecoverKeys()
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: "+
		"cannot execute PCR assertions: cannot execute PolicyOR assertions: current session digest not found in policy data")
}

func (s *platformLegacySuite) TestRecoverKeysTPMLockout(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)
	keyFile := filepath.Join(c.MkDir(), "keydata")

	_, err := SealKeyToTPM(s.TPM(), key, keyFile, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)

	// Put the TPM in DA lockout mode
	c.Check(s.TPM().DictionaryAttackParameters(s.TPM().LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)

	k, err := NewKeyDataFromSealedKeyObjectFile(keyFile)
	c.Assert(err, IsNil)

	_, _, err = k.RecoverKeys()
	c.Check(err, ErrorMatches, "the platform's secure device is unavailable: the TPM is in DA lockout mode")
}

func (s *platformLegacySuite) TestRecoverKeysErrTPMProvisioning(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)
	keyFile := filepath.Join(c.MkDir(), "keydata")

	_, err := SealKeyToTPM(s.TPM(), key, keyFile, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)

	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)

	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())
	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("foo"))

	k, err := NewKeyDataFromSealedKeyObjectFile(keyFile)
	c.Assert(err, IsNil)

	_, _, err = k.RecoverKeys()
	c.Check(err, ErrorMatches, "the platform's secure device is not properly initialized: the TPM is not correctly provisioned")
}
