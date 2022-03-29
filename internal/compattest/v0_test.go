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

package compattest

import (
	"bytes"
	"fmt"
	"math/rand"

	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/tpm2test"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

type compatTestV0Suite struct {
	compatTestSuiteBase
}

func (s *compatTestV0Suite) SetUpSuite(c *C) {
	s.compatTestSuiteBase.setUpSuiteBase(c, "testdata/v0")
}

var _ = Suite(&compatTestV0Suite{})

func (s *compatTestV0Suite) TestSealKeyToTPM(c *C) {
	// Verify that we can seal a new key on a TPM provisioned with a legacy style lock NV index
	key := make([]byte, 64)
	rand.Read(key)
	profile := secboot_tpm2.NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7)
	_, err := secboot_tpm2.SealKeyToTPM(s.TPM(), key, c.MkDir()+"/key", &secboot_tpm2.KeyCreationParams{PCRProfile: profile, PCRPolicyCounterHandle: 0x01810001})
	c.Check(err, IsNil)
	// TODO: Validate the key file when we have an API for this
}

func (s *compatTestV0Suite) TestUnseal1(c *C) {
	s.testUnseal(c, s.absPath("pcrSequence.1"))
}

func (s *compatTestV0Suite) TestUnseal2(c *C) {
	s.testUnseal(c, s.absPath("pcrSequence.2"))
}

func (s *compatTestV0Suite) TestUnsealAfterReprovision(c *C) {
	// Test that reprovisioning doesn't touch the legacy lock NV index if it is valid
	c.Assert(s.TPM().EnsureProvisioned(secboot_tpm2.ProvisionModeWithoutLockout, nil), IsNil)
	s.testUnseal(c, s.absPath("pcrSequence.1"))
}

func (s *compatTestV0Suite) TestUpdateKeyPCRProtectionPolicy(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	k, err := secboot_tpm2.ReadSealedKeyObjectFromFile(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.UpdatePCRProtectionPolicyV0(s.TPM(), s.absPath("pud"), profile), IsNil)
}

func (s *compatTestV0Suite) TestRevokeOldPCRProtectionPolicies(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	key2 := s.copyFile(c, s.absPath("key"))

	k, err := secboot_tpm2.ReadSealedKeyObjectFromFile(key2)
	c.Assert(err, IsNil)

	c.Check(k.UpdatePCRProtectionPolicyV0(s.TPM(), s.absPath("pud"), profile), IsNil)
	c.Check(k.RevokeOldPCRProtectionPoliciesV0(s.TPM(), s.absPath("pud")), IsNil)
	s.replayPCRSequenceFromFile(c, s.absPath("pcrSequence.1"))
	s.testUnsealErrorMatchesCommon(c, "invalid key data: cannot complete authorization policy assertions: the PCR policy has been revoked")
}

func (s *compatTestV0Suite) TestUpdateKeyPCRProtectionPolicyAndUnseal(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	k, err := secboot_tpm2.ReadSealedKeyObjectFromFile(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.UpdatePCRProtectionPolicyV0(s.TPM(), s.absPath("pud"), profile), IsNil)

	w := secboot_tpm2.NewFileSealedKeyObjectWriter(s.absPath("key"))
	c.Check(k.WriteAtomic(w), IsNil)

	var b bytes.Buffer
	fmt.Fprintf(&b, "7 11 %x\n", tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	fmt.Fprintf(&b, "12 11 %x\n", tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))
	s.replayPCRSequenceFromReader(c, &b)

	s.testUnsealCommon(c)
}

func (s *compatTestV0Suite) TestUpdateKeyPCRProtectionPolicyAfterLock(c *C) {
	c.Assert(secboot_tpm2.BlockPCRProtectionPolicies(s.TPM(), nil), IsNil)

	profile := secboot_tpm2.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	k, err := secboot_tpm2.ReadSealedKeyObjectFromFile(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.UpdatePCRProtectionPolicyV0(s.TPM(), s.absPath("pud"), profile), IsNil)
}

func (s *compatTestV0Suite) TestUnsealAfterLock(c *C) {
	// Test unsealing a v0 file from a newer initramfs using the fence-style locking - this just makes
	// the PCR values invalid so there's no reason this shouldn't work or require a compatibility test,
	// but keep this here just to make sure.
	s.replayPCRSequenceFromFile(c, s.absPath("pcrSequence.1"))
	c.Assert(secboot_tpm2.BlockPCRProtectionPolicies(s.TPM(), []int{12}), IsNil)
	s.testUnsealErrorMatchesCommon(c, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: cannot execute PolicyOR assertions: current session digest not found in policy data")
}
