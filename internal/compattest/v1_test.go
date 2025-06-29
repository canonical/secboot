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

	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/tpm2test"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

type compatTestV1Suite struct {
	compatTestSuiteBase
}

func (s *compatTestV1Suite) SetUpSuite(c *C) {
	s.compatTestSuiteBase.setUpSuiteBase(c, "testdata/v1")
}

var _ = Suite(&compatTestV1Suite{})

func (s *compatTestV1Suite) TestUnseal1(c *C) {
	s.testUnseal(c, s.absPath("pcrSequence.1"))
}

func (s *compatTestV1Suite) TestUnseal2(c *C) {
	s.testUnseal(c, s.absPath("pcrSequence.2"))
}

func (s *compatTestV1Suite) TestUnsealAfterReprovision(c *C) {
	// This should still work because the primary key doesn't change.
	c.Assert(s.TPM().EnsureProvisioned(secboot_tpm2.ProvisionModeWithoutLockout, nil), IsNil)
	s.testUnseal(c, s.absPath("pcrSequence.1"))
}

func (s *compatTestV1Suite) TestUpdateKeyPCRProtectionPolicy(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	k, err := secboot_tpm2.ReadSealedKeyObjectFromFile(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.UpdatePCRProtectionPolicy(s.TPM(), s.readFile(c, "authKey"), profile), IsNil)
}

func (s *compatTestV1Suite) TestRevokeOldPCRProtectionPolicies(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	key2 := s.copyFile(c, s.absPath("key"))

	k, err := secboot_tpm2.ReadSealedKeyObjectFromFile(key2)
	c.Assert(err, IsNil)

	c.Check(k.UpdatePCRProtectionPolicy(s.TPM(), s.readFile(c, "authKey"), profile), IsNil)
	c.Check(k.RevokeOldPCRProtectionPolicies(s.TPM(), s.readFile(c, "authKey")), IsNil)
	s.replayPCRSequenceFromFile(c, s.absPath("pcrSequence.1"))
	s.testUnsealErrorMatchesCommon(c, "invalid PCR policy data: cannot complete authorization policy assertions: the PCR policy has been revoked")
}

func (s *compatTestV1Suite) TestUpdateKeyPCRProtectionPolicyAndUnseal(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	k, err := secboot_tpm2.ReadSealedKeyObjectFromFile(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.UpdatePCRProtectionPolicy(s.TPM(), s.readFile(c, "authKey"), profile), IsNil)

	w := secboot_tpm2.NewFileSealedKeyObjectWriter(s.absPath("key"))
	c.Check(k.WriteAtomic(w), IsNil)

	var b bytes.Buffer
	fmt.Fprintf(&b, "7 11 %x\n", tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	fmt.Fprintf(&b, "12 11 %x\n", tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))
	s.replayPCRSequenceFromReader(c, &b)

	s.testUnsealCommon(c)
}

func (s *compatTestV1Suite) TestUpdateKeyPCRProtectionPolicyAfterLock(c *C) {
	c.Assert(secboot_tpm2.BlockPCRProtectionPolicies(s.TPM(), nil), IsNil)

	profile := secboot_tpm2.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	k, err := secboot_tpm2.ReadSealedKeyObjectFromFile(s.absPath("key"))
	c.Assert(err, IsNil)
	c.Check(k.UpdatePCRProtectionPolicy(s.TPM(), s.readFile(c, "authKey"), profile), IsNil)
}

func (s *compatTestV1Suite) TestUnsealAfterLock(c *C) {
	s.replayPCRSequenceFromFile(c, s.absPath("pcrSequence.1"))
	c.Assert(secboot_tpm2.BlockPCRProtectionPolicies(s.TPM(), []int{12}), IsNil)
	s.testUnsealErrorMatchesCommon(c, "invalid PCR policy data: cannot complete authorization policy assertions: cannot execute PCR assertions: cannot execute PolicyOR assertions: current session digest not found in policy data")
}
