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
	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
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
	c.Assert(s.TPM.EnsureProvisioned(secboot.ProvisionModeWithoutLockout, nil), IsNil)
	s.testUnseal(c, s.absPath("pcrSequence.1"))
}

func (s *compatTestV1Suite) TestUnsealWithPIN1(c *C) {
	s.testUnsealWithPIN(c, s.absPath("pcrSequence.1"))
}

func (s *compatTestV1Suite) TestUnsealWithPIN2(c *C) {
	s.testUnsealWithPIN(c, s.absPath("pcrSequence.2"))
}

func (s *compatTestV1Suite) TestUpdateKeyPCRProtectionPolicy(c *C) {
	profile := secboot.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	c.Check(secboot.UpdateKeyPCRProtectionPolicy(s.TPM, s.absPath("key"), s.readFile(c, "authKey"), profile), IsNil)
}

func (s *compatTestV1Suite) TestUpdateKeyPCRProtectionPolicyRevokes(c *C) {
	profile := secboot.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	key2 := s.copyFile(c, s.absPath("key"))

	c.Check(secboot.UpdateKeyPCRProtectionPolicy(s.TPM, key2, s.readFile(c, "authKey"), profile), IsNil)
	s.replayPCRSequenceFromFile(c, s.absPath("pcrSequence.1"))
	s.testUnsealErrorMatchesCommon(c, "invalid key data file: cannot complete authorization policy assertions: the PCR policy has been revoked")
}

func (s *compatTestV1Suite) TestUpdateKeyPCRProtectionPolicyAndUnseal(c *C) {
	profile := secboot.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	c.Check(secboot.UpdateKeyPCRProtectionPolicy(s.TPM, s.absPath("key"), s.readFile(c, "authKey"), profile), IsNil)

	var b bytes.Buffer
	fmt.Fprintf(&b, "7 11 %x\n", testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	fmt.Fprintf(&b, "12 11 %x\n", testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))
	s.replayPCRSequenceFromReader(c, &b)

	s.testUnsealCommon(c, "")
}

func (s *compatTestV1Suite) TestUpdateKeyPCRProtectionPolicyAfterLock(c *C) {
	c.Assert(secboot.BlockPCRProtectionPolicies(s.TPM, nil), IsNil)

	profile := secboot.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	c.Check(secboot.UpdateKeyPCRProtectionPolicy(s.TPM, s.absPath("key"), s.readFile(c, "authKey"), profile), IsNil)
}

func (s *compatTestV1Suite) TestUnsealAfterLock(c *C) {
	s.replayPCRSequenceFromFile(c, s.absPath("pcrSequence.1"))
	c.Assert(secboot.BlockPCRProtectionPolicies(s.TPM, []int{12}), IsNil)
	s.testUnsealErrorMatchesCommon(c, "invalid key data file: cannot complete authorization policy assertions: cannot complete OR assertions: current session digest not found in policy data")
}
