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

type compatTestV0Suite struct {
	compatTestSuiteBase
}

func (s *compatTestV0Suite) SetUpSuite(c *C) {
	s.compatTestSuiteBase.setUpSuiteBase(c, "testdata/v0")
}

var _ = Suite(&compatTestV0Suite{})

func (s *compatTestV0Suite) TestUnseal1(c *C) {
	s.testUnseal(c, s.absPath("pcrSequence.1"))
}

func (s *compatTestV0Suite) TestUnseal2(c *C) {
	s.testUnseal(c, s.absPath("pcrSequence.2"))
}

func (s *compatTestV0Suite) TestUnsealWithPIN1(c *C) {
	s.testUnsealWithPIN(c, s.absPath("pcrSequence.1"))
}

func (s *compatTestV0Suite) TestUnsealWithPIN2(c *C) {
	s.testUnsealWithPIN(c, s.absPath("pcrSequence.2"))
}

func (s *compatTestV0Suite) TestUpdateKeyPCRProtectionPolicy(c *C) {
	profile := secboot.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	c.Check(secboot.UpdateKeyPCRProtectionPolicyV0(s.TPM, s.absPath("key"), s.absPath("pud"), profile), IsNil)
}

func (s *compatTestV0Suite) TestUpdateKeyPCRProtectionPolicyRevokes(c *C) {
	profile := secboot.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	key2 := s.copyFile(c, s.absPath("key"))

	c.Check(secboot.UpdateKeyPCRProtectionPolicyV0(s.TPM, key2, s.absPath("pud"), profile), IsNil)
	s.replayPCRSequenceFromFile(c, s.absPath("pcrSequence.1"))
	s.testUnsealErrorMatchesCommon(c, "invalid authorization policy data: cannot complete authorization policy assertions: the PCR policy has been revoked")
}

func (s *compatTestV0Suite) TestUpdateKeyPCRProtectionPolicyAndUnseal(c *C) {
	profile := secboot.NewPCRProtectionProfile()
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	profile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))

	c.Check(secboot.UpdateKeyPCRProtectionPolicyV0(s.TPM, s.absPath("key"), s.absPath("pud"), profile), IsNil)

	var b bytes.Buffer
	fmt.Fprintf(&b, "7 11 %x\n", testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo"))
	fmt.Fprintf(&b, "12 11 %x\n", testutil.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar"))
	s.replayPCRSequenceFromReader(c, &b)

	s.testUnsealCommon(c, "")
}

func (s *compatTestV0Suite) TestUnsealAfterLock(c *C) {
	s.testUnsealAfterLock(c, s.absPath("pcrSequence.1"))
}
