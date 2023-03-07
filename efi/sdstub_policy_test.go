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

package efi_test

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/util"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

type sdstubPolicySuite struct{}

var _ = Suite(&sdstubPolicySuite{})

type testAddSystemdStubProfileData struct {
	profile *secboot_tpm2.PCRProtectionProfile
	branch  *secboot_tpm2.PCRProtectionProfileBranch
	params  SystemdStubProfileParams
	values  []tpm2.PCRValues
}

func (s *sdstubPolicySuite) testAddSystemdStubProfile(c *C, data *testAddSystemdStubProfileData) {
	profile := data.profile
	branch := data.branch
	switch {
	case profile == nil:
		c.Assert(branch, IsNil)
		profile = secboot_tpm2.NewPCRProtectionProfile()
		branch = profile.RootBranch()
	case branch == nil:
		branch = profile.RootBranch()
	}

	expectedPcrs, _, _ := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	expectedPcrs = expectedPcrs.Merge(tpm2.PCRSelectionList{{Hash: data.params.PCRAlgorithm, Select: []int{data.params.PCRIndex}}})
	var expectedDigests tpm2.DigestList
	for _, v := range data.values {
		d, _ := util.ComputePCRDigest(tpm2.HashAlgorithmSHA256, expectedPcrs, v)
		expectedDigests = append(expectedDigests, d)
	}

	c.Check(AddSystemdStubProfile(branch, &data.params), IsNil)

	pcrs, digests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs.Equal(expectedPcrs), Equals, true)
	c.Check(digests, DeepEquals, expectedDigests)

	if c.Failed() {
		c.Logf("Profile:\n%s", profile)
		c.Logf("Values:\n%s", tpm2test.FormatPCRValuesFromPCRProtectionProfile(profile, nil))
	}
}

func (s *sdstubPolicySuite) TestAddSystemdStubProfileUC20(c *C) {
	s.testAddSystemdStubProfile(c, &testAddSystemdStubProfileData{
		params: SystemdStubProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			KernelCmdlines: []string{
				"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
				"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover",
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: testutil.DecodeHexString(c, "fc433eaf039c6261f496a2a5bf2addfd8ff1104b0fc98af3fe951517e3bde824"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					12: testutil.DecodeHexString(c, "b3a29076eeeae197ae721c254da40480b76673038045305cfa78ec87421c4eea"),
				},
			},
		}})
}

func (s *sdstubPolicySuite) TestAddSystemdStubProfileSHA1(c *C) {
	s.testAddSystemdStubProfile(c, &testAddSystemdStubProfileData{
		params: SystemdStubProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA1,
			PCRIndex:     12,
			KernelCmdlines: []string{
				"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
				"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover",
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA1: {
					12: testutil.DecodeHexString(c, "eb6312b7db70fe16206c162326e36b2fcda74b68"),
				},
			},
			{
				tpm2.HashAlgorithmSHA1: {
					12: testutil.DecodeHexString(c, "bd612bea9efa582fcbfae97973c89b163756fe0b"),
				},
			},
		}})
}

func (s *sdstubPolicySuite) TestAddSystemdStubProfileClassic(c *C) {
	s.testAddSystemdStubProfile(c, &testAddSystemdStubProfileData{
		params: SystemdStubProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     8,
			KernelCmdlines: []string{
				"root=/dev/mapper/vgubuntu-root ro quiet splash vt.handoff=7",
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					8: testutil.DecodeHexString(c, "74fe9080b798f9220c18d0fcdd0ccb82d50ce2a317bc6cdaa2d8715d02d0efbe"),
				},
			},
		}})
}

func (s *sdstubPolicySuite) TestAddSystemdStubProfileWithInitialProfile(c *C) {
	profile := secboot_tpm2.NewPCRProtectionProfile()

	s.testAddSystemdStubProfile(c, &testAddSystemdStubProfileData{
		profile: profile,
		branch: profile.RootBranch().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
		params: SystemdStubProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     8,
			KernelCmdlines: []string{
				"root=/dev/mapper/vgubuntu-root ro quiet splash vt.handoff=7",
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					8: testutil.DecodeHexString(c, "3d39c0db757b47b484006003724d990403d533044ed06e8798ab374bd73f32dc"),
				},
			},
		}})
}
