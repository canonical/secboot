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
	"github.com/snapcore/secboot"
	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

type bootManagerPolicySuite struct{}

var _ = Suite(&bootManagerPolicySuite{})

type testAddBootManagerProfileData struct {
	initial *secboot.PCRProtectionProfile
	params  *BootManagerProfileParams
	values  []tpm2.PCRValues
}

func (s *bootManagerPolicySuite) testAddBootManagerProfile(c *C, data *testAddBootManagerProfileData) {
	restoreEventLogPath := testutil.MockEventLogPath("testdata/eventlog1.bin")
	defer restoreEventLogPath()

	profile := data.initial
	if profile == nil {
		profile = &secboot.PCRProtectionProfile{}
	}
	expectedPcrs, _, _ := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	expectedPcrs = expectedPcrs.Merge(tpm2.PCRSelectionList{{Hash: data.params.PCRAlgorithm, Select: []int{4}}})
	var expectedDigests tpm2.DigestList
	for _, v := range data.values {
		d, _ := tpm2.ComputePCRDigest(tpm2.HashAlgorithmSHA256, expectedPcrs, v)
		expectedDigests = append(expectedDigests, d)
	}

	c.Assert(AddBootManagerProfile(profile, data.params), IsNil)
	pcrs, digests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	c.Check(pcrs.Equal(expectedPcrs), Equals, true)
	c.Check(digests, DeepEquals, expectedDigests)
	if c.Failed() {
		c.Logf("Profile:\n%s", profile)
		c.Logf("Values:\n%s", testutil.FormatPCRValuesFromPCRProtectionProfile(profile, nil))
	}
}

func (s *bootManagerPolicySuite) TestAddBootManagerProfile1(c *C) {
	s.testAddBootManagerProfile(c, &testAddBootManagerProfileData{
		params: &BootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*ImageLoadEvent{
				{
					Image: FileImage("testdata/mockshim1.efi.signed.1"),
					Next: []*ImageLoadEvent{
						{
							Image: FileImage("testdata/mockgrub1.efi.signed.shim"),
							Next: []*ImageLoadEvent{
								{
									Image: FileImage("testdata/mockkernel1.efi.signed.shim"),
								},
								{
									Image: FileImage("testdata/mockkernel2.efi.signed.shim"),
								},
							},
						},
					},
				},
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "4cc69b6c5446269f89bbc0b3e5d30e03983d14478bcaf6efcce1581ae3faa4f6"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "557e91fbdbd0f81e746fcd0509ac639ad9221d9bf5a8d73dca8b343e39932f5f"),
				},
			},
		},
	})
}

func (s *bootManagerPolicySuite) TestAddBootManagerProfile2(c *C) {
	s.testAddBootManagerProfile(c, &testAddBootManagerProfileData{
		params: &BootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*ImageLoadEvent{
				{
					Image: FileImage("testdata/mockshim1.efi.signed.2"),
					Next: []*ImageLoadEvent{
						{
							Image: FileImage("testdata/mockgrub1.efi.signed.2"),
							Next: []*ImageLoadEvent{
								{
									Image: FileImage("testdata/mockkernel1.efi.signed.2"),
								},
								{
									Image: FileImage("testdata/mockkernel2.efi.signed.2"),
								},
								{
									Image: FileImage("testdata/mockgrub1.efi.signed.2"),
									Next: []*ImageLoadEvent{
										{
											Image: FileImage("testdata/mockkernel1.efi.signed.2"),
										},
										{
											Image: FileImage("testdata/mockkernel2.efi.signed.2"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "4cc69b6c5446269f89bbc0b3e5d30e03983d14478bcaf6efcce1581ae3faa4f6"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "557e91fbdbd0f81e746fcd0509ac639ad9221d9bf5a8d73dca8b343e39932f5f"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "dfd014ab6f88bc0a44bad9bbd5557f6449b0a2bf29efcd1bcb3b1affbb413e26"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "1b3c4ce655be2a0679e5bcee76e66afef01c54d709a745c47caf907f841249fe"),
				},
			},
		},
	})
}

func (s *bootManagerPolicySuite) TestAddBootManagerProfile3(c *C) {
	s.testAddBootManagerProfile(c, &testAddBootManagerProfileData{
		initial: secboot.NewPCRProtectionProfile().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 4, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
		params: &BootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*ImageLoadEvent{
				{
					Image: FileImage("testdata/mockshim1.efi.signed.1"),
					Next: []*ImageLoadEvent{
						{
							Image: FileImage("testdata/mockgrub1.efi.signed.shim"),
							Next: []*ImageLoadEvent{
								{
									Image: FileImage("testdata/mockkernel1.efi.signed.shim"),
								},
							},
						},
					},
				},
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "4cc69b6c5446269f89bbc0b3e5d30e03983d14478bcaf6efcce1581ae3faa4f6"),
					7: testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
		},
	})
}

func (s *bootManagerPolicySuite) TestAddBootManagerProfile4(c *C) {
	s.testAddBootManagerProfile(c, &testAddBootManagerProfileData{
		params: &BootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*ImageLoadEvent{
				{
					Image: FileImage("testdata/mockshim1.efi.signed.1"),
					Next: []*ImageLoadEvent{
						{
							Image: FileImage("testdata/mockgrub1.efi.signed.shim"),
							Next: []*ImageLoadEvent{
								{
									Image: FileImage("testdata/mockkernel1.efi.signed.shim"),
								},
							},
						},
					},
				},
				{
					Image: FileImage("testdata/mockshim1.efi.signed.1"),
					Next: []*ImageLoadEvent{
						{
							Image: FileImage("testdata/mockgrub1.efi.signed.shim"),
							Next: []*ImageLoadEvent{
								{
									Image: FileImage("testdata/mockkernel2.efi.signed.shim"),
								},
							},
						},
					},
				},
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "4cc69b6c5446269f89bbc0b3e5d30e03983d14478bcaf6efcce1581ae3faa4f6"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "557e91fbdbd0f81e746fcd0509ac639ad9221d9bf5a8d73dca8b343e39932f5f"),
				},
			},
		},
	})
}
