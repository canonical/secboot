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

package secboot_test

import (
	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"

	. "gopkg.in/check.v1"
)

type efiBootManagerPolicySuite struct{}

var _ = Suite(&efiBootManagerPolicySuite{})

type testComputePeImageDigestData struct {
	alg    tpm2.HashAlgorithmId
	path   string
	digest tpm2.Digest
}

func (s *efiBootManagerPolicySuite) testComputePeImageDigest(c *C, data *testComputePeImageDigestData) {
	d, err := ComputePeImageDigest(data.alg, FileEFIImage(data.path))
	c.Assert(err, IsNil)
	c.Check(d, DeepEquals, data.digest)
	c.Logf("%x", d)
}

func (s *efiBootManagerPolicySuite) TestComputePeImageDigest1(c *C) {
	s.testComputePeImageDigest(c, &testComputePeImageDigestData{
		alg:    tpm2.HashAlgorithmSHA256,
		path:   "testdata/mockshim1.efi.signed.1",
		digest: decodeHexString(c, "1d91795a82b24a61c5b5f4b5843062fd10fc42e2d403c5a65f811014df231c9f"),
	})
}

func (s *efiBootManagerPolicySuite) TestComputePeImageDigest2(c *C) {
	s.testComputePeImageDigest(c, &testComputePeImageDigestData{
		alg:    tpm2.HashAlgorithmSHA256,
		path:   "testdata/mockgrub1.efi.signed.shim",
		digest: decodeHexString(c, "5a03ecd3cc4caf9eabc8d7295772c0b74e2998d1631bbde372acbf2ffad4031a"),
	})
}

func (s *efiBootManagerPolicySuite) TestComputePeImageDigest3(c *C) {
	s.testComputePeImageDigest(c, &testComputePeImageDigestData{
		alg:    tpm2.HashAlgorithmSHA1,
		path:   "testdata/mockshim1.efi.signed.1",
		digest: decodeHexString(c, "2e65c395448b8fcfce99f0421bb396f7a66cc207"),
	})
}

func (s *efiBootManagerPolicySuite) TestComputePeImageDigest4(c *C) {
	s.testComputePeImageDigest(c, &testComputePeImageDigestData{
		alg:    tpm2.HashAlgorithmSHA256,
		path:   "testdata/mockkernel1.efi",
		digest: decodeHexString(c, "d74047a878cab6614ffc3569e6aff636470773c8b73dfb4288c54742e6c85945"),
	})
}

type testAddEFIBootManagerProfileData struct {
	initial *PCRProtectionProfile
	params  *EFIBootManagerProfileParams
	values  []tpm2.PCRValues
}

func (s *efiBootManagerPolicySuite) testAddEFIBootManagerProfile(c *C, data *testAddEFIBootManagerProfileData) {
	restoreEventLogPath := MockEventLogPath("testdata/eventlog1.bin")
	defer restoreEventLogPath()

	profile := data.initial
	if profile == nil {
		profile = &PCRProtectionProfile{}
	}
	expectedPcrs, _, _ := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	expectedPcrs = expectedPcrs.Merge(tpm2.PCRSelectionList{{Hash: data.params.PCRAlgorithm, Select: []int{4}}})
	var expectedDigests tpm2.DigestList
	for _, v := range data.values {
		d, _ := tpm2.ComputePCRDigest(tpm2.HashAlgorithmSHA256, expectedPcrs, v)
		expectedDigests = append(expectedDigests, d)
	}

	c.Assert(AddEFIBootManagerProfile(profile, data.params), IsNil)
	pcrs, digests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	c.Check(pcrs.Equal(expectedPcrs), Equals, true)
	c.Check(digests, DeepEquals, expectedDigests)
	if c.Failed() {
		c.Logf("Profile:\n%s", profile)
		c.Logf("Values:\n%s", profile.DumpValues(nil))
	}
}

func (s *efiBootManagerPolicySuite) TestAddEFIBootManagerProfile1(c *C) {
	s.testAddEFIBootManagerProfile(c, &testAddEFIBootManagerProfileData{
		params: &EFIBootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*EFIImageLoadEvent{
				{
					Image: FileEFIImage("testdata/mockshim1.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Image: FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
							Next: []*EFIImageLoadEvent{
								{
									Image: FileEFIImage("testdata/mockkernel1.efi.signed.shim"),
								},
								{
									Image: FileEFIImage("testdata/mockkernel2.efi.signed.shim"),
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
					4: decodeHexString(c, "4cc69b6c5446269f89bbc0b3e5d30e03983d14478bcaf6efcce1581ae3faa4f6"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: decodeHexString(c, "557e91fbdbd0f81e746fcd0509ac639ad9221d9bf5a8d73dca8b343e39932f5f"),
				},
			},
		},
	})
}

func (s *efiBootManagerPolicySuite) TestAddEFIBootManagerProfile2(c *C) {
	s.testAddEFIBootManagerProfile(c, &testAddEFIBootManagerProfileData{
		params: &EFIBootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*EFIImageLoadEvent{
				{
					Image: FileEFIImage("testdata/mockshim1.efi.signed.2"),
					Next: []*EFIImageLoadEvent{
						{
							Image: FileEFIImage("testdata/mockgrub1.efi.signed.2"),
							Next: []*EFIImageLoadEvent{
								{
									Image: FileEFIImage("testdata/mockkernel1.efi.signed.2"),
								},
								{
									Image: FileEFIImage("testdata/mockkernel2.efi.signed.2"),
								},
								{
									Image: FileEFIImage("testdata/mockgrub1.efi.signed.2"),
									Next: []*EFIImageLoadEvent{
										{
											Image: FileEFIImage("testdata/mockkernel1.efi.signed.2"),
										},
										{
											Image: FileEFIImage("testdata/mockkernel2.efi.signed.2"),
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
					4: decodeHexString(c, "4cc69b6c5446269f89bbc0b3e5d30e03983d14478bcaf6efcce1581ae3faa4f6"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: decodeHexString(c, "557e91fbdbd0f81e746fcd0509ac639ad9221d9bf5a8d73dca8b343e39932f5f"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: decodeHexString(c, "dfd014ab6f88bc0a44bad9bbd5557f6449b0a2bf29efcd1bcb3b1affbb413e26"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: decodeHexString(c, "1b3c4ce655be2a0679e5bcee76e66afef01c54d709a745c47caf907f841249fe"),
				},
			},
		},
	})
}

func (s *efiBootManagerPolicySuite) TestAddEFIBootManagerProfile3(c *C) {
	s.testAddEFIBootManagerProfile(c, &testAddEFIBootManagerProfileData{
		initial: NewPCRProtectionProfile().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 4, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
		params: &EFIBootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*EFIImageLoadEvent{
				{
					Image: FileEFIImage("testdata/mockshim1.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Image: FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
							Next: []*EFIImageLoadEvent{
								{
									Image: FileEFIImage("testdata/mockkernel1.efi.signed.shim"),
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
					4: decodeHexString(c, "4cc69b6c5446269f89bbc0b3e5d30e03983d14478bcaf6efcce1581ae3faa4f6"),
					7: makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
		},
	})
}

func (s *efiBootManagerPolicySuite) TestAddEFIBootManagerProfile4(c *C) {
	s.testAddEFIBootManagerProfile(c, &testAddEFIBootManagerProfileData{
		params: &EFIBootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*EFIImageLoadEvent{
				{
					Image: FileEFIImage("testdata/mockshim1.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Image: FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
							Next: []*EFIImageLoadEvent{
								{
									Image: FileEFIImage("testdata/mockkernel1.efi.signed.shim"),
								},
							},
						},
					},
				},
				{
					Image: FileEFIImage("testdata/mockshim1.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Image: FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
							Next: []*EFIImageLoadEvent{
								{
									Image: FileEFIImage("testdata/mockkernel2.efi.signed.shim"),
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
					4: decodeHexString(c, "4cc69b6c5446269f89bbc0b3e5d30e03983d14478bcaf6efcce1581ae3faa4f6"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: decodeHexString(c, "557e91fbdbd0f81e746fcd0509ac639ad9221d9bf5a8d73dca8b343e39932f5f"),
				},
			},
		},
	})
}
