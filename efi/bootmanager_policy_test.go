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
	"path/filepath"
	"runtime"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/util"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

type bootManagerPolicySuite struct{}

var _ = Suite(&bootManagerPolicySuite{})

type testAddBootManagerProfileData struct {
	eventLogPath string
	initial      *secboot_tpm2.PCRProtectionProfile
	params       *BootManagerProfileParams
	values       []tpm2.PCRValues
}

func (s *bootManagerPolicySuite) testAddBootManagerProfile(c *C, data *testAddBootManagerProfileData) {
	if runtime.GOARCH != "amd64" {
		c.Skip("unsupported architecture")
	}

	restoreEventLogPath := MockEventLogPath(data.eventLogPath)
	defer restoreEventLogPath()

	profile := data.initial
	if profile == nil {
		profile = &secboot_tpm2.PCRProtectionProfile{}
	}
	expectedPcrs, _, _ := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	expectedPcrs = expectedPcrs.Merge(tpm2.PCRSelectionList{{Hash: data.params.PCRAlgorithm, Select: []int{4}}})
	var expectedDigests tpm2.DigestList
	for _, v := range data.values {
		d, _ := util.ComputePCRDigest(tpm2.HashAlgorithmSHA256, expectedPcrs, v)
		expectedDigests = append(expectedDigests, d)
	}

	c.Assert(AddBootManagerProfile(profile, data.params), IsNil)
	pcrs, digests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	c.Check(pcrs.Equal(expectedPcrs), Equals, true)
	c.Check(digests, DeepEquals, expectedDigests)
	if c.Failed() {
		c.Logf("Profile:\n%s", profile)
		c.Logf("Values:\n%s", tpm2test.FormatPCRValuesFromPCRProtectionProfile(profile, nil))
	}
}

func (s *bootManagerPolicySuite) TestAddBootManagerProfileClassic(c *C) {
	// Test with a classic style configuration - shim -> grub -> 2 kernels.
	s.testAddBootManagerProfile(c, &testAddBootManagerProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		params: &BootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*ImageLoadEvent{
				{
					Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim_sbat.efi.signed.1.1.1")),
					Next: []*ImageLoadEvent{
						{
							Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")),
							Next: []*ImageLoadEvent{
								{
									Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")),
								},
								{
									Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1")),
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
					4: testutil.DecodeHexString(c, "2f64bfe7796724c68c54b14bc8690012f9e29c907dc900831dd12f912f20b2b3"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "27c1fcc75127e47454e4b7d2de4d31796d1300ce67c7ea39a4459d64412e0347"),
				},
			},
		},
	})
}

func (s *bootManagerPolicySuite) TestAddBootManagerProfileUC20(c *C) {
	// Test with a UC20 style configuration:
	// - shim -> grub -> 2 kernels
	// - shim -> grub -> grub -> 2 kernels
	s.testAddBootManagerProfile(c, &testAddBootManagerProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		params: &BootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*ImageLoadEvent{
				{
					Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim_sbat.efi.signed.1.1.1")),
					Next: []*ImageLoadEvent{
						{
							Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")),
							Next: []*ImageLoadEvent{
								{
									Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")),
								},
								{
									Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1")),
								},
								{
									Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")),
									Next: []*ImageLoadEvent{
										{
											Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")),
										},
										{
											Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1")),
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
					4: testutil.DecodeHexString(c, "2f64bfe7796724c68c54b14bc8690012f9e29c907dc900831dd12f912f20b2b3"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "27c1fcc75127e47454e4b7d2de4d31796d1300ce67c7ea39a4459d64412e0347"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "3d4e2d8c3c85ac96819b37de0a9216e9041e1d77b6205aa518eb9ce06c73f252"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "695e12cdb86760a02f6551d8155a24c871babcad6b0f8abda104c5a0743b6525"),
				},
			},
		},
	})
}

func (s *bootManagerPolicySuite) TestAddBootManagerProfileWithInitialProfile(c *C) {
	// Test with a PCRProtectionProfile that already has some values in it.
	s.testAddBootManagerProfile(c, &testAddBootManagerProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		initial: secboot_tpm2.NewPCRProtectionProfile().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 4, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
		params: &BootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*ImageLoadEvent{
				{
					Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim_sbat.efi.signed.1.1.1")),
					Next: []*ImageLoadEvent{
						{
							Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")),
							Next: []*ImageLoadEvent{
								{
									Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")),
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
					4: testutil.DecodeHexString(c, "2f64bfe7796724c68c54b14bc8690012f9e29c907dc900831dd12f912f20b2b3"),
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
		},
	})
}

func (s *bootManagerPolicySuite) TestAddBootManagerProfileClassic2(c *C) {
	// Test with a classic style configuration (same as 1), but with LoadSequences
	// constructed differently.
	s.testAddBootManagerProfile(c, &testAddBootManagerProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		params: &BootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*ImageLoadEvent{
				{
					Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim_sbat.efi.signed.1.1.1")),
					Next: []*ImageLoadEvent{
						{
							Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")),
							Next: []*ImageLoadEvent{
								{
									Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")),
								},
							},
						},
					},
				},
				{
					Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim_sbat.efi.signed.1.1.1")),
					Next: []*ImageLoadEvent{
						{
							Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")),
							Next: []*ImageLoadEvent{
								{
									Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1")),
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
					4: testutil.DecodeHexString(c, "2f64bfe7796724c68c54b14bc8690012f9e29c907dc900831dd12f912f20b2b3"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "27c1fcc75127e47454e4b7d2de4d31796d1300ce67c7ea39a4459d64412e0347"),
				},
			},
		},
	})
}

func (s *bootManagerPolicySuite) TestAddBootManagerProfileWithMissingEFIActionEvents(c *C) {
	// Test with a classic style configuration - shim -> grub -> 2 kernels, but on
	// a system that omits the ready-to-boot signal in PCR4 (should produce different
	// digests compared to 1).
	s.testAddBootManagerProfile(c, &testAddBootManagerProfileData{
		eventLogPath: "testdata/eventlog_sb_no_efi_action.bin",
		params: &BootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*ImageLoadEvent{
				{
					Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim_sbat.efi.signed.1.1.1")),
					Next: []*ImageLoadEvent{
						{
							Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")),
							Next: []*ImageLoadEvent{
								{
									Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")),
								},
								{
									Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1")),
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
					4: testutil.DecodeHexString(c, "c9a0abf798e665b6ae397716371cecd84ea06ec7c250a7119af04696a783f419"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "c856dcc6a2fd95a4d7a95ab46ee4f982775ffd614847c002450ec95af8153598"),
				},
			},
		},
	})
}

func (s *bootManagerPolicySuite) TestAddBootManagerProfileWithCustomEFIEnv(c *C) {
	// Test with a classic style configuration - shim -> grub -> 2 kernels, but using
	// a custom EFI environment. Set the log path for the "default" environment to
	// the one set in the Classic test, but supply the log used in the
	// WithMissingEFIActionEvents test via the custom environment to verify that the
	// correct one is used.
	s.testAddBootManagerProfile(c, &testAddBootManagerProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		params: &BootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []*ImageLoadEvent{
				{
					Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim_sbat.efi.signed.1.1.1")),
					Next: []*ImageLoadEvent{
						{
							Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")),
							Next: []*ImageLoadEvent{
								{
									Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")),
								},
								{
									Image: FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1")),
								},
							},
						},
					},
				},
			},
			Environment: &mockEFIEnvironment{"", "testdata/eventlog_sb_no_efi_action.bin"},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "c9a0abf798e665b6ae397716371cecd84ea06ec7c250a7119af04696a783f419"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "c856dcc6a2fd95a4d7a95ab46ee4f982775ffd614847c002450ec95af8153598"),
				},
			},
		},
	})
}
