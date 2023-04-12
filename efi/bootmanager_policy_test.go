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
	profile      *secboot_tpm2.PCRProtectionProfile
	branch       *secboot_tpm2.PCRProtectionProfileBranch
	params       *BootManagerProfileParams
	values       []tpm2.PCRValues
}

func (s *bootManagerPolicySuite) testAddBootManagerProfile(c *C, data *testAddBootManagerProfileData) {
	if runtime.GOARCH != "amd64" {
		c.Skip("unsupported architecture")
	}

	restoreEventLogPath := MockEventLogPath(data.eventLogPath)
	defer restoreEventLogPath()

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
	expectedPcrs = expectedPcrs.Merge(tpm2.PCRSelectionList{{Hash: data.params.PCRAlgorithm, Select: []int{4}}})
	var expectedDigests tpm2.DigestList
	for _, v := range data.values {
		d, _ := util.ComputePCRDigest(tpm2.HashAlgorithmSHA256, expectedPcrs, v)
		expectedDigests = append(expectedDigests, d)
	}

	c.Assert(AddBootManagerProfile(branch, data.params), IsNil)
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
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1"))).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1"))).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1"))),
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1"))),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "5804639fea81fffdd24566225c22341e2fb2a0c1d89a4d3982eaf55ca23448ce"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "a6129cb7017c846a8f082560516a796d4134f3136f97ca450183e0747c3bb664"),
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
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1"))).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1"))).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1"))),
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1"))),
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1"))).Loads(
							NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1"))),
							NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1"))),
						),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "5804639fea81fffdd24566225c22341e2fb2a0c1d89a4d3982eaf55ca23448ce"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "a6129cb7017c846a8f082560516a796d4134f3136f97ca450183e0747c3bb664"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "9a56db0abdb377efe1e7a5bb771b5e0c0a19fce524a5f3cd9614d3d6be2c120c"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "fe678585e9e00443912c2fe91558ad1a5b8180d130a357a58c5920fe42cafe7b"),
				},
			},
		},
	})
}

func (s *bootManagerPolicySuite) TestAddBootManagerProfileWithInitialProfile(c *C) {
	// Test with a PCRProtectionProfile that already has some values in it.
	profile := secboot_tpm2.NewPCRProtectionProfile()

	s.testAddBootManagerProfile(c, &testAddBootManagerProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		profile:      profile,
		branch: profile.RootBranch().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 4, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
		params: &BootManagerProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1"))).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1"))).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1"))),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "5804639fea81fffdd24566225c22341e2fb2a0c1d89a4d3982eaf55ca23448ce"),
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
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1"))).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1"))).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1"))),
					),
				),
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1"))).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1"))).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1"))),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "5804639fea81fffdd24566225c22341e2fb2a0c1d89a4d3982eaf55ca23448ce"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "a6129cb7017c846a8f082560516a796d4134f3136f97ca450183e0747c3bb664"),
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
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1"))).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1"))).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1"))),
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1"))),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "7d10327e46b3595b66625cf34ab842efd9cd93a311ab8d5d9fbabe5fc3bf4ed7"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "48ee65c0c9bdabc592f0207dd36d4367ed76c29a740c29210c81edf99b25a85d"),
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
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1"))).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1"))).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1"))),
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1"))),
					),
				),
			},
			Environment: &mockEFIEnvironment{"", "testdata/eventlog_sb_no_efi_action.bin"},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "7d10327e46b3595b66625cf34ab842efd9cd93a311ab8d5d9fbabe5fc3bf4ed7"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4: testutil.DecodeHexString(c, "48ee65c0c9bdabc592f0207dd36d4367ed76c29a740c29210c81edf99b25a85d"),
				},
			},
		},
	})
}
