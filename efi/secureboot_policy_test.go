// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2021 Canonical Ltd
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

type securebootPolicySuite struct{}

var _ = Suite(&securebootPolicySuite{})

type testAddSecureBootPolicyProfileData struct {
	eventLogPath string
	efivars      string
	initial      *secboot_tpm2.PCRProtectionProfile
	params       SecureBootPolicyProfileParams
	values       []tpm2.PCRValues
	errMatch     string
}

func (s *securebootPolicySuite) testAddSecureBootPolicyProfile(c *C, data *testAddSecureBootPolicyProfileData) {
	if runtime.GOARCH != "amd64" {
		c.Skip("unsupported architecture")
	}

	restoreEventLogPath := MockEventLogPath(data.eventLogPath)
	defer restoreEventLogPath()
	restoreReadVar := MockReadVar(data.efivars)
	defer restoreReadVar()
	restoreEfivarsPath := MockEFIVarsPath(data.efivars)
	defer restoreEfivarsPath()

	profile := data.initial
	if profile == nil {
		profile = secboot_tpm2.NewPCRProtectionProfile()
	}
	expectedPcrs, _, _ := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	expectedPcrs = expectedPcrs.Merge(tpm2.PCRSelectionList{{Hash: data.params.PCRAlgorithm, Select: []int{7}}})
	var expectedDigests tpm2.DigestList
	for _, v := range data.values {
		d, _ := util.ComputePCRDigest(tpm2.HashAlgorithmSHA256, expectedPcrs, v)
		expectedDigests = append(expectedDigests, d)
	}

	err := AddSecureBootPolicyProfile(profile, &data.params)
	if data.errMatch != "" {
		c.Check(err, ErrorMatches, data.errMatch)
	} else {
		c.Check(err, IsNil)

		pcrs, digests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
		c.Check(err, IsNil)
		c.Check(pcrs.Equal(expectedPcrs), Equals, true)
		c.Check(digests, DeepEquals, expectedDigests)
		if c.Failed() {
			c.Logf("Profile:\n%s", profile)
			c.Logf("Values:\n%s", tpm2test.FormatPCRValuesFromPCRProtectionProfile(profile, nil))
		}
	}
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileClassic(c *C) {
	// Test with a classic style boot flow (shim -> grub -> 2 kernels), with
	// grub and the kernel being authenticated by shim's vendor CA.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "84c3cf3c3ca91234fda780141b06af2e32bb4c6fc809216f2c33d25b84155796"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileNoSBAT(c *C) {
	// Test with a shim that doesn't have a .sbat section - we assume that this
	// will not measure the current SBAT variable contents.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb_no_sbat.bin",
		efivars:      "testdata/efivars_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim_no_sbat.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "63ef227855b50bbc7fc8c3f2c351a82aa577faa729a64960821f117862697e9f"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileUC20(c *C) {
	// Test with a UC20 style boot flow:
	// - shim -> grub -> 2 kernels
	// - shim -> grub -> grub -> 2 kernels
	// ... with grub and the kernels being authenticated by shim's vendor CA.
	// As this uses the same trust path, it should produce the same digest
	// as Classic.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1")), Shim),
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
							NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
							NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel2.efi.signed.shim.1")), Shim),
						),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "84c3cf3c3ca91234fda780141b06af2e32bb4c6fc809216f2c33d25b84155796"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileInvalidGrubSignature(c *C) {
	// Test with a component that is signed by an unrecognized authority.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim_no_vendor_cert.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1"))).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1"))),
					),
				),
			},
		},
		errMatch: "cannot compute secure boot policy profile: cannot process OS load event for testdata/amd64/mockgrub1.efi.signed.shim.1: cannot compute load verification event: cannot determine authority",
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileNoKernelSignature(c *C) {
	// Test with a component that is missing a signature.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi")), Shim),
					),
				),
			},
		},
		errMatch: "cannot compute secure boot policy profile: cannot process OS load event for testdata/amd64/mockkernel1.efi: cannot compute load verification event: no secure boot signatures",
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileShimVerificationDisabled(c *C) {
	// Test with shim verification disabled on the current boot.
	// XXX(chrisccoulson): There isn't really a valid reason to bail out here -
	//  we could generate a profile that would work once shim verification has
	//  been enabled.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb_no_shim_verification.bin",
		efivars:      "testdata/efivars_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		errMatch: "cannot compute secure boot policy profile: the current boot was performed with validation disabled in Shim",
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileSecureBootDisabled(c *C) {
	// Test with secure boot disabled on the current boot. This bails out because
	// we don't get verification events associated with UEFI drivers in the log if
	// any are loaded.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_no_sb.bin",
		efivars:      "testdata/efivars_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		errMatch: "cannot compute secure boot policy profile: the current boot was performed with secure boot disabled in firmware",
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileAllAuthenticatedWithDb(c *C) {
	// Test with all components authenticated by a CA in the UEFI db.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.1.1.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.1.1.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "1d34d3df18188302a2e514525dd0ca0e84641bc4dc2baee3f390b37b41898f8a"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileAuthenticatedWithDbAndShim(c *C) {
	// Test with one component loaded by shim being authenticated by the UEFI db and
	// the other component being authenticated by the built-in vendor cert. When shim
	// loads multiple executables with the same trust chain, only one verification
	// event is measured and we have code to detect and handle this to ensure we compute
	// the correct digest. Make sure that a second event is computed correctly if 2
	// binaries are authenticated with different certs.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.1.1.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "2377917b728cb380570fab710a463401c1f721bfafdc23ac3e71abb4526912a3"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileAuthenticateWithDbBeforeShimBasline(c *C) {
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1_plus_shim_vendor_ca",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim_no_vendor_cert.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "98f2452139898691c56bebe24aa8471990f7e849906e352ba95710f1f83710df"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileAuthenticateWithDbBeforeShim(c *C) {
	// Shim will check the UEFI db before its built-in vendor CA. Verify we compute
	// the correct digest where an executable can be authenticated by either.
	// Should produce the same digest as AuthentiateWithDbBeforeShimBaseline.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1_plus_shim_vendor_ca",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "98f2452139898691c56bebe24aa8471990f7e849906e352ba95710f1f83710df"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileAuthenticateWithDbBeforeShimNoSBAT(c *C) {
	// Old versions of shim only measured the CA certificate it authenticated a
	// binary with as opposed to the entire EFI_SIGNATURE_DATA structure. Since
	// https://github.com/rhboot/shim/commit/e3325f8100f5a14e0684ff80290e53975de1a5d9,
	// shim measures the EFI_SIGNATURE_DATA structure for events not associated with
	// its built-in vendor cert. Verify that we compute the correct digest for an older
	// shim (the heuristic being whether it has a .sbat section, but this isn't generally
	// correct. It is fine for Canonical shims though).
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb_no_sbat.bin",
		efivars:      "testdata/efivars_mock1_plus_shim_vendor_ca",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim_no_sbat.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "db4fd492da07f1922b43d0028ba53dcf203b25d62c08f4224fbe05f06a51345c"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileWithMultipleDbCerts(c *C) {
	// Test that we still compute the correct digest if the UEFI db contains certs
	// not used for authenticating the supplied binaries.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_ms_plus_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "7172a37992a5623a59c4367d6df5626045d984b1403c419409cd68686acd7173"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileWithDbxUpdate(c *C) {
	// Test that we get 2 digests when there is a single dbx update. The first one
	// should match the digest in WithMultipleDbCerts.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_ms_plus_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
			SignatureDbUpdateKeystores: []string{"testdata/update_uefi.org_2016-08-08"},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "7172a37992a5623a59c4367d6df5626045d984b1403c419409cd68686acd7173"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "fb3338118ad848a711fca6409d6f374759393c4b1cb111b87f916265ba22b38b"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileWithTwoDbxUpdates(c *C) {
	// Test that we get 3 digests where there are 2 dbx updates. The first two
	// should match the digests in WithDbxUpdates.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_ms_plus_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
			SignatureDbUpdateKeystores: []string{
				"testdata/update_uefi.org_2020-10-12",
				"testdata/update_uefi.org_2016-08-08",
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "7172a37992a5623a59c4367d6df5626045d984b1403c419409cd68686acd7173"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "fb3338118ad848a711fca6409d6f374759393c4b1cb111b87f916265ba22b38b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "6c6582f485b94c52b146ed29c6d15059b8cc6e4923f348c20987dd9b68b70cf0"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileTestDbxUpdateDedupQuirks(c *C) {
	// Test applying a dbx update that only contains 2 additional signatures - one of these
	// has the same signature data as an existing signature (but a different owner GUID).
	// The spec says that the update should append 2 new signatures, but some firmware
	// implementations will omit the new one that has the same signature data as an
	// existing signature. As we don't know how the firmware will behave, we generate
	// a profile for both cases, so this single update should produce 3 digests.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_ms_plus_mock1_and_2016_dbx_update",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
			SignatureDbUpdateKeystores: []string{"testdata/update_modified_uefi.org_2016-08-08"},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "fb3338118ad848a711fca6409d6f374759393c4b1cb111b87f916265ba22b38b"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "863319d78ddf19546e5a1b39e0fe19a0c2e51983e18cee12dd03579a8a6b76e1"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "d3e52bc6fda61d8e8b5b5c57bf4bdf96802d2a0e2d3507ff595102dfe6963f6b"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileDellEmbeddedBoxPC3000(c *C) {
	// Test using an event log from a Dell Embedded Box PC 3000.
	// See https://github.com/snapcore/secboot/issues/107
	// Should produce a single digest that matches the one in Classic.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/src/eventlog_dell_embedded_box_pc_3000.bin",
		efivars:      "testdata/efivars_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "84c3cf3c3ca91234fda780141b06af2e32bb4c6fc809216f2c33d25b84155796"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileToInitialProfile(c *C) {
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1",
		initial: func() *secboot_tpm2.PCRProtectionProfile {
			return secboot_tpm2.NewPCRProtectionProfile().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
		}(),
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "84c3cf3c3ca91234fda780141b06af2e32bb4c6fc809216f2c33d25b84155796"),
					8: testutil.DecodeHexString(c, "a98b1d896c9383603b7923fffe230c9e4df24218eb84c90c5c758e63ce62843c"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileWithCustomEnv(c *C) {
	// Test with a custom EFI environment. Set the mock environment to an invalid
	// one to ensure that the correct environment is used.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_no_sb.bin",
		efivars:      "testdata/efivars_ms",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
			Environment: newMockEFIEnvironmentFromFiles(c, "testdata/efivars_mock1", "testdata/eventlog_sb.bin"),
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "84c3cf3c3ca91234fda780141b06af2e32bb4c6fc809216f2c33d25b84155796"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileUpgrageToSBATShim(c *C) {
	// Test upgrading from pre-SBAT shim to a SBAT shim. This should produce 2 digests
	// that match the ones in Classic and NoSBAT.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb_no_sbat.bin",
		efivars:      "testdata/efivars_mock1",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim_no_sbat.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "63ef227855b50bbc7fc8c3f2c351a82aa577faa729a64960821f117862697e9f"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "84c3cf3c3ca91234fda780141b06af2e32bb4c6fc809216f2c33d25b84155796"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileDbCARotation(c *C) {
	// Test that an update to shim where the authenticating CA changes produces 2 digests.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1_plus_extra_db_ca",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.2.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "1addd78383c266a590898323e8524e27cf3b230396e5dd3d64fdd67c734071c1"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "8ffc5c808206b903807f1a3da88251bd376119d7e4ea214042c262e315e75812"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyProfileDbCARotation3(c *C) {
	// Test that updating grub and the kernel on a system where everything is
	// authenticated via the UEFI db and the authenticating CA changes produces
	// 4 digests.
	// (old -> old, old -> new, new -> old, new -> new)
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1_plus_extra_db_ca",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.1.1.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.1.1.1")), Shim),
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.1.2.1")), Shim),
					),
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.1.2.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.1.1.1")), Shim),
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.1.2.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "8aa7d038c81499dac1e6e6c31279949ab25d2b9375ed423c2e640df23d9a8565"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "a0dd6479cc39314ba0bb6a634f5ba2d2cf740e3cbb0f282af5f1bf895b7902e0"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "c5822b1d2aef48edd31ff04aa51f2af9dae53e5bb8f8bc564c355ded1967b85e"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "662d38c6a5938245d08de02b57fe2319fcdfd39dcb5c336bc5a6fe80287d763e"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyDualSignedShimBaseline1(c *C) {
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1_plus_mock2",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.2.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "3f2a3ec3dc632b253644bac36ec831bc8828845ec7837f0caf5a81e182bf42ce"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyDualSignedShimBaseline2(c *C) {
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1_plus_mock2",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "184f3b0914408091fd62d16f0dc6a97f420881ae1e70c5aca4fdfb5547cba856"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyDualSignedShimBaseline3(c *C) {
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock2",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.2.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "d8348aafadb44d32d77b78480c8f1f82a0bf39f80ce27e241aef73189294969f"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyDualSignedShim1(c *C) {
	// Test with a dual signed shim and verify that we produce a digest for
	// the first signature where the UEFI db contains CAs that can authenticate
	// both. Should produce the digest from DualSignedBaseline1 rather than
	// DualSignedBaseline2.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock1_plus_mock2",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.2.1.1+1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "3f2a3ec3dc632b253644bac36ec831bc8828845ec7837f0caf5a81e182bf42ce"),
				},
			},
		},
	})
}

func (s *securebootPolicySuite) TestAddSecureBootPolicyDualSignedShim2(c *C) {
	// Test with a dual-signed shim and verify we produce a digest for the
	// second signature where the UEFI db only contains a CA that can
	// authenticate it. Should produce the same digest as DualSignedBaseline3.
	s.testAddSecureBootPolicyProfile(c, &testAddSecureBootPolicyProfileData{
		eventLogPath: "testdata/eventlog_sb.bin",
		efivars:      "testdata/efivars_mock2",
		params: SecureBootPolicyProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			LoadSequences: []ImageLoadActivity{
				NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockshim.efi.signed.2.1.1+1.1.1")), Firmware).Loads(
					NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockgrub1.efi.signed.shim.1")), Shim).Loads(
						NewImageLoadActivity(FileImage(filepath.Join("testdata", runtime.GOARCH, "mockkernel1.efi.signed.shim.1")), Shim),
					),
				),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: testutil.DecodeHexString(c, "d8348aafadb44d32d77b78480c8f1f82a0bf39f80ce27e241aef73189294969f"),
				},
			},
		},
	})
}
