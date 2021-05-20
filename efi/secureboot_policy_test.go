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
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"encoding/binary"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot"
	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"
)

func TestReadShimVendorCert(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.SkipNow()
	}

	for _, data := range []struct {
		desc     string
		path     string
		err      string
		certHash []byte
	}{
		{
			desc:     "WithVendorCert",
			path:     "testdata/mockshim1.efi.signed.2",
			certHash: testutil.DecodeHexStringT(t, "9fc46ec43288967b862a5c12f13142325a6357746dd8195392fe1bf167e8b7ed"),
		},
		{
			desc: "NoVendorCert",
			path: "testdata/mockshim.efi.signed.2",
		},
		{
			desc: "NotShim",
			path: "testdata/mockgrub1.efi.signed.2",
			err:  "missing .vendor_cert section",
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			f, err := os.Open(data.path)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer f.Close()

			cert, err := ReadShimVendorCert(f)
			if data.err == "" {
				if err != nil {
					t.Errorf("ReadShimVendorCert failed: %v", err)
				}
				if data.certHash != nil {
					h := crypto.SHA256.New()
					h.Write(cert)
					if !bytes.Equal(h.Sum(nil), data.certHash) {
						t.Errorf("Unexpected certificate hash (got %x)", h.Sum(nil))
					}
				} else if len(cert) > 0 {
					t.Errorf("ReadShimVendorCert should have returned no data")
				}
			} else {
				if err == nil {
					t.Fatalf("ReadShimVendorCert should have failed: %v", err)
				}
				if err.Error() != data.err {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestComputeDbUpdate(t *testing.T) {
	for _, data := range []struct {
		desc          string
		orig          string
		update        string
		quirkMode     SigDbUpdateQuirkMode
		sha1hash      []byte
		newESLs       int
		newSignatures []int
	}{
		{
			desc:          "AppendOneCertToDb",
			orig:          "testdata/efivars3/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates2/db/1.bin",
			quirkMode:     SigDbUpdateQuirkModeNone,
			sha1hash:      testutil.DecodeHexStringT(t, "12669d032dd0c15a157a7af0df7b86f2e174344b"),
			newESLs:       1,
			newSignatures: []int{1},
		},
		{
			desc:      "AppendExistingCertToDb",
			orig:      "testdata/efivars5/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:    "testdata/updates2/db/1.bin",
			quirkMode: SigDbUpdateQuirkModeNone,
			sha1hash:  testutil.DecodeHexStringT(t, "12669d032dd0c15a157a7af0df7b86f2e174344b"),
		},
		{
			desc:          "AppendMsDbxUpdate/1",
			orig:          "testdata/efivars2/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates1/dbx/MS-2016-08-08.bin",
			quirkMode:     SigDbUpdateQuirkModeNone,
			sha1hash:      testutil.DecodeHexStringT(t, "96f7dc104ee34a0ce8425aac20f29e2b2aba9d7e"),
			newESLs:       1,
			newSignatures: []int{77},
		},
		{
			desc:          "AppendMsDbxUpdate/2",
			orig:          "testdata/efivars2/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates1/dbx/MS-2016-08-08.bin",
			quirkMode:     SigDbUpdateQuirkModeDedupIgnoresOwner,
			sha1hash:      testutil.DecodeHexStringT(t, "96f7dc104ee34a0ce8425aac20f29e2b2aba9d7e"),
			newESLs:       1,
			newSignatures: []int{77},
		},
		{
			desc:          "AppendDbxUpdateWithDuplicateSignatures/1",
			orig:          "testdata/efivars4/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates3/dbx/1.bin",
			quirkMode:     SigDbUpdateQuirkModeNone,
			sha1hash:      testutil.DecodeHexStringT(t, "b49564b2daee39b01b524bef75cf9cde2c3a2a0d"),
			newESLs:       1,
			newSignatures: []int{2},
		},
		{
			desc:          "AppendDbxUpdateWithDuplicateSignatures/2",
			orig:          "testdata/efivars4/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates3/dbx/1.bin",
			quirkMode:     SigDbUpdateQuirkModeDedupIgnoresOwner,
			sha1hash:      testutil.DecodeHexStringT(t, "d2af590925046adc61b250a71f00b7b38d0eb3d1"),
			newESLs:       1,
			newSignatures: []int{1},
		},
		{
			desc:          "AppendDbxUpdateWithMultipleESLs",
			orig:          "testdata/efivars2/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates5/dbx/dbxupdate_x64_1.bin",
			quirkMode:     SigDbUpdateQuirkModeNone,
			sha1hash:      testutil.DecodeHexStringT(t, "306985f67cdc580e25c1572568f9e65e420984d2"),
			newESLs:       4,
			newSignatures: []int{1, 1, 1, 183},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			o, err := os.Open(data.orig)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer o.Close()

			orig := io.NewSectionReader(o, 4, (1<<63)-5)

			origDb, err := efi.ReadSignatureDatabase(orig)
			if err != nil {
				t.Errorf("ReadSignatureDatabase failed: %v", err)
			}

			update, err := os.Open(data.update)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer update.Close()

			orig.Seek(0, io.SeekStart)
			updated, err := ComputeDbUpdate(orig, update, data.quirkMode)
			if err != nil {
				t.Errorf("ComputeDbUpdate failed: %v", err)
			}

			// Ensure that an append was performed (ie, the original contents are unmofified)
			orig.Seek(0, io.SeekStart)
			origBytes, err := ioutil.ReadAll(orig)
			if err != nil {
				t.Errorf("ReadAll failed: %v", err)
			}

			if !bytes.Equal(origBytes, updated[:len(origBytes)]) {
				t.Errorf("ComputeDbUpdate didn't perform an append")
			}

			// Ensure that the result is well formed
			updatedDb, err := efi.ReadSignatureDatabase(bytes.NewReader(updated))
			if err != nil {
				t.Errorf("ReadSignatureDatabase failed: %v", err)
			}

			if (len(updatedDb) - len(origDb)) != data.newESLs {
				t.Errorf("Incorrect number of new ESLs (got %d, expected %d)", len(updatedDb)-len(origDb), data.newESLs)
			}
			for i := 0; i < data.newESLs; i++ {
				if len(updatedDb[len(origDb)+i].Signatures) != data.newSignatures[i] {
					t.Errorf("Incorrect number of new signatures (got %d, expected %d)", len(updatedDb[len(origDb)+i].Signatures), data.newSignatures[i])
				}
			}

			// Lastly, verify the contents against a known good digest
			h := crypto.SHA1.New()
			var attrs uint32
			if err := binary.Read(o, binary.LittleEndian, &attrs); err != nil {
				t.Fatalf("binary.Read failed: %v", err)
			}
			if err := binary.Write(h, binary.LittleEndian, attrs); err != nil {
				t.Fatalf("binary.Write failed: %v", err)
			}
			h.Write(updated)

			if !bytes.Equal(data.sha1hash, h.Sum(nil)) {
				t.Errorf("Unexpected updated contents (sha1 got %x, expected %x)", h.Sum(nil), data.sha1hash)
			}
		})
	}
}

func TestAddSecureBootPolicyProfile(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.SkipNow()
	}

	for _, data := range []struct {
		desc    string
		logPath string
		efivars string
		initial *secboot.PCRProtectionProfile
		params  SecureBootPolicyProfileParams
		values  []tpm2.PCRValues
		err     string
	}{
		{
			// Test with a classic style boot chain with grub and kernel authenticated using the shim vendor cert
			desc:    "Classic",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.1"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.shim"),
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
						7: testutil.DecodeHexStringT(t, "d9ea13718ff09d8ade8e570656f4ac3d93d121d4fe784dee966b38e3fcddaf87"),
					},
				},
			},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. All
			// components are authenticated using a certificate in the UEFI signature db.
			desc:    "UC20AuthenticateWithDb",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars3",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.2"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*ImageLoadEvent{
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
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
						7: testutil.DecodeHexStringT(t, "6d13b267035194ddd12fd9ec817ad7f8e5919e481cb2b4e3b54ec00a226dcb1a"),
					},
				},
			},
		},
		{
			// Test with a GRUB binary that has an invalid signature
			desc:    "InvalidGrubSignature",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.1"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.shim"),
									},
								},
							},
						},
					},
				},
			},
			err: "cannot compute secure boot policy profile: no bootable paths with current EFI signature database",
		},
		{
			// Test with an unsigned kernel
			desc:    "NoKernelSignature",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.1"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi"),
									},
								},
							},
						},
					},
				},
			},
			err: "cannot compute secure boot policy profile: cannot process OS load event for testdata/mockkernel1.efi: cannot compute load " +
				"verification event: no Authenticode signatures",
		},
		{
			// Test with secure boot enforcement disabled in shim
			desc:    "ShimVerificationDisabled",
			logPath: "testdata/eventlog2.bin",
			efivars: "testdata/efivars2",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.1"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.shim"),
									},
								},
							},
						},
					},
				},
			},
			err: "cannot compute secure boot policy profile: the current boot was performed with validation disabled in Shim",
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. Grub
			// and the kernel are authenticated using a shim's vendor cert.
			desc:    "UC20AuthenticateGrubAndKernelWithShim",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.1"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.shim"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockgrub1.efi.signed.shim"),
										Next: []*ImageLoadEvent{
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.shim"),
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
						7: testutil.DecodeHexStringT(t, "d9ea13718ff09d8ade8e570656f4ac3d93d121d4fe784dee966b38e3fcddaf87"),
					},
				},
			},
		},
		{
			// Verify that when grub and kernel can be authenticated using a CA in both shim and the UEFI signature db, we compute digests
			// for authenticating with the signature database, as that is what shim tries first.
			desc:    "AuthenticateUsingDbBeforeShim",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars3",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim2.efi.signed.2"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
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
						7: testutil.DecodeHexStringT(t, "6d13b267035194ddd12fd9ec817ad7f8e5919e481cb2b4e3b54ec00a226dcb1a"),
					},
				},
			},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. All
			// components are authenticated using a certificate in the UEFI signature db. There are 2 kernels for each system, each signed
			// with a different key to simulate what the profile might look like after installing a kernel signed with a new key.
			desc:    "KernelCARotationUC20",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars5",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.3"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.3"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.3"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockgrub1.efi.signed.3"),
										Next: []*ImageLoadEvent{
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
											},
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.3"),
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
						7: testutil.DecodeHexStringT(t, "638018bd7b8cc0ee760bc245a1626518969abcb18fa1fac5e4d6b516089e4273"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "700ae6c5f01993a7d0e7d1a27de62f4907714cb1ca5f3b331b17c98c16cad7ca"),
					},
				},
			},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. All
			// components are authenticated using a certificate in the UEFI signature db. There are paths through 2 different shim binaries,
			// each signed with a different key to simulate what the profile might look like before committing a shim update signed with a
			// new key.
			desc:    "ShimCARotationUC20",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars5",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.2"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*ImageLoadEvent{
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
											},
										},
									},
								},
							},
						},
					},
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.3"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*ImageLoadEvent{
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
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
						7: testutil.DecodeHexStringT(t, "b2c71674ff57f4dbb8c565367e7b2c81b33df2fe3d1e1267301e532dc0bff244"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "a4d24afe50e018e28a7e7d95013346036514ec829ec7b6f775077733fd8c8a3f"),
					},
				},
			},
		},
		{
			// Verify that DirectLoadWithShimVerify fails if there are no shim binaries in the boot chain.
			desc:    "MissingShimVendorCertSection",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars3",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
							},
						},
					},
				},
			},
			err: "cannot compute secure boot policy profile: cannot process OS load event for testdata/mockkernel1.efi.signed.2: cannot " +
				"compute load verification event: shim specified as event source without a shim executable appearing in preceding events",
		},
		{
			// Test that shim binaries without a vendor cert work correctly
			desc:    "NoShimVendorCert",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars3",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim.efi.signed.2"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
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
						7: testutil.DecodeHexStringT(t, "6d13b267035194ddd12fd9ec817ad7f8e5919e481cb2b4e3b54ec00a226dcb1a"),
					},
				},
			},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. The
			// normal and recovery chains have different trust paths
			desc:    "MismatchedNormalAndRecoverySystemsUC20",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars5",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.2"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockgrub1.efi.signed.3"),
										Next: []*ImageLoadEvent{
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.3"),
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
						7: testutil.DecodeHexStringT(t, "b2c71674ff57f4dbb8c565367e7b2c81b33df2fe3d1e1267301e532dc0bff244"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "2474f28ed67b5ba81d5cba8d32c309d936c836226dc7f3627c497d87043e6f32"),
					},
				},
			},
		},
		{
			// Test that a single dbx update produces 2 digests
			desc:    "DbxUpdate/1",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.1"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.shim"),
									},
								},
							},
						},
					},
				},
				SignatureDbUpdateKeystores: []string{"testdata/updates1"},
			},
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "d9ea13718ff09d8ade8e570656f4ac3d93d121d4fe784dee966b38e3fcddaf87"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "3adb2087747261c43a096cb63ce49d60548029c9e848e8db37f2613a1d39b9e3"),
					},
				},
			},
		},
		{
			// Test that a single dbx update that contains a signature that only differs from an existing signature by SignatureOwner
			// produces 3 digests - we don't know whether the firmware will consider this extra signature as new or not, so precompute
			// values for both scenarios.
			desc:    "DbxUpdate/2",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars4",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.1"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.shim"),
									},
								},
							},
						},
					},
				},
				SignatureDbUpdateKeystores: []string{"testdata/updates3"},
			},
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "3adb2087747261c43a096cb63ce49d60548029c9e848e8db37f2613a1d39b9e3"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "486bbbead76727ca5c634105f6f5d233c8320fa5565b053e34677bf263a684c4"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "6afe6128b8fa5826736c27c7510d7e576ace53e98abc9e0638dde94e5ec1ecde"),
					},
				},
			},
		},
		{
			// Test that a db anx dbx update produces 3 digests (a before and after digest, plus an intermediate one in case the device dies
			// in between updates. Each update is written atomically, but there isn't atomicity between updates, so the 3 digests takes care
			// of this)
			desc:    "DbAndDbxUpdate",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.1"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.shim"),
									},
								},
							},
						},
					},
				},
				SignatureDbUpdateKeystores: []string{"testdata/updates4"},
			},
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "d9ea13718ff09d8ade8e570656f4ac3d93d121d4fe784dee966b38e3fcddaf87"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "3adb2087747261c43a096cb63ce49d60548029c9e848e8db37f2613a1d39b9e3"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "774dc0533ccc3906bd75aed7539f264271dce7263a67fba757f55a89b4feb058"),
					},
				},
			},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. All
			// components are authenticated using a certificate in the UEFI signature db. There is a pending db update which adds a new CA,
			// and 2 kernels for each system - one signed with an existing CA and one signed with the new one. Verify that we get 3 digests
			// (the new kernels can only be authenticated after the db update is applied).
			desc:    "DbUpdateAndKernelCARotationUC20",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars3",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.2"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.3"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*ImageLoadEvent{
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
											},
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.3"),
											},
										},
									},
								},
							},
						},
					},
				},
				SignatureDbUpdateKeystores: []string{"testdata/updates2"},
			},
			values: []tpm2.PCRValues{
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "6d13b267035194ddd12fd9ec817ad7f8e5919e481cb2b4e3b54ec00a226dcb1a"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "b2c71674ff57f4dbb8c565367e7b2c81b33df2fe3d1e1267301e532dc0bff244"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: testutil.DecodeHexStringT(t, "2474f28ed67b5ba81d5cba8d32c309d936c836226dc7f3627c497d87043e6f32"),
					},
				},
			},
		},
		{
			// Test that computation fails with an error even if there are some bootable paths, if there are no bootable paths with the
			// initial (pre-update) signature database.
			desc:    "DbUpdateWithNoInitialBootablePaths",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.3"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.3"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.3"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockgrub1.efi.signed.3"),
										Next: []*ImageLoadEvent{
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.3"),
											},
										},
									},
								},
							},
						},
					},
				},
				SignatureDbUpdateKeystores: []string{"testdata/updates2"},
			},
			err: "cannot compute secure boot policy profile: no bootable paths with current EFI signature database",
		},
		{
			// Test with an initial secboot.PCRProtectionProfile to verify that it behaves correctly
			desc:    "WithInitialProfile",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			initial: func() *secboot.PCRProtectionProfile {
				return secboot.NewPCRProtectionProfile().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			}(),
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.1"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.shim"),
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
						7: testutil.DecodeHexStringT(t, "d9ea13718ff09d8ade8e570656f4ac3d93d121d4fe784dee966b38e3fcddaf87"),
						8: testutil.DecodeHexStringT(t, "a98b1d896c9383603b7923fffe230c9e4df24218eb84c90c5c758e63ce62843c"),
					},
				},
			},
		},
		{
			desc:    "VerifyWithDualSignedShim_1",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim2.efi.signed.21"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*ImageLoadEvent{
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
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
						7: testutil.DecodeHexStringT(t, "6466563be3828a602d73756ec9ebcfd717336e2297dc3ad0f2fa5074b5c637b6"),
					},
				},
			},
		},
		{
			desc:    "VerifyWithDualSignedShim_2",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars3",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim2.efi.signed.21"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*ImageLoadEvent{
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
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
						7: testutil.DecodeHexStringT(t, "6d13b267035194ddd12fd9ec817ad7f8e5919e481cb2b4e3b54ec00a226dcb1a"),
					},
				},
			},
		},
		{
			// Verify that a load sequence is omitted from the profile if any intermediate component can't be authenticated
			// before a branch.
			desc:    "NoBootablePaths",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim2.efi.signed.2"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*ImageLoadEvent{
											{
												Source: Shim,
												Image:  FileImage("testdata/mockkernel1.efi.signed.2"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			err: "cannot compute secure boot policy profile: no bootable paths with current EFI signature database",
		},
		{
			// Test with a classic style boot chain with grub and kernel authenticated using the shim vendor cert, using
			// an event log where the order of EV_EFI_VARIABLE_AUTHORITY and EV_EFI_BOOT_SERVICES_APPLICATION events are
			// misordered according to the spec, and where the EV_SEPARATOR event for PCR7 is measured as part of the transition
			// to OS-present as opposed to immediately before the handoff to BDS.
			desc:    "Classic/2",
			logPath: "testdata/eventlog4.bin",
			efivars: "testdata/efivars2",
			params: SecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*ImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileImage("testdata/mockshim1.efi.signed.1"),
						Next: []*ImageLoadEvent{
							{
								Source: Shim,
								Image:  FileImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*ImageLoadEvent{
									{
										Source: Shim,
										Image:  FileImage("testdata/mockkernel1.efi.signed.shim"),
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
						7: testutil.DecodeHexStringT(t, "b00b060d82d146bc21cf22576f7d468dce3b898ce01e5ca5b7cf93cf02bbd2e8"),
					},
				},
			},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			restoreEventLogPath := testutil.MockEventLogPath(data.logPath)
			defer restoreEventLogPath()
			restoreReadVar := testutil.MockEFIReadVar(data.efivars)
			defer restoreReadVar()
			restoreEfivarsPath := testutil.MockEFIVarsPath(data.efivars)
			defer restoreEfivarsPath()

			policy := data.initial
			if policy == nil {
				policy = &secboot.PCRProtectionProfile{}
			}
			expectedPcrs, _, _ := policy.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
			expectedPcrs = expectedPcrs.Merge(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})
			var expectedDigests tpm2.DigestList
			for _, v := range data.values {
				d, _ := tpm2.ComputePCRDigest(tpm2.HashAlgorithmSHA256, expectedPcrs, v)
				expectedDigests = append(expectedDigests, d)
			}

			err := AddSecureBootPolicyProfile(policy, &data.params)
			if data.err != "" {
				if err == nil {
					t.Fatalf("Expected AddSecureBootPolicyProfile to fail")
				}
				if err.Error() != data.err {
					t.Errorf("Unexpected error: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("AddSecureBootPolicyProfile failed: %v", err)
				}

				pcrs, digests, err := policy.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
				if err != nil {
					t.Fatalf("ComputePCRDigests failed: %v", err)
				}
				if !pcrs.Equal(expectedPcrs) {
					t.Errorf("ComputePCRDigests returned the wrong selection")
				}
				if !reflect.DeepEqual(digests, expectedDigests) {
					t.Errorf("ComputePCRDigests returned unexpected values")
					t.Logf("Profile:\n%s", policy)
					t.Logf("Values:\n%s", testutil.FormatPCRValuesFromPCRProtectionProfile(policy, nil))
				}
			}
		})
	}
}
