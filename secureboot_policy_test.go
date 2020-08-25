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
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/canonical/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
)

func TestDecodeWinCertificate(t *testing.T) {
	for _, data := range []struct {
		desc            string
		path            string
		offset          int64
		expectedType    uint16
		efiGuidCertType *tcglog.EFIGUID
	}{
		{
			desc:            "AuthenticatedVariable",
			path:            "testdata/updates1/dbx/MS-2016-08-08.bin",
			offset:          16,
			expectedType:    WinCertTypeEfiGuid,
			efiGuidCertType: EFICertTypePkcs7Guid,
		},
		// TODO: Add test with signed EFI executable
	} {
		t.Run(data.desc, func(t *testing.T) {
			f, err := os.Open(data.path)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer f.Close()

			f.Seek(data.offset, io.SeekStart)

			cert, _, err := DecodeWinCertificate(f)
			if err != nil {
				t.Fatalf("DecodeWinCertificate failed: %v", err)
			}

			certType := GetWinCertificateType(cert)
			if certType != data.expectedType {
				t.Errorf("Unexpected type: %v", certType)
			}

			switch certType {
			case WinCertTypePKCSSignedData:
			case WinCertTypeEfiGuid:
				c := cert.(WinCertificate)
				if c.ToWinCertificateUefiGuid().CertType != *data.efiGuidCertType {
					t.Errorf("Unexpected WIN_CERTIFICATE_UEFI_GUID type: %v", &c.ToWinCertificateUefiGuid().CertType)
				}
			}
		})
	}
}

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
			certHash: decodeHexStringT(t, "9fc46ec43288967b862a5c12f13142325a6357746dd8195392fe1bf167e8b7ed"),
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

func TestDecodeSecureBootDb(t *testing.T) {
	var (
		microsoftOwnerGuid = tcglog.NewEFIGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b})

		microsoftRootCAName = "CN=Microsoft Root Certificate Authority 2010,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US"
		microsoftPCASubject = "CN=Microsoft Windows Production PCA 2011,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US"
		microsoftPCASerial  = decodeHexStringT(t, "61077656000000000008")

		microsoftThirdPartyRootCAName = "CN=Microsoft Corporation Third Party Marketplace Root,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US"
		microsoftCASubject            = "CN=Microsoft Corporation UEFI CA 2011,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US"
		microsoftCASerial             = decodeHexStringT(t, "6108d3c4000000000004")

		testOwnerGuid = tcglog.NewEFIGUID(0xd1b37b32, 0x172d, 0x4d2a, 0x909f, [...]uint8{0xc7, 0x80, 0x81, 0x50, 0x17, 0x86})
	)

	type certId struct {
		issuer  string
		subject string
		serial  []byte
		owner   *tcglog.EFIGUID
	}
	for _, data := range []struct {
		desc       string
		path       string
		certs      []certId
		signatures int
	}{
		{
			desc: "db1",
			path: "testdata/efivars1/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			certs: []certId{
				{
					issuer:  microsoftRootCAName,
					subject: microsoftPCASubject,
					serial:  microsoftPCASerial,
					owner:   microsoftOwnerGuid,
				},
				{
					issuer:  microsoftThirdPartyRootCAName,
					subject: microsoftCASubject,
					serial:  microsoftCASerial,
					owner:   microsoftOwnerGuid,
				},
			},
			signatures: 2,
		},
		{
			desc: "db2",
			path: "testdata/efivars2/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			certs: []certId{
				{
					issuer:  microsoftRootCAName,
					subject: microsoftPCASubject,
					serial:  microsoftPCASerial,
					owner:   microsoftOwnerGuid,
				},
				{
					issuer:  microsoftThirdPartyRootCAName,
					subject: microsoftCASubject,
					serial:  microsoftCASerial,
					owner:   microsoftOwnerGuid,
				},
				{
					issuer:  "CN=Test Key Exchange Key",
					subject: "CN=Test UEFI CA",
					serial:  decodeHexStringT(t, "01"),
					owner:   testOwnerGuid,
				},
			},
			signatures: 3,
		},
		{
			desc: "db3",
			path: "testdata/efivars3/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			certs: []certId{
				{
					issuer:  microsoftRootCAName,
					subject: microsoftPCASubject,
					serial:  microsoftPCASerial,
					owner:   microsoftOwnerGuid,
				},
				{
					issuer:  microsoftThirdPartyRootCAName,
					subject: microsoftCASubject,
					serial:  microsoftCASerial,
					owner:   microsoftOwnerGuid,
				},
				{
					issuer:  "CN=Test Key Exchange Key",
					subject: "CN=Test UEFI CA",
					serial:  decodeHexStringT(t, "01"),
					owner:   testOwnerGuid,
				},
				{
					issuer:  "CN=Test Key Exchange Key",
					subject: "CN=Test UEFI CA 2",
					serial:  decodeHexStringT(t, "02"),
					owner:   testOwnerGuid,
				},
			},
			signatures: 4,
		},
		{
			desc: "dbx1",
			path: "testdata/efivars1/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			certs: []certId{
				{
					issuer:  microsoftRootCAName,
					subject: "CN=Microsoft Windows PCA 2010,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US",
					serial:  decodeHexStringT(t, "610c6a19000000000004"),
					owner:   tcglog.NewEFIGUID(0x00000000, 0x0000, 0x0000, 0x0000, [...]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
				},
			},
			signatures: 78,
		},
		{
			desc:       "dbx2",
			path:       "testdata/efivars2/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			signatures: 1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			d, err := ioutil.ReadFile(data.path)
			if err != nil {
				t.Fatalf("ReadFile failed: %v", err)
			}

			signatures, err := DecodeSecureBootDb(bytes.NewReader(d[4:]))
			if err != nil {
				t.Fatalf("decodeSecureBootDb failed: %v", err)
			}
			if len(signatures) != data.signatures {
				t.Fatalf("Unexpected number of signatures (got %d, expected %d)", len(signatures), data.signatures)
			}
			i := 0
			for _, s := range signatures {
				sig := (*EFISignatureData)(s)
				if *sig.SignatureType() != *EFICertX509Guid {
					continue
				}

				c, err := x509.ParseCertificate(sig.Data())
				if err != nil {
					t.Errorf("ParseCertificate failed: %v", err)
				}

				if *sig.Owner() != *data.certs[i].owner {
					t.Errorf("Unexpected owner (got %s, expected %s)", sig.Owner(), data.certs[i].owner)
				}
				if c.Issuer.String() != data.certs[i].issuer {
					t.Errorf("Unexpected issuer: %s", c.Issuer)
				}
				if c.Subject.String() != data.certs[i].subject {
					t.Errorf("Unexpected subject: %s", c.Subject.String())
				}
				if !bytes.Equal(c.SerialNumber.Bytes(), data.certs[i].serial) {
					t.Errorf("Unexpected serial number (got %x, expected %x)", c.SerialNumber.Bytes(), data.certs[i].serial)
				}
				i++
			}
		})
	}
}

func TestIdentifyInitialOSLaunchVerificationEvent(t *testing.T) {
	for _, data := range []struct {
		desc    string
		logPath string
		index   int
		err     string
	}{
		{
			desc:    "SecureBootEnabled",
			logPath: "testdata/eventlog1.bin",
			index:   24,
		},
		{
			desc:    "SecureBootDisabled",
			logPath: "testdata/eventlog3.bin",
			err:     "boot manager image load event occurred without a preceding verification event",
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			f, err := os.Open(data.logPath)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer f.Close()

			log, err := tcglog.NewLog(f, tcglog.LogOptions{})
			if err != nil {
				t.Fatalf("NewLog failed: %v", err)
			}

			var events []*tcglog.Event
			for {
				e, err := log.NextEvent()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("Log parsing failed: %v", err)
				}
				events = append(events, e)
			}

			event, err := IdentifyInitialOSLaunchVerificationEvent(events)
			if data.err == "" {
				if err != nil {
					t.Fatalf("IdentifyInitialOSLaunchVerificationEvent failed: %v", err)
				}
				if events[data.index] != event.Event {
					t.Errorf("incorrect event detected")
				}
				if event.PCRIndex != 7 {
					t.Errorf("Detected event has wrong PCR index")
				}
				if event.EventType != tcglog.EventTypeEFIVariableAuthority {
					t.Errorf("Detected event has wrong type")
				}
				if event.MeasuredInPreOS() {
					t.Errorf("Detected pre-OS event")
				}
			} else {
				if err == nil {
					t.Fatalf("Expected an error")
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
		newSignatures int
	}{
		{
			desc:          "AppendOneCertToDb",
			orig:          "testdata/efivars3/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates2/db/1.bin",
			quirkMode:     SigDbUpdateQuirkModeNone,
			sha1hash:      decodeHexStringT(t, "12669d032dd0c15a157a7af0df7b86f2e174344b"),
			newSignatures: 1,
		},
		{
			desc:      "AppendExistingCertToDb",
			orig:      "testdata/efivars5/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:    "testdata/updates2/db/1.bin",
			quirkMode: SigDbUpdateQuirkModeNone,
			sha1hash:  decodeHexStringT(t, "12669d032dd0c15a157a7af0df7b86f2e174344b"),
		},
		{
			desc:          "AppendMsDbxUpdate/1",
			orig:          "testdata/efivars2/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates1/dbx/MS-2016-08-08.bin",
			quirkMode:     SigDbUpdateQuirkModeNone,
			sha1hash:      decodeHexStringT(t, "96f7dc104ee34a0ce8425aac20f29e2b2aba9d7e"),
			newSignatures: 77,
		},
		{
			desc:          "AppendMsDbxUpdate/2",
			orig:          "testdata/efivars2/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates1/dbx/MS-2016-08-08.bin",
			quirkMode:     SigDbUpdateQuirkModeDedupIgnoresOwner,
			sha1hash:      decodeHexStringT(t, "96f7dc104ee34a0ce8425aac20f29e2b2aba9d7e"),
			newSignatures: 77,
		},
		{
			desc:          "AppendDbxUpdateWithDuplicateSignatures/1",
			orig:          "testdata/efivars4/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates3/dbx/1.bin",
			quirkMode:     SigDbUpdateQuirkModeNone,
			sha1hash:      decodeHexStringT(t, "b49564b2daee39b01b524bef75cf9cde2c3a2a0d"),
			newSignatures: 2,
		},
		{
			desc:          "AppendDbxUpdateWithDuplicateSignatures/2",
			orig:          "testdata/efivars4/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates3/dbx/1.bin",
			quirkMode:     SigDbUpdateQuirkModeDedupIgnoresOwner,
			sha1hash:      decodeHexStringT(t, "d2af590925046adc61b250a71f00b7b38d0eb3d1"),
			newSignatures: 1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			orig, err := os.Open(data.orig)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer orig.Close()
			origReader := io.NewSectionReader(orig, 4, (1<<63)-5)
			origSignatures, err := DecodeSecureBootDb(origReader)
			if err != nil {
				t.Errorf("DecodeSecureBootDb failed: %v", err)
			}

			update, err := os.Open(data.update)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer update.Close()

			db, err := ComputeDbUpdate(origReader, update, data.quirkMode)
			if err != nil {
				t.Fatalf("ComputeDbUpdate failed: %v", err)
			}

			// Ensure that an append was performed (ie, the original contents are unmofified)
			origReader.Seek(0, io.SeekStart)
			origDb, err := ioutil.ReadAll(origReader)
			if err != nil {
				t.Fatalf("ReadAll failed: %v", err)
			}

			if !bytes.Equal(origDb, db[:len(origDb)]) {
				t.Errorf("ComputeDbUpdate didn't perform an append")
			}

			// Ensure that the result is well formed
			signatures, err := DecodeSecureBootDb(bytes.NewReader(db))
			if err != nil {
				t.Errorf("DecodeSecureBootDb failed: %v", err)
			}

			// Check we got the expected number of new signatures
			if (len(signatures) - len(origSignatures)) != data.newSignatures {
				t.Errorf("Incorrect number of new signatures (got %d, expected %d)", len(signatures)-len(origSignatures), data.newSignatures)
			}

			// Lastly, verify the contents against a known good digest
			h := crypto.SHA1.New()
			var attrs uint32
			if err := binary.Read(orig, binary.LittleEndian, &attrs); err != nil {
				t.Fatalf("binary.Read failed: %v", err)
			}
			if err := binary.Write(h, binary.LittleEndian, attrs); err != nil {
				t.Fatalf("binary.Write failed: %v", err)
			}
			h.Write(db)

			if !bytes.Equal(data.sha1hash, h.Sum(nil)) {
				t.Errorf("Unexpected updated contents (sha1 got %x, expected %x)", h.Sum(nil), data.sha1hash)
			}
		})
	}
}

func TestAddEFISecureBootPolicyProfile(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.SkipNow()
	}

	for _, data := range []struct {
		desc    string
		logPath string
		efivars string
		initial *PCRProtectionProfile
		params  EFISecureBootPolicyProfileParams
		values  []tpm2.PCRValues
		err     string
	}{
		{
			// Test with a classic style boot chain with grub and kernel authenticated using the shim vendor cert
			desc:    "Classic",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.1"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.shim"),
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
						7: decodeHexStringT(t, "d9ea13718ff09d8ade8e570656f4ac3d93d121d4fe784dee966b38e3fcddaf87"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.2"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*EFIImageLoadEvent{
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
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
						7: decodeHexStringT(t, "6d13b267035194ddd12fd9ec817ad7f8e5919e481cb2b4e3b54ec00a226dcb1a"),
					},
				},
			},
		},
		{
			// Test with a GRUB binary that has an invalid signature
			desc:    "InvalidGrubSignature",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.1"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.shim"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.1"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.1"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.shim"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.1"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.shim"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
										Next: []*EFIImageLoadEvent{
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.shim"),
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
						7: decodeHexStringT(t, "d9ea13718ff09d8ade8e570656f4ac3d93d121d4fe784dee966b38e3fcddaf87"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim2.efi.signed.2"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
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
						7: decodeHexStringT(t, "6d13b267035194ddd12fd9ec817ad7f8e5919e481cb2b4e3b54ec00a226dcb1a"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.3"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.3"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.3"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockgrub1.efi.signed.3"),
										Next: []*EFIImageLoadEvent{
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
											},
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.3"),
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
						7: decodeHexStringT(t, "638018bd7b8cc0ee760bc245a1626518969abcb18fa1fac5e4d6b516089e4273"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: decodeHexStringT(t, "700ae6c5f01993a7d0e7d1a27de62f4907714cb1ca5f3b331b17c98c16cad7ca"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.2"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*EFIImageLoadEvent{
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
											},
										},
									},
								},
							},
						},
					},
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.3"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*EFIImageLoadEvent{
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
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
						7: decodeHexStringT(t, "b2c71674ff57f4dbb8c565367e7b2c81b33df2fe3d1e1267301e532dc0bff244"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: decodeHexStringT(t, "a4d24afe50e018e28a7e7d95013346036514ec829ec7b6f775077733fd8c8a3f"),
					},
				},
			},
		},
		{
			// Verify that DirectLoadWithShimVerify fails if there are no shim binaries in the boot chain.
			desc:    "MissingShimVendorCertSection",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars3",
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim.efi.signed.2"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
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
						7: decodeHexStringT(t, "6d13b267035194ddd12fd9ec817ad7f8e5919e481cb2b4e3b54ec00a226dcb1a"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.2"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockgrub1.efi.signed.3"),
										Next: []*EFIImageLoadEvent{
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.3"),
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
						7: decodeHexStringT(t, "b2c71674ff57f4dbb8c565367e7b2c81b33df2fe3d1e1267301e532dc0bff244"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: decodeHexStringT(t, "2474f28ed67b5ba81d5cba8d32c309d936c836226dc7f3627c497d87043e6f32"),
					},
				},
			},
		},
		{
			// Test that a single dbx update produces 2 digests
			desc:    "DbxUpdate/1",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.1"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.shim"),
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
						7: decodeHexStringT(t, "d9ea13718ff09d8ade8e570656f4ac3d93d121d4fe784dee966b38e3fcddaf87"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: decodeHexStringT(t, "3adb2087747261c43a096cb63ce49d60548029c9e848e8db37f2613a1d39b9e3"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.1"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.shim"),
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
						7: decodeHexStringT(t, "3adb2087747261c43a096cb63ce49d60548029c9e848e8db37f2613a1d39b9e3"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: decodeHexStringT(t, "486bbbead76727ca5c634105f6f5d233c8320fa5565b053e34677bf263a684c4"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: decodeHexStringT(t, "6afe6128b8fa5826736c27c7510d7e576ace53e98abc9e0638dde94e5ec1ecde"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.1"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.shim"),
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
						7: decodeHexStringT(t, "d9ea13718ff09d8ade8e570656f4ac3d93d121d4fe784dee966b38e3fcddaf87"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: decodeHexStringT(t, "3adb2087747261c43a096cb63ce49d60548029c9e848e8db37f2613a1d39b9e3"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: decodeHexStringT(t, "774dc0533ccc3906bd75aed7539f264271dce7263a67fba757f55a89b4feb058"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.2"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.3"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*EFIImageLoadEvent{
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
											},
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.3"),
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
						7: decodeHexStringT(t, "6d13b267035194ddd12fd9ec817ad7f8e5919e481cb2b4e3b54ec00a226dcb1a"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: decodeHexStringT(t, "b2c71674ff57f4dbb8c565367e7b2c81b33df2fe3d1e1267301e532dc0bff244"),
					},
				},
				{
					tpm2.HashAlgorithmSHA256: {
						7: decodeHexStringT(t, "2474f28ed67b5ba81d5cba8d32c309d936c836226dc7f3627c497d87043e6f32"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.3"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.3"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.3"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockgrub1.efi.signed.3"),
										Next: []*EFIImageLoadEvent{
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.3"),
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
			// Test with an initial PCRProtectionProfile to verify that it behaves correctly
			desc:    "WithInitialProfile",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			initial: func() *PCRProtectionProfile {
				return NewPCRProtectionProfile().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 8, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			}(),
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim1.efi.signed.1"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.shim"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.shim"),
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
						7: decodeHexStringT(t, "d9ea13718ff09d8ade8e570656f4ac3d93d121d4fe784dee966b38e3fcddaf87"),
						8: decodeHexStringT(t, "a98b1d896c9383603b7923fffe230c9e4df24218eb84c90c5c758e63ce62843c"),
					},
				},
			},
		},
		{
			desc:    "VerifyWithDualSignedShim_1",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim2.efi.signed.21"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*EFIImageLoadEvent{
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
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
						7: decodeHexStringT(t, "6466563be3828a602d73756ec9ebcfd717336e2297dc3ad0f2fa5074b5c637b6"),
					},
				},
			},
		},
		{
			desc:    "VerifyWithDualSignedShim_2",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars3",
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim2.efi.signed.21"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*EFIImageLoadEvent{
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
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
						7: decodeHexStringT(t, "6d13b267035194ddd12fd9ec817ad7f8e5919e481cb2b4e3b54ec00a226dcb1a"),
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
			params: EFISecureBootPolicyProfileParams{
				PCRAlgorithm: tpm2.HashAlgorithmSHA256,
				LoadSequences: []*EFIImageLoadEvent{
					{
						Source: Firmware,
						Image:  FileEFIImage("testdata/mockshim2.efi.signed.2"),
						Next: []*EFIImageLoadEvent{
							{
								Source: Shim,
								Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
								Next: []*EFIImageLoadEvent{
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
									},
									{
										Source: Shim,
										Image:  FileEFIImage("testdata/mockgrub1.efi.signed.2"),
										Next: []*EFIImageLoadEvent{
											{
												Source: Shim,
												Image:  FileEFIImage("testdata/mockkernel1.efi.signed.2"),
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
	} {
		t.Run(data.desc, func(t *testing.T) {
			restoreEventLogPath := testutil.MockEventLogPath(data.logPath)
			defer restoreEventLogPath()
			restoreEfivarsPath := testutil.MockEFIVarsPath(data.efivars)
			defer restoreEfivarsPath()

			policy := data.initial
			if policy == nil {
				policy = &PCRProtectionProfile{}
			}
			expectedPcrs, _, _ := policy.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
			expectedPcrs = expectedPcrs.Merge(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})
			var expectedDigests tpm2.DigestList
			for _, v := range data.values {
				d, _ := tpm2.ComputePCRDigest(tpm2.HashAlgorithmSHA256, expectedPcrs, v)
				expectedDigests = append(expectedDigests, d)
			}

			err := AddEFISecureBootPolicyProfile(policy, &data.params)
			if data.err != "" {
				if err == nil {
					t.Fatalf("Expected AddEFISecureBootPolicyProfile to fail")
				}
				if err.Error() != data.err {
					t.Errorf("Unexpected error: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("AddEFISecureBootPolicyProfile failed: %v", err)
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
					t.Logf("Values:\n%s", policy.DumpValues(nil))
				}
			}
		})
	}
}
