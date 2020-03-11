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
	"runtime"
	"testing"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
	. "github.com/snapcore/secboot"
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
			path:            "testdata/updates/dbx/MS-2016-08-08.bin",
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

			cert, err := DecodeWinCertificate(f)
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
			certHash: decodeHexString(t, "9badc31b6b648413f07dfa94559c27e1b923f474e2cf6bd7b40369913b6cd334"),
		},
		{
			desc: "NoVendorCert",
			path: "testdata/mockshim.efi.signed.1",
		},
		{
			desc: "NotShim",
			path: "testdata/mock.efi.signed.1",
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
					c, err := x509.ParseCertificate(cert)
					if err != nil {
						t.Fatalf("ParseCertificate failed: %v", err)
					}
					h := crypto.SHA256.New()
					h.Write(c.Raw)
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
		microsoftPCASerial  = decodeHexString(t, "61077656000000000008")

		microsoftThirdPartyRootCAName = "CN=Microsoft Corporation Third Party Marketplace Root,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US"
		microsoftCASubject            = "CN=Microsoft Corporation UEFI CA 2011,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US"
		microsoftCASerial             = decodeHexString(t, "6108d3c4000000000004")

		testOwnerGuid  = tcglog.NewEFIGUID(0xd1b37b32, 0x172d, 0x4d2a, 0x909f, [...]uint8{0xc7, 0x80, 0x81, 0x50, 0x17, 0x86})
		testRootCAName = "CN=Test UEFI CA"
		testCASubject  = "CN=Test UEFI CA"
		testCASerial1  = decodeHexString(t, "1bd2a0d563e5901d6d1488431bc639bf06e0f4fa")
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
			path: "testdata/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
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
				{
					issuer:  testRootCAName,
					subject: testCASubject,
					serial:  testCASerial1,
					owner:   testOwnerGuid,
				},
			},
			signatures: 3,
		},
		{
			desc: "db3",
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
					issuer:  testRootCAName,
					subject: testCASubject,
					serial:  testCASerial1,
					owner:   testOwnerGuid,
				},
				{
					issuer:  testRootCAName,
					subject: testCASubject,
					serial:  decodeHexString(t, "2c7a9ef3e50ab167953021d32e4e9233cbc480a9"),
					owner:   testOwnerGuid,
				},
			},
			signatures: 4,
		},
		{
			desc: "dbx1",
			path: "testdata/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			certs: []certId{
				{
					issuer:  microsoftRootCAName,
					subject: "CN=Microsoft Windows PCA 2010,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US",
					serial:  decodeHexString(t, "610c6a19000000000004"),
					owner:   tcglog.NewEFIGUID(0x00000000, 0x0000, 0x0000, 0x0000, [...]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
				},
			},
			signatures: 78,
		},
		{
			desc:       "dbx2",
			path:       "testdata/efivars1/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
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
				if sig.SignatureType() != EFICertX509Guid {
					continue
				}

				c, err := x509.ParseCertificate(sig.Data())
				if err != nil {
					t.Errorf("ParseCertificate failed: %v", err)
				}

				if sig.Owner() != data.certs[i].owner {
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
			logPath: "testdata/eventlog7.bin",
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
				e := (*SecureBootVerificationEvent)(event)
				if events[data.index] != e.Event() {
					t.Errorf("incorrect event detected")
				}
				if e.Event().PCRIndex != 7 {
					t.Errorf("Detected event has wrong PCR index")
				}
				if e.Event().EventType != tcglog.EventTypeEFIVariableAuthority {
					t.Errorf("Detected event has wrong type")
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
		sha1hash      []byte
		newSignatures int
	}{
		{
			desc:          "AppendOneCertToDb",
			orig:          "testdata/efivars1/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates1/db/1.bin",
			sha1hash:      decodeHexString(t, "49785b436fbcbbc4349dfae2c0895477baba15e8"),
			newSignatures: 1,
		},
		{
			desc:     "AppendExistingCertToDb",
			orig:     "testdata/efivars2/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:   "testdata/updates1/db/1.bin",
			sha1hash: decodeHexString(t, "49785b436fbcbbc4349dfae2c0895477baba15e8"),
		},
		{
			desc:          "AppendMsDbxUpdate",
			orig:          "testdata/efivars1/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates/dbx/MS-2016-08-08.bin",
			sha1hash:      decodeHexString(t, "96f7dc104ee34a0ce8425aac20f29e2b2aba9d7e"),
			newSignatures: 77,
		},
		{
			desc:          "AppendDbxUpdateWithDuplicateSignatures",
			orig:          "testdata/efivars3/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
			update:        "testdata/updates2/dbx/1.bin",
			sha1hash:      decodeHexString(t, "b49564b2daee39b01b524bef75cf9cde2c3a2a0d"),
			newSignatures: 2,
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

			db, err := ComputeDbUpdate(origReader, update)
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

func TestComputeSecureBootPolicyDigests(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.SkipNow()
	}

	for _, data := range []struct {
		desc                       string
		logPath                    string
		efivars                    string
		loadSequences              []*EFIImageLoadEvent
		signatureDbUpdateKeystores []string
		digests                    tpm2.DigestList
		err                        string
	}{
		{
			// Test with a classic style boot chain with grub and kernel verified against the shim vendor cert
			desc:    "VerifyFromDbClassic",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim2.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.2"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.2"),
								},
							},
						},
					},
				},
			},
			digests: tpm2.DigestList{decodeHexString(t, "4a4fd90c8418bc4e6c763acc6d8849fdd997ceafbafe83538c507daf165ae8e6")},
		},
		{
			// Test with a classic style boot chain with grub and kernel verified against the shim vendor cert, and grub signed by the actual
			// CA certificate
			desc:    "VerifyDirectCASignature",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim2.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.ca2"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.2"),
								},
							},
						},
					},
				},
			},
			digests: tpm2.DigestList{decodeHexString(t, "4a4fd90c8418bc4e6c763acc6d8849fdd997ceafbafe83538c507daf165ae8e6")},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. GRUB
			// and the kernel are verified by the UEFI db and shim contains a vendor cert that isn't used.
			desc:    "VerifyFromDbUC20",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim2.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.1"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
								},
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
									Next: []*EFIImageLoadEvent{
										{
											Source: Shim,
											Image:  FileEFIImage("testdata/mock.efi.signed.1"),
										},
									},
								},
							},
						},
					},
				},
			},
			digests: tpm2.DigestList{decodeHexString(t, "e80130f2d8212d6969f0cd20effc3bbded14584861f8f560fbc5208a8bfc0681")},
		},
		{
			// Test with a GRUB binary that has an invalid signature
			desc:    "InvalidGrubSignature",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim1.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.2"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
								},
							},
						},
					},
				},
			},
			err: "no bootable paths with current EFI signature database",
		},
		{
			// Test with an unsigned kernel
			desc:    "NoKernelSignature",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim2.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.2"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi"),
								},
							},
						},
					},
				},
			},
			err: "cannot process OS load event for testdata/mock.efi: cannot compute load verification event: cannot decode WIN_CERTIFICATE " +
				"from security directory entry of PE binary: cannot read WIN_CERTIFICATE header fields: EOF",
		},
		{
			// Test with secure boot enforcement disabled in shim
			desc:    "ShimVerificationDisabled",
			logPath: "testdata/eventlog2.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim2.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.2"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.2"),
								},
							},
						},
					},
				},
			},
			err: "the current boot was performed with validation disabled in Shim",
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. GRUB
			// and the kernel are verified by shim's vendor cert
			desc:    "VerifyGrubAndKernelWithShimVendorCert",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim2.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.2"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.2"),
								},
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.2"),
									Next: []*EFIImageLoadEvent{
										{
											Source: Shim,
											Image:  FileEFIImage("testdata/mock.efi.signed.2"),
										},
									},
								},
							},
						},
					},
				},
			},
			digests: tpm2.DigestList{decodeHexString(t, "4a4fd90c8418bc4e6c763acc6d8849fdd997ceafbafe83538c507daf165ae8e6")},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. GRUB
			// and the kernel are verified by the UEFI db, and shim contains a vendor cert that could verify them but isn't used. This
			// verifies that we pick the correct order here (UEFI db -> shim)
			desc:    "VerifyFromDbUC20_2",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim1.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.1"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
								},
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
									Next: []*EFIImageLoadEvent{
										{
											Source: Shim,
											Image:  FileEFIImage("testdata/mock.efi.signed.1"),
										},
									},
								},
							},
						},
					},
				},
			},
			digests: tpm2.DigestList{decodeHexString(t, "e80130f2d8212d6969f0cd20effc3bbded14584861f8f560fbc5208a8bfc0681")},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. GRUB
			// is verified by shim's vendor cert and the kernel is verified by the UEFI db
			desc:    "VerifyFromDbUC20_3",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim2.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.2"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
								},
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.2"),
									Next: []*EFIImageLoadEvent{
										{
											Source: Shim,
											Image:  FileEFIImage("testdata/mock.efi.signed.1"),
										},
									},
								},
							},
						},
					},
				},
			},
			digests: tpm2.DigestList{decodeHexString(t, "f73bb24f88ba33e9a99688bb47e72edd798f2442c8e072e0de03cde9edbbf394")},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. Two
			// kernels are supplied for both normal and recovery paths signed with alternate keys to simulate what would happen when upgrading
			// to a kernel signed with a new key
			desc:    "KernelKeyRotationUC20",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars2",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim2.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.1"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
								},
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.2"),
								},
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
									Next: []*EFIImageLoadEvent{
										{
											Source: Shim,
											Image:  FileEFIImage("testdata/mock.efi.signed.1"),
										},
										{
											Source: Shim,
											Image:  FileEFIImage("testdata/mock.efi.signed.2"),
										},
									},
								},
							},
						},
					},
				},
			},
			digests: tpm2.DigestList{
				decodeHexString(t, "bed6e96b835c1e2bb3c7ea930f9ec728f05eeeb5622e99b8f12fafe6df93039f"),
				decodeHexString(t, "46387dc7040c29ec3ac57b5e616f5ede478a9f735fec08311e6f0b78e53ddb66"),
			},
		},
		{
			// Verify that DirectLoadWithShimVerify fails if there are no shim binaries in the boot chain.
			desc:    "MissingShimVendorCertSection",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mock.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.1"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
								},
							},
						},
					},
				},
			},
			err: "cannot process OS load event for testdata/mock.efi.signed.1: cannot compute load verification event: shim specified as " +
				"event source without a shim executable appearing in preceding events",
		},
		{
			// Test that shim binaries without a vendor cert work correctly
			desc:    "NoShimVendorCert",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.1"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
								},
							},
						},
					},
				},
			},
			digests: tpm2.DigestList{decodeHexString(t, "e80130f2d8212d6969f0cd20effc3bbded14584861f8f560fbc5208a8bfc0681")},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. The
			// normal and recovery chains have different trust paths
			desc:    "MismatchedNormalAndRecoverySystemsUC20",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim2.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.1"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
								},
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.2"),
									Next: []*EFIImageLoadEvent{
										{
											Source: Shim,
											Image:  FileEFIImage("testdata/mock.efi.signed.2"),
										},
									},
								},
							},
						},
					},
				},
			},
			digests: tpm2.DigestList{
				decodeHexString(t, "e80130f2d8212d6969f0cd20effc3bbded14584861f8f560fbc5208a8bfc0681"),
				decodeHexString(t, "a64025484424ba7a64dc1154889eb8fe78d7b204fa581ace55522c074050e428"),
			},
		},
		{
			// Test that a single dbx update produces 2 digests
			desc:    "DbxUpdate",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim2.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.1"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
								},
							},
						},
					},
				},
			},
			signatureDbUpdateKeystores: []string{"testdata/updates"},
			digests: tpm2.DigestList{
				decodeHexString(t, "e80130f2d8212d6969f0cd20effc3bbded14584861f8f560fbc5208a8bfc0681"),
				decodeHexString(t, "38ae1e75ea7237983f4d44c3695e08a1d7b60d8cbac3c65e576473b72777616e"),
			},
		},
		{
			// Test that a db anx dbx update produces 3 digests (a before and after digest, plus an intermediate one in case the device dies
			// in between updates. Each update is written atomically, but there isn't atomicity between updates, so the 3 digests takes care
			// of this)
			desc:    "DbAndDbxUpdate",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim2.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.1"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
								},
							},
						},
					},
				},
			},
			signatureDbUpdateKeystores: []string{"testdata/updates3"},
			digests: tpm2.DigestList{
				decodeHexString(t, "e80130f2d8212d6969f0cd20effc3bbded14584861f8f560fbc5208a8bfc0681"),
				decodeHexString(t, "38ae1e75ea7237983f4d44c3695e08a1d7b60d8cbac3c65e576473b72777616e"),
				decodeHexString(t, "3d612a0eda6deb41982b81d4c24695cf721e00233b40489af5918dae865320ac"),
			},
		},
		{
			// Test with a UC20 style bootchain with normal and recovery systems, and the normal path booting via a chainloaded GRUB. Two
			// kernels are supplied for both normal and recovery paths signed with alternate keys to simulate what would happen when upgrading
			// to a kernel signed with a new key. The updated kernel depends on a new signature, also provided as a signature database update.
			// Verify that we get 3 digests (the new kernels are only bootable after applying the signature database update)
			desc:    "DbUpdateAndKeyRotation",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.1"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
								},
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.2"),
								},
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
									Next: []*EFIImageLoadEvent{
										{
											Source: Shim,
											Image:  FileEFIImage("testdata/mock.efi.signed.1"),
										},
										{
											Source: Shim,
											Image:  FileEFIImage("testdata/mock.efi.signed.2"),
										},
									},
								},
							},
						},
					},
				},
			},
			signatureDbUpdateKeystores: []string{"testdata/updates1"},
			digests: tpm2.DigestList{
				decodeHexString(t, "e80130f2d8212d6969f0cd20effc3bbded14584861f8f560fbc5208a8bfc0681"),
				decodeHexString(t, "bed6e96b835c1e2bb3c7ea930f9ec728f05eeeb5622e99b8f12fafe6df93039f"),
				decodeHexString(t, "46387dc7040c29ec3ac57b5e616f5ede478a9f735fec08311e6f0b78e53ddb66"),
			},
		},
		{
			// Test that computation fails with an error even if there are some bootable paths, if there are no bootable paths with the
			// initial (pre-update) signature database.
			desc:    "DbUpdateWithNoInitialBootablePaths",
			logPath: "testdata/eventlog1.bin",
			efivars: "testdata/efivars1",
			loadSequences: []*EFIImageLoadEvent{
				{
					Source: Firmware,
					Image:  FileEFIImage("testdata/mockshim.efi.signed.1"),
					Next: []*EFIImageLoadEvent{
						{
							Source: Shim,
							Image:  FileEFIImage("testdata/mock.efi.signed.1"),
							Next: []*EFIImageLoadEvent{
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.2"),
								},
								{
									Source: Shim,
									Image:  FileEFIImage("testdata/mock.efi.signed.1"),
									Next: []*EFIImageLoadEvent{
										{
											Source: Shim,
											Image:  FileEFIImage("testdata/mock.efi.signed.2"),
										},
									},
								},
							},
						},
					},
				},
			},
			signatureDbUpdateKeystores: []string{"testdata/updates1"},
			err: "no bootable paths with current EFI signature database",
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			restoreEventLogPath := MockEventLogPath(data.logPath)
			defer restoreEventLogPath()
			restoreEfivarsPath := MockEfivarsPath(data.efivars)
			defer restoreEfivarsPath()

			digests, err := ComputeSecureBootPolicyDigests(tpm2.HashAlgorithmSHA256, NewSecureBootProtectionParams(data.loadSequences, data.signatureDbUpdateKeystores))
			if data.err != "" {
				if err == nil {
					t.Fatalf("Expected ComputeSecureBootPolicyDigests to fail")
				}
				if err.Error() != data.err {
					t.Errorf("Unexpected error: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("ComputeSecureBootPolicyDigests failed: %v", err)
				}

				if len(digests) != len(data.digests) {
					t.Fatalf("Unexpected number of digests")
				}
				for i, digest := range digests {
					if !bytes.Equal(digest, data.digests[i]) {
						t.Errorf("Unexpected digest (got %x, expected %x)", digest, data.digests[i])
					}
				}
			}
		})
	}
}
