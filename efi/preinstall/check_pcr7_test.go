// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package preinstall_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"io"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	secboot_efi "github.com/snapcore/secboot/efi"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	pe "github.com/snapcore/secboot/internal/pe1.14"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

// TODO: It might be good to move the functionality in efi/vars_test.go to internal/efitest and
// add some extra functionality in order to simplify some of the setup here, but that's for
// another PR.
//
// It will be especially useful if I add an option in a future PR to compare the signature database
// contents in the log with the current signature database contents read from the variables, in the
// scenario when we can be sure they haven't been modified from the OS. The first iteration of this
// code does not compare them yet (with the exception of the SecureBoot variable, which is read only),
// so there's no need to set up a full signature database configuration for each test.

type pcr7Suite struct{}

var _ = Suite(&pcr7Suite{})

type testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams struct {
	env      internal_efi.HostEnvironment
	pcrAlg   tpm2.HashAlgorithmId
	iblImage secboot_efi.Image

	expectedFlags           SecureBootPolicyResultFlags
	expectedUsedAuthorities []*x509.Certificate
}

func (s *pcr7Suite) testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c *C, params *testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams) error {
	var (
		expectedImageReader io.ReaderAt
		expectedPeFile      *pe.File
	)
	restore := MockPeNewFile(func(r io.ReaderAt) (*pe.File, error) {
		c.Check(r, NotNil)
		expectedImageReader = r
		expectedPeFile = new(pe.File)
		return expectedPeFile, nil
	})
	defer restore()

	restore = MockInternalEfiSecureBootSignaturesFromPEFile(func(pefile *pe.File, r io.ReaderAt) ([]*efi.WinCertificateAuthenticode, error) {
		c.Check(pefile, Equals, expectedPeFile)
		c.Check(r, Equals, expectedImageReader)
		c.Assert(r, testutil.ConvertibleTo, &mockImageReader{})
		imageReader := r.(*mockImageReader)
		return imageReader.signatures, nil
	})
	defer restore()

	log, err := params.env.ReadEventLog()
	c.Assert(err, IsNil)

	result, err := CheckSecureBootPolicyMeasurementsAndObtainAuthorities(context.Background(), params.env, log, params.pcrAlg, params.iblImage)
	if err != nil {
		return err
	}
	c.Check(result.Flags, Equals, params.expectedFlags)
	c.Assert(result.UsedAuthorities, HasLen, len(params.expectedUsedAuthorities))
	for i, authority := range result.UsedAuthorities {
		c.Check(authority.Equal(params.expectedUsedAuthorities[i]), testutil.IsTrue)
	}
	return nil
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesGood(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
		expectedFlags: SecureBootPolicyResultFlags(0),
		expectedUsedAuthorities: []*x509.Certificate{
			testutil.ParseCertificate(c, msUefiCACert),
		},
	})
	c.Check(err, IsNil)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesGoodSHA384(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA384}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA384,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
		expectedFlags: SecureBootPolicyResultFlags(0),
		expectedUsedAuthorities: []*x509.Certificate{
			testutil.ParseCertificate(c, msUefiCACert),
		},
	})
	c.Check(err, IsNil)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesGoodWithDriverLaunch(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch: true,
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
		expectedFlags: SecureBootPolicyResultFlags(0),
		expectedUsedAuthorities: []*x509.Certificate{
			testutil.ParseCertificate(c, msUefiCACert),
		},
	})
	c.Check(err, IsNil)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesGoodWithDriverLaunchVerifiedByDigest(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA256,
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
		expectedFlags: SecureBootPreOSVerificationIncludesDigest,
		expectedUsedAuthorities: []*x509.Certificate{
			testutil.ParseCertificate(c, msUefiCACert),
		},
	})
	c.Check(err, IsNil)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesGoodWithDriverLaunchVerifiedByDigestSHA1(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                   []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeDriverLaunch:          true,
				PreOSVerificationUsesDigests: crypto.SHA1,
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
		expectedFlags: SecureBootIncludesWeakAlg | SecureBootPreOSVerificationIncludesDigest,
		expectedUsedAuthorities: []*x509.Certificate{
			testutil.ParseCertificate(c, msUefiCACert),
		},
	})
	c.Check(err, IsNil)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesGoodWithSysPrepLaunch(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:              []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeSysPrepAppLaunch: true,
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
		expectedFlags: SecureBootPolicyResultFlags(0),
		expectedUsedAuthorities: []*x509.Certificate{
			testutil.ParseCertificate(c, msUefiCACert),
		},
	})
	c.Check(err, IsNil)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesGoodWithAbsoluteLaunch(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:                        []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				IncludeOSPresentFirmwareAppLaunch: efi.MakeGUID(0x821aca26, 0x29ea, 0x4993, 0x839f, [...]byte{0x59, 0x7f, 0xc0, 0x21, 0x70, 0x8d}),
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
		expectedFlags: SecureBootPolicyResultFlags(0),
		expectedUsedAuthorities: []*x509.Certificate{
			testutil.ParseCertificate(c, msUefiCACert),
		},
	})
	c.Check(err, IsNil)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesGoodPreUEFI25(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
		expectedFlags: SecureBootPolicyResultFlags(0),
		expectedUsedAuthorities: []*x509.Certificate{
			testutil.ParseCertificate(c, msUefiCACert),
		},
	})
	c.Check(err, IsNil)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadNoSecureBoot(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(false).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, Equals, ErrNoSecureBoot)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadUserMode(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, Equals, ErrNoDeployedMode)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadFWSupportsDBT(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `generating secure boot profiles for systems with timestamp revocation \(dbt\) support is currently not supported`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadFWSupportsDBR(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `generating secure boot profiles for systems with OS recovery support, which requires dbr support, is not supported`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadNoBootCurrent(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `cannot read BootCurrent variable: variable does not exist`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadNoLoadOption(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x4, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `cannot read current Boot0004 load option from log: cannot find specified boot option`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadUnexpectedConfigMeasurement(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	var eventsCopy []*tcglog.Event
	for _, ev := range log.Events {
		eventsCopy = append(eventsCopy, ev)

		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIVariableDriverConfig {
			continue
		}
		data, ok := ev.Data.(*tcglog.EFIVariableData)
		c.Assert(ok, testutil.IsTrue)
		if data.UnicodeName == "dbx" {
			// Measure dbx twice
			eventsCopy = append(eventsCopy, ev)
		}
	}
	log.Events = eventsCopy

	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `unexpected EV_EFI_VARIABLE_DRIVER_CONFIG event: all expected secure boot variable have been measured`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadConfigEventDataErr(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	for _, ev := range log.Events {
		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIVariableDriverConfig {
			continue
		}
		data, ok := ev.Data.(*tcglog.EFIVariableData)
		c.Assert(ok, testutil.IsTrue)
		if data.UnicodeName == "dbx" {
			ev.Data = &invalidEventData{errors.New("some error")}
		}
	}

	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `invalid event data for EV_EFI_VARIABLE_DRIVER_CONFIG event: some error`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadInvalidConfigMeasurementOrder(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	var eventsCopy []*tcglog.Event
	for _, ev := range log.Events {
		eventsCopy = append(eventsCopy, ev)

		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIVariableDriverConfig {
			continue
		}
		data, ok := ev.Data.(*tcglog.EFIVariableData)
		c.Assert(ok, testutil.IsTrue)
		if data.UnicodeName == "dbx" {
			// Swap db and dbx measurements
			dbx := eventsCopy[len(eventsCopy)-1]
			eventsCopy[len(eventsCopy)-1] = eventsCopy[len(eventsCopy)-2]
			eventsCopy[len(eventsCopy)-2] = dbx
		}
	}
	log.Events = eventsCopy

	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `unexpected EV_EFI_VARIABLE_DRIVER_CONFIG event ordering \(expected db-d719b2cb-3d3a-4596-a3bc-dad00e67656f, got dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f\)`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadConfigDigestWrong(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	for _, ev := range log.Events {
		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIVariableDriverConfig {
			continue
		}
		data, ok := ev.Data.(*tcglog.EFIVariableData)
		c.Assert(ok, testutil.IsTrue)
		if data.UnicodeName == "dbx" {
			ev.Digests[tpm2.HashAlgorithmSHA256] = testutil.DecodeHexString(c, "8c8d89cdf0f2de4a1e97d436d7f6a19c49ab55d33bdb81c27470d4140b3de220")
		}
	}

	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `event data inconsistent with measured digest for EV_EFI_VARIABLE_DRIVER_CONFIG event \(name:\"dbx\", GUID:d719b2cb-3d3a-4596-a3bc-dad00e67656f, expected digest:0x1963d580fcc0cede165e23837b55335eebe18750c0b795883386026ea071e3c6, measured digest:0x8c8d89cdf0f2de4a1e97d436d7f6a19c49ab55d33bdb81c27470d4140b3de220\)`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadInvalidSecureBootValueInLog(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	for _, ev := range log.Events {
		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIVariableDriverConfig {
			continue
		}
		data, ok := ev.Data.(*tcglog.EFIVariableData)
		c.Assert(ok, testutil.IsTrue)
		if data.UnicodeName == "SecureBoot" {
			data.VariableData = []byte{0}
			ev.Digests[tpm2.HashAlgorithmSHA256] = testutil.DecodeHexString(c, "115aa827dbccfb44d216ad9ecfda56bdea620b860a94bed5b7a27bba1c4d02d8")
		}
	}

	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `SecureBoot variable is not consistent with the corresponding EV_EFI_VARIABLE_DRIVER_CONFIG event value in the TCG log`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadUEFIDebuggerPresent(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:       []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				FirmwareDebugger: true,
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `unexpected EV_EFI_ACTION event \"UEFI Debug Mode\" whilst measuring config`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadMissingConfigMeasurement(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	var eventsCopy []*tcglog.Event
	for _, ev := range log.Events {
		eventsCopy = append(eventsCopy, ev)

		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIVariableDriverConfig {
			continue
		}
		data, ok := ev.Data.(*tcglog.EFIVariableData)
		c.Assert(ok, testutil.IsTrue)
		if data.UnicodeName == "dbx" {
			// Delete dbx measurement
			eventsCopy = eventsCopy[:len(eventsCopy)-1]
		}
	}
	log.Events = eventsCopy

	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `EV_EFI_VARIABLE_DRIVER_CONFIG events for some secure boot variables missing from log`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadMissingIBLLaunch(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	var eventsCopy []*tcglog.Event
	seenIBLVerification := false
	for _, ev := range log.Events {
		eventsCopy = append(eventsCopy, ev)

		switch {
		case ev.PCRIndex == internal_efi.BootManagerCodePCR && ev.EventType == tcglog.EventTypeEFIBootServicesApplication:
			// Delete measurement
			eventsCopy = eventsCopy[:len(eventsCopy)-1]
		case ev.PCRIndex == internal_efi.SecureBootPolicyPCR && ev.EventType == tcglog.EventTypeEFIVariableAuthority && !seenIBLVerification:
			seenIBLVerification = true
		case ev.PCRIndex == internal_efi.SecureBootPolicyPCR && ev.EventType == tcglog.EventTypeEFIVariableAuthority && seenIBLVerification:
			// Delete measurement
			eventsCopy = eventsCopy[:len(eventsCopy)-1]
		}
	}
	log.Events = eventsCopy

	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `missing load event for initial boot loader`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadFirstVerifiedOSPresentLoadIsntIBL(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `unexpected EV_EFI_BOOT_SERVICES_APPLICATION event for \\PciRoot\(0x0\)\\Pci\(0x1d,0x0\)\\Pci\(0x0,0x0\)\\NVMe\(0x1,00-00-00-00-00-00-00-00\)\\HD\(1,GPT,66de947b-fdb2-4525-b752-30d66bb2b960\)\\\\EFI\\ubuntu\\shimx64.efi after already seeing a verification event during the OS-present environment. This event should be for the initial boot loader`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadInvalidSourceForFirstOSPresentVerification(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	for _, ev := range log.Events {
		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIVariableAuthority {
			continue
		}
		data, ok := ev.Data.(*tcglog.EFIVariableData)
		c.Assert(ok, testutil.IsTrue)
		data.VariableName = efi.GlobalVariable
		break
	}

	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `EV_EFI_VARIABLE_AUTHORITY event is not from db \(got db-8be4df61-93ca-11d2-aa0d-00e098032b8c\)`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadFirstOSPresentVerificationWrongDigest(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	for _, ev := range log.Events {
		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIVariableAuthority {
			continue
		}
		ev.Digests[tpm2.HashAlgorithmSHA256] = testutil.DecodeHexString(c, "8c8d89cdf0f2de4a1e97d436d7f6a19c49ab55d33bdb81c27470d4140b3de220")
		break
	}

	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `event data inconsistent with TPM_ALG_SHA256 event digest for EV_EFI_VARIABLE_AUTHORITY event \(log digest:0x8c8d89cdf0f2de4a1e97d436d7f6a19c49ab55d33bdb81c27470d4140b3de220, expected digest:0x4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9\)`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadDuplicateVerificationDigests(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{
		Algorithms:          []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		IncludeDriverLaunch: true,
	})
	var (
		eventsCopy        []*tcglog.Event
		verificationEvent *tcglog.Event
		seenIBLLaunch     bool
	)
	for _, ev := range log.Events {
		eventsCopy = append(eventsCopy, ev)

		switch {
		case ev.PCRIndex == internal_efi.SecureBootPolicyPCR && ev.EventType == tcglog.EventTypeEFIVariableAuthority:
			// This should be the only verification event. Save it to put it in the log later on
			verificationEvent = ev
		case ev.PCRIndex == internal_efi.BootManagerCodePCR && ev.EventType == tcglog.EventTypeEFIBootServicesApplication && !seenIBLLaunch:
			seenIBLLaunch = true
			// Copy the previous verification event before this event
			eventsCopy = append(eventsCopy, ev)
			eventsCopy[len(eventsCopy)-2] = verificationEvent
		}
	}
	log.Events = eventsCopy

	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `EV_EFI_VARIABLE_AUTHORITY digest 0x4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9 has been measured by the firmware more than once`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadInvalidIBLLoadEventData(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	for _, ev := range log.Events {
		if ev.PCRIndex != internal_efi.BootManagerCodePCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIBootServicesApplication {
			continue
		}
		ev.Data = &invalidEventData{errors.New("some error")}
		break
	}

	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `invalid OS-present EV_EFI_BOOT_SERVICES_APPLICATION event data: some error`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadInvalidVerificationEventData(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})
	for _, ev := range log.Events {
		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}
		if ev.EventType != tcglog.EventTypeEFIVariableAuthority {
			continue
		}
		ev.Data = &invalidEventData{errors.New("some error")}
		break
	}

	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(log),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `EV_EFI_VARIABLE_AUTHORITY event has wrong data format: some error`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadDMAProtectionDisabled(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{
				Algorithms:            []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
				DMAProtectionDisabled: efitest.DMAProtectionDisabledNullTerminated,
			})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `unexpected EV_EFI_ACTION event \"DMA Protection Disabled\" whilst measuring verification`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadMissingSecureBoot(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `cannot read SecureBoot variable: variable does not exist`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadInvalidSecureBootMode(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `cannot compute secure boot mode: inconsistent secure boot mode: firmware indicates audit mode is enabled when not in setup mode`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadMissingOsIndications(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:         &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:       &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:         &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
		iblImage: &mockImage{
			signatures: []*efi.WinCertificateAuthenticode{
				efitest.ReadWinCertificateAuthenticodeDetached(c, shimUbuntuSig4),
			},
		},
	})
	c.Check(err, ErrorMatches, `cannot read OsIndicationsSupported variable: variable does not exist`)
}

func (s *pcr7Suite) TestCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesBadMissingIBL(c *C) {
	err := s.testCheckSecureBootPolicyMeasurementsAndObtainAuthorities(c, &testCheckSecureBootPolicyMeasurementsAndObtainAuthoritiesParams{
		env: efitest.NewMockHostEnvironmentWithOpts(
			efitest.WithMockVars(efitest.MockVars{
				{Name: "AuditMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "BootCurrent", GUID: efi.GlobalVariable}:            &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x3, 0x0}},
				{Name: "BootOptionSupport", GUID: efi.GlobalVariable}:      &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x13, 0x03, 0x00, 0x00}},
				{Name: "DeployedMode", GUID: efi.GlobalVariable}:           &efitest.VarEntry{Attrs: efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x1}},
				{Name: "SetupMode", GUID: efi.GlobalVariable}:              &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x0}},
				{Name: "OsIndicationsSupported", GUID: efi.GlobalVariable}: &efitest.VarEntry{Attrs: efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, Payload: []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			}.SetSecureBoot(true).SetPK(c, efitest.NewSignatureListX509(c, snakeoilCert, efi.MakeGUID(0x03f66fa4, 0x5eee, 0x479c, 0xa408, [...]uint8{0xc4, 0xdc, 0x0a, 0x33, 0xfc, 0xde})))),
			efitest.WithLog(efitest.NewLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256}})),
		),
		pcrAlg: tpm2.HashAlgorithmSHA256,
	})
	c.Check(err, ErrorMatches, `must supply the initial boot loader image`)
}

// TODO (some harder, and some of these may require a more customizable test log generation in internal/efitest/log.go):
// - Various PK/KEK/db/dbx decoding errors
// - Failure to open initial boot loader image
// - Failure to decode initial boot loader image
// - Initial boot loader has signature that doesn't chain to anything in db
// - Initial boot loader signer does not have a RSA key
// - Initial boot loader signer has a weak RSA key
// - EV_EFI_VARIABLE_AUTHORITY event has ESD that doesn't match any ESL in db
// - EV_EFI_VARIABLE_AUTHORITY event has ESD that contains a non RSA key
// - EV_EFI_VARIABLE_AUTHORITY event has ESD with weak RSA key
// - EV_EFI_VARIABLE_AUTHORITY containing a digest in OS-present
// - EV_EFI_VARIABLE_AUTHORITY event has ESD with unrecognized ESL type
// - Spurious events in PCR7 after measuring config with logs that don't terminate the config with a EV_SEPARATOR
