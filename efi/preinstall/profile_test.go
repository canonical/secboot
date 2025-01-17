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
	"errors"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type profileSuite struct{}

var _ = Suite(&profileSuite{})

type mockPcrProfileOptionVisitor struct {
	pcrs tpm2.HandleList
}

func (v *mockPcrProfileOptionVisitor) AddPCRs(pcrs ...tpm2.Handle) {
	v.pcrs = append(v.pcrs, pcrs...)
}

func (*mockPcrProfileOptionVisitor) SetEnvironment(env internal_efi.HostEnvironmentEFI) {
	panic("not reached")
}

func (*mockPcrProfileOptionVisitor) AddInitialVariablesModifier(fn internal_efi.InitialVariablesModifier) {
	panic("not reached")
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefault(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultDiscreteTPM(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4, 2, 0})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4, 2, 0})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultDiscreteTPMNoResetMitigation(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected | StartupLocalityNotProtected,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultCATrustedForBootCode(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert2023))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 2})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultCATrustedForDrivers(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustDrivers},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert2023))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultCATrustedForDriversAndBootCode(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode | AuthorityTrustDrivers},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert2023))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultCATrustedForDriversAndBootCodeDiscreteTPM(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode | AuthorityTrustDrivers},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert2023))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 0})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 0})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultUnrecognizedCA(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2023, 0},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultNoBootManagerCodeSupport(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerCodeProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	err := profile.ApplyOptionTo(visitor)
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: cannot create a valid secure boot configuration: one or more CAs used for secure boot verification are not trusted to authenticate boot code and the PCRProfileOptionTrustCAsForBootCode option was not supplied: PCR 0x00000004 is required, but is unsupported`)
	var err2 *UnsupportedRequiredPCRsError
	c.Check(errors.As(err, &err2), testutil.IsTrue)

	_, err = profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: cannot create a valid secure boot configuration: one or more CAs used for secure boot verification are not trusted to authenticate boot code and the PCRProfileOptionTrustCAsForBootCode option was not supplied: PCR 0x00000004 is required, but is unsupported`)
	c.Check(errors.As(err, &err2), testutil.IsTrue)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultNoDriversAndAppsSupport(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	err := profile.ApplyOptionTo(visitor)
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: cannot create a valid secure boot configuration: one or more CAs used for secure boot verification are not trusted to authenticate value-added-retailer suppled drivers and the PCRProfileOptionTrustCAsForVARSuppliedDrivers option was not supplied: PCR 0x00000002 is required, but is unsupported`)
	var err2 *UnsupportedRequiredPCRsError
	c.Check(errors.As(err, &err2), testutil.IsTrue)

	_, err = profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: cannot create a valid secure boot configuration: one or more CAs used for secure boot verification are not trusted to authenticate value-added-retailer suppled drivers and the PCRProfileOptionTrustCAsForVARSuppliedDrivers option was not supplied: PCR 0x00000002 is required, but is unsupported`)
	c.Check(errors.As(err, &err2), testutil.IsTrue)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultNoSecureBootPolicyProfileSupport(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	err := profile.ApplyOptionTo(visitor)
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: cannot create a valid configuration without secure boot policy and the PCRProfileOptionPermitNoSecureBootPolicyProfile option was not supplied: PCR 0x00000007 is required, but is unsupported`)
	var err2 *UnsupportedRequiredPCRsError
	c.Check(errors.As(err, &err2), testutil.IsTrue)

	_, err = profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: cannot create a valid configuration without secure boot policy and the PCRProfileOptionPermitNoSecureBootPolicyProfile option was not supplied: PCR 0x00000007 is required, but is unsupported`)
	c.Check(errors.As(err, &err2), testutil.IsTrue)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultDiscreteTPMNoPlatformFirmwareProfileSupport(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformFirmwareProfileSupport | NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	err := profile.ApplyOptionTo(visitor)
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: cannot enable a discrete TPM reset attack mitigation and the PCRProfileOptionNoDiscreteTPMResetMitigation was not supplied: PCR 0x00000000 is required, but is unsupported`)
	var err2 *UnsupportedRequiredPCRsError
	c.Check(errors.As(err, &err2), testutil.IsTrue)

	_, err = profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: cannot enable a discrete TPM reset attack mitigation and the PCRProfileOptionNoDiscreteTPMResetMitigation was not supplied: PCR 0x00000000 is required, but is unsupported`)
	c.Check(errors.As(err, &err2), testutil.IsTrue)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileMostSecure(c *C) {
	// This is an error for now, but will work in the future when we've added
	// support for the missing PCRs.
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionMostSecure)

	visitor := new(mockPcrProfileOptionVisitor)
	err := profile.ApplyOptionTo(visitor)
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionMostSecure cannot be used: PCRs \[0x00000001 0x00000003 0x00000005 0x00000007\] are required, but are unsupported`)
	var err2 *UnsupportedRequiredPCRsError
	c.Check(errors.As(err, &err2), testutil.IsTrue)

	_, err = profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionMostSecure cannot be used: PCRs \[0x00000001 0x00000003 0x00000005 0x00000007\] are required, but are unsupported`)
	c.Check(errors.As(err, &err2), testutil.IsTrue)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileMostSecure2(c *C) {
	// This is an error for now, but will work in the future when we've added
	// support for the missing PCRs.
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionMostSecure)

	visitor := new(mockPcrProfileOptionVisitor)
	err := profile.ApplyOptionTo(visitor)
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionMostSecure cannot be used because it is currently unsupported: PCRs \[0x00000001 0x00000003 0x00000005\] are required, but are unsupported`)
	var err2 *UnsupportedRequiredPCRsError
	c.Check(errors.As(err, &err2), testutil.IsTrue)

	_, err = profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionMostSecure cannot be used because it is currently unsupported: PCRs \[0x00000001 0x00000003 0x00000005\] are required, but are unsupported`)
	c.Check(errors.As(err, &err2), testutil.IsTrue)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultNoSecureBootPolicyProfileSupportOptIn(c *C) {
	// This is an error for now, but will work in the future when we've added
	// support for the missing PCRs.
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionPermitNoSecureBootPolicyProfile)

	visitor := new(mockPcrProfileOptionVisitor)
	err := profile.ApplyOptionTo(visitor)
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: cannot create a valid configuration without secure boot policy: PCRs \[0x00000001 0x00000003 0x00000005\] are required, but are unsupported`)
	var err2 *UnsupportedRequiredPCRsError
	c.Check(errors.As(err, &err2), testutil.IsTrue)

	_, err = profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: cannot create a valid configuration without secure boot policy: PCRs \[0x00000001 0x00000003 0x00000005\] are required, but are unsupported`)
	c.Check(errors.As(err, &err2), testutil.IsTrue)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultNoSecureBootPolicyProfileSupportOptIn2(c *C) {
	// This is an error for now, but will work in the future when we've added
	// support for the missing PCRs.
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoSecureBootPolicyProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionPermitNoSecureBootPolicyProfile)

	visitor := new(mockPcrProfileOptionVisitor)
	err := profile.ApplyOptionTo(visitor)
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: cannot create a configuration without secure boot policy because this is currently unsupported: PCRs \[0x00000001 0x00000003 0x00000005\] are required, but are unsupported`)
	var err2 *UnsupportedRequiredPCRsError
	c.Check(errors.As(err, &err2), testutil.IsTrue)

	_, err = profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: cannot create a configuration without secure boot policy because this is currently unsupported: PCRs \[0x00000001 0x00000003 0x00000005\] are required, but are unsupported`)
	c.Check(errors.As(err, &err2), testutil.IsTrue)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileMostSecureWithOtherOptions(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionMostSecure|PCRProfileOptionNoDiscreteTPMResetMitigation)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionMostSecure can only be used on its own`)

	_, err := profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionMostSecure can only be used on its own`)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileTrustCAsForBootCode(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionTrustCAsForBootCode)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 2})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileTrustCAsForVARSuppliedDrivers(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionTrustCAsForVARSuppliedDrivers)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileTrustCAsForVARSuppliedDriversAndBootCode(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionTrustCAsForBootCode|PCRProfileOptionTrustCAsForVARSuppliedDrivers)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultDistrustVARSuppliedNonHostCode(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode | AuthorityTrustDrivers},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert2023))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionDistrustVARSuppliedNonHostCode)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 2})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileDefaultDistrustVARSuppliedNonHostCodeNoDriversAndAppsProfileSupport(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode | AuthorityTrustDrivers},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert2023))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionDistrustVARSuppliedNonHostCode)

	visitor := new(mockPcrProfileOptionVisitor)
	err := profile.ApplyOptionTo(visitor)
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionDistrustVARSuppliedNonHostCode cannot be used: PCR 0x00000002 is required, but is unsupported`)
	var err2 *UnsupportedRequiredPCRsError
	c.Check(errors.As(err, &err2), testutil.IsTrue)

	_, err = profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionDistrustVARSuppliedNonHostCode cannot be used: PCR 0x00000002 is required, but is unsupported`)
	c.Check(errors.As(err, &err2), testutil.IsTrue)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileNoDiscreteTPMMitigation(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionNoDiscreteTPMResetMitigation)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileOptions(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	profile = profile.Options(PCRProfileOptionTrustCAsForBootCode | PCRProfileOptionTrustCAsForVARSuppliedDrivers)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7})

	expectedProfile := WithAutoTCGPCRProfile(result, PCRProfileOptionTrustCAsForBootCode|PCRProfileOptionTrustCAsForVARSuppliedDrivers)
	c.Check(profile, DeepEquals, expectedProfile)
}
