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
	"crypto/x509"

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

func (s *profileSuite) TestWithAutoPCRProfileDefault(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultDiscreteTPM(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4, 2, 0})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4, 2, 0})
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultDiscreteTPMNoResetMitigation(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected | StartupLocalityNotProtected,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultCATrustedForBootCode(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert2023)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 2})
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultCATrustedForDrivers(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustDrivers},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert2023)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4})
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultCATrustedForDriversAndBootCode(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode | AuthorityTrustDrivers},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert2023)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7})
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultCATrustedForDriversAndBootCodeDiscreteTPM(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode | AuthorityTrustDrivers},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert2023)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 0})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 0})
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultUnrecognizedCA(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2023, 0},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultNoBootManagerCodeSupport(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerCodeProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: one or more CAs used for secure boot verification are not trusted to authenticate boot code and the PCRProfileOptionTrustCAsForBootCode option was not supplied, so PCR 4 is required, but PCR 4 failed earlier checks`)

	_, err := profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: one or more CAs used for secure boot verification are not trusted to authenticate boot code and the PCRProfileOptionTrustCAsForBootCode option was not supplied, so PCR 4 is required, but PCR 4 failed earlier checks`)
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultNoDriversAndAppsSupport(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: one or more CAs used for secure boot verification are not trusted to authenticate value-added-retailer supplied drivers and the PCRProfileOptionTrustCAsForVARSuppliedDrivers option was not supplied, so PCR 2 is required, but PCR 2 failed earlier checks`)

	_, err := profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: one or more CAs used for secure boot verification are not trusted to authenticate value-added-retailer supplied drivers and the PCRProfileOptionTrustCAsForVARSuppliedDrivers option was not supplied, so PCR 2 is required, but PCR 2 failed earlier checks`)
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultNoSecureBootPolicyProfileSupport(c *C) {
	// This is an error for now, but will work in the future when we've added
	// support for the missing PCRs.
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCR 7 failed earlier checks making PCRs 1, 2, 3, 4 and 5 mandatory, but one or more of these failed earlier checks`)

	_, err := profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCR 7 failed earlier checks making PCRs 1, 2, 3, 4 and 5 mandatory, but one or more of these failed earlier checks`)
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultNoSecureBootPolicyProfileSupport2(c *C) {
	// This is an error for now, but will work in the future when we've added
	// support for the missing PCRs.
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoSecureBootPolicyProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: configurations without PCR 7 are currently unsupported`)

	_, err := profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: configurations without PCR 7 are currently unsupported`)
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultDiscreteTPMNoPlatformFirmwareProfileSupport(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformFirmwareProfileSupport | NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: it was decided to enable a discrete TPM reset attack mitigation and the PCRProfileOptionNoDiscreteTPMResetMitigation option was not supplied, so PCR 0 is required, but PCR 0 failed earlier checks`)

	_, err := profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: it was decided to enable a discrete TPM reset attack mitigation and the PCRProfileOptionNoDiscreteTPMResetMitigation option was not supplied, so PCR 0 is required, but PCR 0 failed earlier checks`)
}
func (s *profileSuite) TestWithAutoPCRProfileMostSecure(c *C) {
	// This is an error for now, but will work in the future when we've added
	// support for the missing PCRs.
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionMostSecure)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionMostSecure does not work because of one or more of PCRs 0, 1, 2, 3, 4, 5 or 7 failed earlier checks`)

	_, err := profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionMostSecure does not work because of one or more of PCRs 0, 1, 2, 3, 4, 5 or 7 failed earlier checks`)
}

func (s *profileSuite) TestWithAutoPCRProfileMostSecure2(c *C) {
	// This is an error for now, but will work in the future when we've added
	// support for the missing PCRs.
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionMostSecure)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionMostSecure is currently unsupported`)

	_, err := profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionMostSecure is currently unsupported`)
}

func (s *profileSuite) TestWithAutoPCRProfileMostSecureWithOtherOptions(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionMostSecure|PCRProfileOptionNoDiscreteTPMResetMitigation)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionMostSecure can only be used on its own`)

	_, err := profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: PCRProfileOptionMostSecure can only be used on its own`)
}

func (s *profileSuite) TestWithAutoPCRProfileTrustCAsForBootCode(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionTrustCAsForBootCode)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 2})
}

func (s *profileSuite) TestWithAutoPCRProfileTrustCAsForVARSuppliedDrivers(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionTrustCAsForVARSuppliedDrivers)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4})
}

func (s *profileSuite) TestWithAutoPCRProfileTrustCAsForVARSuppliedDriversAndBootCode(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionTrustCAsForBootCode|PCRProfileOptionTrustCAsForVARSuppliedDrivers)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7})
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultDistrustVARSuppliedNonHostCode(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode | AuthorityTrustDrivers},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert2023)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionDistrustVARSuppliedNonHostCode)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 2})
}

func (s *profileSuite) TestWithAutoPCRProfileDefaultDistrustVARSuppliedNonHostCodeNoDriversAndAppsProfileSupport(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode | AuthorityTrustDrivers},
	})
	defer restore()

	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert2023)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionDistrustVARSuppliedNonHostCode)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: options include PCRProfileOptionDistrustVARSuppliedNonHostCode, so PCR 2 is required, but PCR2 failed earlier checks`)

	_, err := profile.PCRs()
	c.Check(err, ErrorMatches, `cannot select an appropriate set of TCG defined PCRs with the current options: options include PCRProfileOptionDistrustVARSuppliedNonHostCode, so PCR 2 is required, but PCR2 failed earlier checks`)
}
func (s *profileSuite) TestWithAutoPCRProfileNoDiscreteTPMMitigation(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | DiscreteTPMDetected,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionNoDiscreteTPMResetMitigation)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7, 4, 2})
}

func (s *profileSuite) TestWithAutoPCRProfileOptions(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*x509.Certificate{testutil.ParseCertificate(c, msUefiCACert)},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	profile := WithAutoPCRProfile(result, PCRProfileOptionsDefault)

	profile = profile.Options(PCRProfileOptionTrustCAsForBootCode | PCRProfileOptionTrustCAsForVARSuppliedDrivers)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{7})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{7})

	expectedProfile := WithAutoPCRProfile(result, PCRProfileOptionTrustCAsForBootCode|PCRProfileOptionTrustCAsForVARSuppliedDrivers)
	c.Check(profile, DeepEquals, expectedProfile)
}
