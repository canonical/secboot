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
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type profileSuite struct{}

var _ = Suite(&profileSuite{})

type mockPcrProfileOptionVisitor struct {
	pcrs            tpm2.HandleList
	imageLoadParams []internal_efi.LoadParams
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

func (v *mockPcrProfileOptionVisitor) AddImageLoadParams(f func(...internal_efi.LoadParams) []internal_efi.LoadParams) {
	v.imageLoadParams = f(v.imageLoadParams...)
}

func (s *profileSuite) TestPCRProfileOptionsFlagsMarshalJSON(c *C) {
	for _, params := range []struct {
		flags    PCRProfileOptionsFlags
		expected string
	}{
		{flags: PCRProfileOptionsDefault, expected: `[]`},
		{flags: PCRProfileOptionLockToPlatformFirmware, expected: `["lock-platform-firmware"]`},
		{flags: PCRProfileOptionLockToPlatformConfig, expected: `["lock-platform-config"]`},
		{flags: PCRProfileOptionLockToDriversAndApps, expected: `["lock-drivers-and-apps"]`},
		{flags: PCRProfileOptionLockToDriversAndAppsConfig, expected: `["lock-drivers-and-apps-config"]`},
		{flags: PCRProfileOptionLockToBootManagerCode, expected: `["lock-boot-manager-code"]`},
		{flags: PCRProfileOptionLockToBootManagerConfig, expected: `["lock-boot-manager-config"]`},
		{flags: PCRProfileOptionTrustSecureBootAuthoritiesForBootCode, expected: `["trust-authorities-for-boot-code"]`},
		{flags: PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers, expected: `["trust-authorities-for-addon-drivers"]`},
		{flags: PCRProfileOptionPermitNoSecureBootPolicyProfile, expected: `["permit-no-secure-boot-policy-profile"]`},
		{flags: PCRProfileOptionNoPartialDiscreteTPMResetAttackMitigation, expected: `["no-partial-dtpm-reset-attack-mitigation"]`},
		{flags: PCRProfileOptionMostSecure, expected: `["lock-platform-firmware","lock-platform-config","lock-drivers-and-apps","lock-drivers-and-apps-config","lock-boot-manager-code","lock-boot-manager-config"]`},
	} {
		data, err := json.Marshal(params.flags)
		c.Check(err, IsNil, Commentf("flags:%v", params.flags))
		c.Check(data, DeepEquals, []byte(params.expected), Commentf("flags:%v", params.flags))
	}
}

func (s *profileSuite) TestPCRProfileOptionsFlagsUnmarshalJSON(c *C) {
	for _, params := range []struct {
		flags    string
		expected PCRProfileOptionsFlags
	}{
		{flags: `[]`, expected: PCRProfileOptionsDefault},
		{flags: `["lock-platform-firmware"]`, expected: PCRProfileOptionLockToPlatformFirmware},
		{flags: `["lock-platform-config"]`, expected: PCRProfileOptionLockToPlatformConfig},
		{flags: `["lock-drivers-and-apps"]`, expected: PCRProfileOptionLockToDriversAndApps},
		{flags: `["lock-drivers-and-apps-config"]`, expected: PCRProfileOptionLockToDriversAndAppsConfig},
		{flags: `["lock-boot-manager-code"]`, expected: PCRProfileOptionLockToBootManagerCode},
		{flags: `["lock-boot-manager-config"]`, expected: PCRProfileOptionLockToBootManagerConfig},
		{flags: `["trust-authorities-for-boot-code"]`, expected: PCRProfileOptionTrustSecureBootAuthoritiesForBootCode},
		{flags: `["trust-authorities-for-addon-drivers"]`, expected: PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers},
		{flags: `["permit-no-secure-boot-policy-profile"]`, expected: PCRProfileOptionPermitNoSecureBootPolicyProfile},
		{flags: `["no-partial-dtpm-reset-attack-mitigation"]`, expected: PCRProfileOptionNoPartialDiscreteTPMResetAttackMitigation},
		{flags: `["lock-platform-firmware","lock-platform-config","lock-drivers-and-apps","lock-drivers-and-apps-config","lock-boot-manager-code","lock-boot-manager-config"]`, expected: PCRProfileOptionMostSecure},
		{flags: `["0x3f"]`, expected: PCRProfileOptionMostSecure},
		{flags: `["256"]`, expected: PCRProfileOptionPermitNoSecureBootPolicyProfile},
	} {
		var flags PCRProfileOptionsFlags
		c.Check(json.Unmarshal([]byte(params.flags), &flags), IsNil, Commentf("flags:%q", params.flags))
		c.Check(flags, Equals, params.expected, Commentf("flags:%q", params.flags))
	}
}

func (s *profileSuite) TestPCRProfileOptionsFlagsUnmarshalJSONInvalidSlice(c *C) {
	var flags PCRProfileOptionsFlags
	c.Check(json.Unmarshal([]byte("foo"), &flags), ErrorMatches, `invalid character 'o' in literal false \(expecting 'a'\)`)
}

func (s *profileSuite) TestPCRProfileOptionsFlagsUnmarshalJSONInvalidFlag(c *C) {
	var flags PCRProfileOptionsFlags
	c.Check(json.Unmarshal([]byte(`["foo"]`), &flags), ErrorMatches, `unrecognized flag "foo"`)
}

func (s *profileSuite) TestPCRProfileOptionsFlagsString(c *C) {
	for _, params := range []struct {
		flags    PCRProfileOptionsFlags
		expected string
	}{
		{flags: PCRProfileOptionsDefault, expected: ""},
		{flags: PCRProfileOptionLockToPlatformFirmware, expected: "lock-platform-firmware"},
		{flags: PCRProfileOptionLockToPlatformConfig, expected: "lock-platform-config"},
		{flags: PCRProfileOptionLockToDriversAndApps, expected: "lock-drivers-and-apps"},
		{flags: PCRProfileOptionLockToDriversAndAppsConfig, expected: "lock-drivers-and-apps-config"},
		{flags: PCRProfileOptionLockToBootManagerCode, expected: "lock-boot-manager-code"},
		{flags: PCRProfileOptionLockToBootManagerConfig, expected: "lock-boot-manager-config"},
		{flags: PCRProfileOptionTrustSecureBootAuthoritiesForBootCode, expected: "trust-authorities-for-boot-code"},
		{flags: PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers, expected: "trust-authorities-for-addon-drivers"},
		{flags: PCRProfileOptionPermitNoSecureBootPolicyProfile, expected: "permit-no-secure-boot-policy-profile"},
		{flags: PCRProfileOptionNoPartialDiscreteTPMResetAttackMitigation, expected: "no-partial-dtpm-reset-attack-mitigation"},
		{flags: PCRProfileOptionMostSecure, expected: "lock-platform-firmware,lock-platform-config,lock-drivers-and-apps,lock-drivers-and-apps-config,lock-boot-manager-code,lock-boot-manager-config"},
	} {
		c.Check(params.flags.String(), Equals, params.expected, Commentf("flags:%#08x", params.flags))
	}
}

type testWithAutoTCGPCRProfilePCRSelectionParams struct {
	usedSecureBootCAs [][]byte
	flags             CheckResultFlags
	opts              PCRProfileOptionsFlags
	expectedPcrs      tpm2.HandleList
}

func (s *profileSuite) testWithAutoTCGPCRProfilePCRSelection(c *C, params *testWithAutoTCGPCRProfilePCRSelectionParams) {
	var usedSecureBootCAs []*X509CertificateID
	for _, cert := range params.usedSecureBootCAs {
		usedSecureBootCAs = append(usedSecureBootCAs, NewX509CertificateID(testutil.ParseCertificate(c, cert)))
	}
	result := &CheckResult{
		UsedSecureBootCAs: usedSecureBootCAs,
		Flags:             params.flags,
	}
	profile := WithAutoTCGPCRProfile(result, params.opts)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, params.expectedPcrs)

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, params.expectedPcrs)
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionDefault(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert},
		expectedPcrs:      tpm2.HandleList{2, 4, 7},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionDefaultUnrecognizedCA(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{})
	defer restore()

	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert},
		expectedPcrs:      tpm2.HandleList{2, 4, 7},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionLockToPlatformFirmare(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert},
		opts:              PCRProfileOptionLockToPlatformFirmware,
		expectedPcrs:      tpm2.HandleList{0, 2, 4, 7},
	})
}

// XXX: Uncomment when secboot_efi.WithPlatformConfigProfile exists.
//func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionLockToPlatformConfig(c *C) {
//	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
//		usedSecureBootCAs: [][]byte{msUefiCACert},
//		opts:              PCRProfileOptionLockToPlatformConfig,
//		expectedPcrs:      tpm2.HandleList{1, 2, 4, 7},
//	})
//}
//
//func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionLockToPlatformFirmareAndConfig(c *C) {
//	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
//		usedSecureBootCAs: [][]byte{msUefiCACert},
//		opts:              PCRProfileOptionLockToPlatformFirmware | PCRProfileOptionLockToPlatformConfig,
//		expectedPcrs:      tpm2.HandleList{0, 1, 2, 4, 7},
//	})
//}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionDefaultCAsTrustedForDrivers(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustDrivers},
	})
	defer restore()

	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert2023},
		expectedPcrs:      tpm2.HandleList{4, 7},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionLockToDriversAndApps(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustDrivers},
	})
	defer restore()

	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert2023},
		opts:              PCRProfileOptionLockToDriversAndApps,
		expectedPcrs:      tpm2.HandleList{2, 4, 7},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionTrustSecureBootAuthoritiesForAddonDrivers(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{})
	defer restore()

	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert},
		opts:              PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers,
		expectedPcrs:      tpm2.HandleList{4, 7},
	})
}

// XXX: Uncomment when secboot_efi.WithDriversAndAppsConfigProfile exists.
//func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionLockToDriversAndAppsConfig(c *C) {
//	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
//		usedSecureBootCAs: [][]byte{msUefiCACert},
//		opts:              PCRProfileOptionLockToDriversAndAppsConfig,
//		expectedPcrs:      tpm2.HandleList{2, 3, 4, 7},
//	})
//}
//
//func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionLockToDriversAndAppsAndConfig(c *C) {
//	restore := MockKnownCAs(AuthorityTrustDataSet{
//		{internal_efi.MSUefiCA2011, 0},
//		{internal_efi.MSUefiCA2023, AuthorityTrustDrivers},
//	})
//	defer restore()
//
//	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
//		usedSecureBootCAs: [][]byte{msUefiCACert2023},
//		opts:              PCRProfileOptionLockToDriversAndApps | PCRProfileOptionLockToDriversAndAppsConfig,
//		expectedPcrs:      tpm2.HandleList{2, 3, 4, 7},
//	})
//}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionDefaultCAsTrustedForBootCode(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode},
	})
	defer restore()

	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert2023},
		expectedPcrs:      tpm2.HandleList{2, 7},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionLockToBootManagerCode(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{
		{internal_efi.MSUefiCA2011, 0},
		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode},
	})
	defer restore()

	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert2023},
		opts:              PCRProfileOptionLockToBootManagerCode,
		expectedPcrs:      tpm2.HandleList{2, 4, 7},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionTrustSecureBootAuthoritiesForBootCode(c *C) {
	restore := MockKnownCAs(AuthorityTrustDataSet{})
	defer restore()

	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert},
		opts:              PCRProfileOptionTrustSecureBootAuthoritiesForBootCode,
		expectedPcrs:      tpm2.HandleList{2, 7},
	})
}

// XXX: Uncomment when secboot_efi.WithBootManagerConfigProfile exists.
//func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionLockToBootManagerConfig(c *C) {
//	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
//		usedSecureBootCAs: [][]byte{msUefiCACert},
//		opts:              PCRProfileOptionLockToBootManagerConfig,
//		expectedPcrs:      tpm2.HandleList{2, 4, 5, 7},
//	})
//}
//
//func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionLockToBootManagerCodeAndConfig(c *C) {
//	restore := MockKnownCAs(AuthorityTrustDataSet{
//		{internal_efi.MSUefiCA2011, 0},
//		{internal_efi.MSUefiCA2023, AuthorityTrustBootCode},
//	})
//	defer restore()
//
//	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
//		usedSecureBootCAs: [][]byte{msUefiCACert2023},
//		opts:              PCRProfileOptionLockToBootManagerCode | PCRProfileOptionLockToBootManagerConfig,
//		expectedPcrs:      tpm2.HandleList{2, 4, 5, 7},
//	})
//}

// XXX: Uncomment when secboot_efi.WithPlatformConfigProfile, secboot_efi.WithDriversAndAppsConfigProfile
// and secboot_efi.WithBootManagerConfigProfile exist.
//func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionMostSecure(c *C) {
//	restore := MockKnownCAs(AuthorityTrustDataSet{
//		{internal_efi.MSUefiCA2011, 0},
//		{internal_efi.MSUefiCA2023, AuthorityTrustDriver | AuthorityTrustBootCode},
//	})
//	defer restore()
//
//	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
//		usedSecureBootCAs: [][]byte{msUefiCACert2023},
//		opts:              PCRProfileOptionsMostSecure,
//		expectedPcrs:      tpm2.HandleList{0, 1, 2, 3, 4, 5, 7},
//	})
//}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionPermitNoSecureBootPolicyProfile(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert},
		opts:              PCRProfileOptionPermitNoSecureBootPolicyProfile,
		expectedPcrs:      tpm2.HandleList{2, 4, 7},
	})
}

// XXX: Uncomment when secboot_efi.WithPlatformConfigProfile, secboot_efi.WithDriversAndAppsConfigProfile
// and secboot_efi.WithBootManagerConfigProfile exist.
//func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionNoSecureBootPolicyProfileSupportedButPermitted(c *C) {
//	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
//		usedSecureBootCAs: [][]byte{msUefiCACert},
//		flags:             NoSecureBootPolicyProfileSupport,
//		opts:              PCRProfileOptionPermitNoSecureBootPolicyProfile,
//		expectedPcrs:      tpm2.HandleList{2, 4, 7},
//	})
//}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionWithPartialDTPMResetAttackMitigation(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert},
		flags:             RequestPartialDiscreteTPMResetAttackMitigation,
		expectedPcrs:      tpm2.HandleList{0, 2, 4, 7},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionNoPartialDTPMResetAttackMitigation(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelection(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert},
		flags:             RequestPartialDiscreteTPMResetAttackMitigation,
		opts:              PCRProfileOptionNoPartialDiscreteTPMResetAttackMitigation,
		expectedPcrs:      tpm2.HandleList{2, 4, 7},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileLockToDriversAndAppsIncompatibleWithTrustSecureBootAuthoritiesForAddonDrivers(c *C) {
	profile := WithAutoTCGPCRProfile(new(CheckResult), PCRProfileOptionLockToDriversAndApps|PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers)
	c.Check(profile.ApplyOptionTo(new(mockPcrProfileOptionVisitor)), ErrorMatches,
		`cannot select an appropriate set of TCG defined PCRs with the current options: "trust-authorities-for-addon-drivers" option is incompatible with "lock-drivers-and-apps" option`)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileTrustSecureBootAuthoritiesForAddonDriversFailsForExplicitlyDistrusted(c *C) {
	result := &CheckResult{
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionTrustSecureBootAuthoritiesForAddonDrivers)
	c.Check(profile.ApplyOptionTo(new(mockPcrProfileOptionVisitor)), ErrorMatches,
		`cannot select an appropriate set of TCG defined PCRs with the current options: "trust-authorities-for-addon-drivers" option cannot be used when secure boot CAs that are explicitly distrusted for authenticating addon drivers are active`)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileLockToBootManagerCodeIncompatibleWithTrustSecureBootAuthoritiesForBootCode(c *C) {
	profile := WithAutoTCGPCRProfile(new(CheckResult), PCRProfileOptionLockToBootManagerCode|PCRProfileOptionTrustSecureBootAuthoritiesForBootCode)
	c.Check(profile.ApplyOptionTo(new(mockPcrProfileOptionVisitor)), ErrorMatches,
		`cannot select an appropriate set of TCG defined PCRs with the current options: "trust-authorities-for-boot-code" option is incompatible with "lock-boot-manager-code" option`)
}

func (s *profileSuite) TestWithAutoTCGPCRProfileTrustSecureBootAuthoritiesForBootCodeFailsForExplicitlyDistrusted(c *C) {
	result := &CheckResult{
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionTrustSecureBootAuthoritiesForBootCode)
	c.Check(profile.ApplyOptionTo(new(mockPcrProfileOptionVisitor)), ErrorMatches,
		`cannot select an appropriate set of TCG defined PCRs with the current options: "trust-authorities-for-boot-code" option cannot be used when secure boot CAs that are explicitly distrusted for authenticating boot code are active`)
}

func (s *profileSuite) testWithAutoTCGPCRProfilePCRSelectionUnsupported(c *C, params *testWithAutoTCGPCRProfilePCRSelectionParams) {
	var usedSecureBootCAs []*X509CertificateID
	for _, cert := range params.usedSecureBootCAs {
		usedSecureBootCAs = append(usedSecureBootCAs, NewX509CertificateID(testutil.ParseCertificate(c, cert)))
	}
	result := &CheckResult{
		UsedSecureBootCAs: usedSecureBootCAs,
		Flags:             params.flags,
	}
	profile := WithAutoTCGPCRProfile(result, params.opts)

	var expectedErr string
	switch len(params.expectedPcrs) {
	case 1:
		expectedErr = fmt.Sprintf("PCR %v is required, but is unsupported", params.expectedPcrs[0])
	default:
		expectedErr = fmt.Sprintf("PCRs %v are required, but are unsupported", params.expectedPcrs)
	}

	err := profile.ApplyOptionTo(new(mockPcrProfileOptionVisitor))
	c.Check(err, ErrorMatches, fmt.Sprintf("cannot select an appropriate set of TCG defined PCRs with the current options: %s", regexp.QuoteMeta(expectedErr)))

	var e *UnsupportedRequiredPCRsError
	c.Assert(errors.As(err, &e), testutil.IsTrue)
	c.Check(e.PCRs, DeepEquals, params.expectedPcrs)
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionPlatformFirmwareProfileUnsupported(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelectionUnsupported(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		flags:             NoPlatformFirmwareProfileSupport | RequestPartialDiscreteTPMResetAttackMitigation,
		usedSecureBootCAs: [][]byte{msUefiCACert},
		expectedPcrs:      tpm2.HandleList{0},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionPlatformConfigProfileUnsupported(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelectionUnsupported(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		flags:             NoPlatformConfigProfileSupport,
		usedSecureBootCAs: [][]byte{msUefiCACert},
		opts:              PCRProfileOptionLockToPlatformConfig,
		expectedPcrs:      tpm2.HandleList{1},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionDriversAndAppsProfileUnsupported(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelectionUnsupported(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		flags:             NoDriversAndAppsProfileSupport,
		usedSecureBootCAs: [][]byte{msUefiCACert},
		expectedPcrs:      tpm2.HandleList{2},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionDriversAndAppsConfigProfileUnsupported(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelectionUnsupported(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		flags:             NoDriversAndAppsConfigProfileSupport,
		usedSecureBootCAs: [][]byte{msUefiCACert},
		opts:              PCRProfileOptionLockToDriversAndAppsConfig,
		expectedPcrs:      tpm2.HandleList{3},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionBootManagerCodeProfileUnsupported(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelectionUnsupported(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		flags:             NoBootManagerCodeProfileSupport,
		usedSecureBootCAs: [][]byte{msUefiCACert},
		expectedPcrs:      tpm2.HandleList{4},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionSecureBootPolicyProfileUnsupported(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelectionUnsupported(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		flags:             NoSecureBootPolicyProfileSupport,
		usedSecureBootCAs: [][]byte{msUefiCACert},
		expectedPcrs:      tpm2.HandleList{7},
	})
}

// Error cases for temporarily unsupported options.

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionLockToPlatformConfigUnsupported(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelectionUnsupported(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert},
		opts:              PCRProfileOptionLockToPlatformConfig,
		expectedPcrs:      tpm2.HandleList{1},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionLockToDriversAndAppsConfigUnsupported(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelectionUnsupported(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert},
		opts:              PCRProfileOptionLockToDriversAndAppsConfig,
		expectedPcrs:      tpm2.HandleList{3},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionLockToBootManagerConfigUnsupported(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelectionUnsupported(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert},
		opts:              PCRProfileOptionLockToBootManagerConfig,
		expectedPcrs:      tpm2.HandleList{5},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfilePCRSelectionPermitNoSecureBootPolicyProfileUnsupported(c *C) {
	s.testWithAutoTCGPCRProfilePCRSelectionUnsupported(c, &testWithAutoTCGPCRProfilePCRSelectionParams{
		usedSecureBootCAs: [][]byte{msUefiCACert},
		flags:             NoSecureBootPolicyProfileSupport,
		opts:              PCRProfileOptionPermitNoSecureBootPolicyProfile,
		expectedPcrs:      tpm2.HandleList{1, 3, 5},
	})
}

func (s *profileSuite) TestWithAutoTCGPCRProfileOptions(c *C) {
	result := &CheckResult{
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	profile = profile.Options(PCRProfileOptionLockToPlatformFirmware)

	visitor := new(mockPcrProfileOptionVisitor)
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.pcrs, DeepEquals, tpm2.HandleList{0, 2, 4, 7})

	pcrs, err := profile.PCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.HandleList{0, 2, 4, 7})

	expectedProfile := WithAutoTCGPCRProfile(result, PCRProfileOptionLockToPlatformFirmware)
	c.Check(profile, DeepEquals, expectedProfile)
}

func (s *profileSuite) TestWithAutoTCGPCRInsufficientDMAProtection(c *C) {
	result := &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             InsufficientDMAProtectionDetected,
	}
	profile := WithAutoTCGPCRProfile(result, PCRProfileOptionsDefault)

	profile = profile.Options(PCRProfileOptionsDefault)

	visitor := &mockPcrProfileOptionVisitor{
		imageLoadParams: []internal_efi.LoadParams{{}},
	}
	c.Check(profile.ApplyOptionTo(visitor), IsNil)
	c.Check(visitor.imageLoadParams, DeepEquals, []internal_efi.LoadParams{
		{
			"allow_insufficient_dma_protection":   true,
			"include_insufficient_dma_protection": false,
		},
		{
			"allow_insufficient_dma_protection":   true,
			"include_insufficient_dma_protection": true,
		},
	})
}
