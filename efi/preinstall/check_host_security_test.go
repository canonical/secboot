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
	. "gopkg.in/check.v1"

	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
)

type hostSecuritySuite struct{}

var _ = Suite(&hostSecuritySuite{})

func (s *hostSecuritySuite) TestCheckForKernelIOMMUNotPresent(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices())
	c.Check(CheckForKernelIOMMU(env), Equals, ErrNoKernelIOMMU)
}

func (s *hostSecuritySuite) TestCheckForKernelIOMMUPresent(c *C) {
	device := efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	c.Check(CheckForKernelIOMMU(env), IsNil)
}

func (s *hostSecuritySuite) TestCheckForKernelIOMMUPresentErr(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts()
	err := CheckForKernelIOMMU(env)
	c.Check(err, ErrorMatches, `nil devices`)
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedFirmwareSettingsOk(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{})
	c.Check(CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log), IsNil)
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedFirmwareSettingsOkNoSecureBoot(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{SecureBootDisabled: true})
	c.Check(CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log), IsNil)
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedFirmwareSettingsOkNoSecureBootAndEmptySbatLevel(c *C) {
	// Simulate running on a machine with secure boot disabled and running
	// shim on a system with an empty SbatLevel variable. In this case,
	// there are no EV_EFI_VARIABLE_AUTHORITY events which caused
	// https://launchpad.net/bugs/2125439
	log := efitest.NewLog(c, &efitest.LogOptions{
		SecureBootDisabled: true,
		NoSBAT:             true,
	})
	c.Check(CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log), IsNil)
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedSettingsFirmwareDebuggingEnabled(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})
	err := CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrUEFIDebuggingEnabled})
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedSettingsDMAProtectionDisabled(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{DMAProtection: efitest.DMAProtectionDisabled})
	err := CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrInsufficientDMAProtection})
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedSettingsDMAProtectionDisabledEventNullTerminated(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{
		DMAProtection: efitest.DMAProtectionDisabled | efitest.DMAProtectionDisabledEventNullTerminated,
	})
	err := CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrInsufficientDMAProtection})
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedSettingsDMAProtectionDisabledEventAfterSeparator(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{
		DMAProtection: efitest.DMAProtectionDisabled | efitest.DMAProtectionDisabledEventOrderAfterSeparator,
	})
	err := CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrInsufficientDMAProtection})
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedSettingsDMAProtectionDisabledBeforeConfig(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{
		DMAProtection: efitest.DMAProtectionDisabled | efitest.DMAProtectionDisabledEventOrderBeforeConfig,
	})
	err := CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrInsufficientDMAProtection})
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedSettingsFirmwareDebuggingEnabledAndDMAProtectionDisabled(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{
		FirmwareDebugger: true,
		DMAProtection:    efitest.DMAProtectionDisabled,
	})
	err := CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrUEFIDebuggingEnabled, ErrInsufficientDMAProtection})
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedSettingsErrUnexpectedData(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})
	for _, ev := range log.Events {
		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}
		ev.Data = tcglog.EFICallingEFIApplicationEvent
		break
	}
	err := CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log)
	c.Check(err, ErrorMatches, `unexpected EV_EFI_ACTION event data in PCR7 event: \"Calling EFI Application from Boot Option\"`)
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedSettingsErrUnexpectedType(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})
	for _, ev := range log.Events {
		if ev.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}
		ev.EventType = tcglog.EventTypeAction
		break
	}
	c.Check(CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log), ErrorMatches, `unexpected event type \(EV_ACTION\) in PCR7`)
	err := CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log)
	c.Check(err, ErrorMatches, `unexpected event type \(EV_ACTION\) in PCR7`)
}
