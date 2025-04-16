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

func (s *hostSecuritySuite) TestCheckForKernelIOMMUNotPresent1(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(make(map[string][]internal_efi.SysfsDevice)))
	c.Check(CheckForKernelIOMMU(env), Equals, ErrNoKernelIOMMU)
}

func (s *hostSecuritySuite) TestCheckForKernelIOMMUNotPresent2(c *C) {
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "foo", nil),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	c.Check(CheckForKernelIOMMU(env), Equals, ErrNoKernelIOMMU)
}

func (s *hostSecuritySuite) TestCheckForKernelIOMMUPresent(c *C) {
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
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

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedSettingsFirmwareDebuggingEnabled(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})
	err := CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrUEFIDebuggingEnabled})
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedSettingsDMAProtectionDisabled1(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{DMAProtectionDisabled: efitest.DMAProtectionDisabled})
	err := CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrInsufficientDMAProtection})
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedSettingsDMAProtectionDisabled2(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{DMAProtectionDisabled: efitest.DMAProtectionDisabledNullTerminated})
	err := CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrInsufficientDMAProtection})
}

func (s *hostSecuritySuite) TestCheckSecureBootPolicyPCRForDegradedSettingsFirmwareDebuggingEnabledAndDMAProtectionDisabled(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{
		FirmwareDebugger:      true,
		DMAProtectionDisabled: efitest.DMAProtectionDisabled,
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
