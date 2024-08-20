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

type fwProtectionsSuite struct{}

var _ = Suite(&fwProtectionsSuite{})

func (s *fwProtectionsSuite) TestCheckForKernelIOMMUNotPresent1(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(make(map[string][]internal_efi.SysfsDevice)))
	c.Check(CheckForKernelIOMMU(env), Equals, ErrNoKernelIOMMU)
}

func (s *fwProtectionsSuite) TestCheckForKernelIOMMUNotPresent2(c *C) {
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "foo", nil),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	c.Check(CheckForKernelIOMMU(env), Equals, ErrNoKernelIOMMU)
}

func (s *fwProtectionsSuite) TestCheckForKernelIOMMUPresent(c *C) {
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices))
	c.Check(CheckForKernelIOMMU(env), IsNil)
}

func (s *fwProtectionsSuite) TestCheckForKernelIOMMUPresentErr(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts()
	c.Check(CheckForKernelIOMMU(env), ErrorMatches, `nil devices`)
}

func (s *fwProtectionsSuite) TestCheckSecureBootPolicyPCRForDegradedFirmwareSettingsOk(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{})
	c.Check(CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log), IsNil)
}

func (s *fwProtectionsSuite) TestCheckSecureBootPolicyPCRForDegradedSettingsFirmwareDebuggingEnabled(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})
	c.Check(CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log), Equals, ErrUEFIDebuggingEnabled)
}

func (s *fwProtectionsSuite) TestCheckSecureBootPolicyPCRForDegradedSettingsDMAProtectionDisabled1(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{DMAProtectionDisabled: efitest.DMAProtectionDisabled})
	c.Check(CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log), Equals, ErrInsufficientDMAProtection)
}

func (s *fwProtectionsSuite) TestCheckSecureBootPolicyPCRForDegradedSettingsDMAProtectionDisabled2(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{DMAProtectionDisabled: efitest.DMAProtectionDisabledNullTerminated})
	c.Check(CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log), Equals, ErrInsufficientDMAProtection)
}

func (s *fwProtectionsSuite) TestCheckSecureBootPolicyPCRForDegradedSettingsErrUnexpectedData(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})
	for _, ev := range log.Events {
		if ev.PCRIndex != tcglog.PCRIndex(internal_efi.SecureBootPolicyPCR) {
			continue
		}
		ev.Data = tcglog.EFICallingEFIApplicationEvent
		break
	}
	c.Check(CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log), ErrorMatches, `unexpected EV_EFI_ACTION event data in PCR7 event: \"Calling EFI Application from Boot Option\"`)
}

func (s *fwProtectionsSuite) TestCheckSecureBootPolicyPCRForDegradedSettingsErrUnexpectedType(c *C) {
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})
	for _, ev := range log.Events {
		if ev.PCRIndex != tcglog.PCRIndex(internal_efi.SecureBootPolicyPCR) {
			continue
		}
		ev.EventType = tcglog.EventTypeAction
		break
	}
	c.Check(CheckSecureBootPolicyPCRForDegradedFirmwareSettings(log), ErrorMatches, `unexpected event type \(EV_ACTION\) in PCR7`)
}
