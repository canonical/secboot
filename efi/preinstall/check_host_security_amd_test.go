//go:build amd64

// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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

	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/efitest"
)

type hostSecurityAMDSuite struct{}

var _ = Suite(&hostSecurityAMDSuite{})

func (s *hostSecurityAMDSuite) TestCheckHostSecurityAMDPSPGood(c *C) {
	attrs := map[string][]byte{
		"debug_lock_on": []byte(`1
`),
		"fused_part": []byte(`1
`),
	}

	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", attrs, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityAMDPSP(env)
	c.Check(err, IsNil)
}

func (s *hostSecurityAMDSuite) TestCheckHostSecurityErrNoCCPModule(c *C) {
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"PCI_CLASS": "108000", "PCI_ID": "1022:15C7"}, "pci", nil, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityAMDPSP(env)
	c.Check(err, ErrorMatches, `the kernel module "ccp" must be loaded`)
	c.Check(err, Equals, MissingKernelModuleError("ccp"))
}

func (s *hostSecurityAMDSuite) TestCheckHostSecurityErrNoPSPDevice(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices())
	err := CheckHostSecurityAMDPSP(env)
	c.Check(err, ErrorMatches, `unsupported platform: no PSP PCI device`)
	c.Check(err, FitsTypeOf, &UnsupportedPlatformError{})
}

func (s *hostSecurityAMDSuite) TestCheckHostSecurityErrNoSecurityReporting(c *C) {
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", nil, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityAMDPSP(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: PSP security reporting not available`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityAMDSuite) TestCheckHostSecurityAMDPSPErrNoDebugLock(c *C) {
	attrs := map[string][]byte{
		"debug_lock_on": []byte(`0
`),
		"fused_part": []byte(`1
`),
	}

	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", attrs, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityAMDPSP(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: PSP debug lock is not enabled`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityAMDSuite) TestCheckHostSecurityAMDPSPErrNoPSB(c *C) {
	attrs := map[string][]byte{
		"debug_lock_on": []byte(`1
`),
		"fused_part": []byte(`0
`),
	}

	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", attrs, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityAMDPSP(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: Platform Secure Boot is not enabled`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}
