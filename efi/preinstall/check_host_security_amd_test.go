// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025-2026 Canonical Ltd
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
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
)

type hostSecurityAMDSuite struct{}

var _ = Suite(&hostSecurityAMDSuite{})

func (s *hostSecurityAMDSuite) TestCheckHostSecurityAMDPSPGood(c *C) {
	attrs := map[string][]byte{
		"boot_integrity": []byte(`1
`),
		"debug_lock_on": []byte(`1
`),
		"fused_part": []byte(`1
`),
	}

	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", attrs, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(device),
		efitest.WithAMD64Environment("AuthenticAMD", 0x1a, nil, 0, nil),
	)
	integrity, err := CheckHostSecurityAMDPSP(env)
	c.Check(err, IsNil)
	c.Check(integrity, Equals, PlatformFirmwareIntegrityVerified)
}

func (s *hostSecurityAMDSuite) TestCheckHostSecurityAMDPSPGoodBootIntegrityDisabled(c *C) {
	attrs := map[string][]byte{
		"boot_integrity": []byte(`0
`),
		"debug_lock_on": []byte(`1
`),
		"fused_part": []byte(`1
`),
	}

	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", attrs, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(device),
		efitest.WithAMD64Environment("AuthenticAMD", 0x1a, nil, 0, nil),
	)
	integrity, err := CheckHostSecurityAMDPSP(env)
	c.Check(err, IsNil)
	c.Check(integrity, Equals, PlatformFirmwareIntegrityMeasured)
}

func (s *hostSecurityAMDSuite) TestCheckHostSecurityAMDPSPGoodNoBootIntegrityAttr(c *C) {
	attrs := map[string][]byte{
		"debug_lock_on": []byte(`1
`),
		"fused_part": []byte(`1
`),
	}

	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", attrs, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(device),
		efitest.WithAMD64Environment("AuthenticAMD", 0x1a, nil, 0, nil),
	)
	integrity, err := CheckHostSecurityAMDPSP(env)
	c.Check(err, IsNil)
	c.Check(integrity, Equals, PlatformFirmwareIntegrityMeasured)
}

func (s *hostSecurityAMDSuite) TestCheckHostSecurityAMDPSPGoodNotFused(c *C) {
	attrs := map[string][]byte{
		"boot_integrity": []byte(`0
`),
		"debug_lock_on": []byte(`1
`),
		"fused_part": []byte(`0
`),
	}

	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", attrs, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(device),
		efitest.WithAMD64Environment("AuthenticAMD", 0x1a, nil, 0, nil),
	)
	integrity, err := CheckHostSecurityAMDPSP(env)
	c.Check(err, IsNil)
	c.Check(integrity, Equals, PlatformFirmwareIntegrityMeasured)
}

func (s *hostSecurityAMDSuite) TestCheckHostSecurityErrNoCCPModule(c *C) {
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"PCI_CLASS": "108000", "PCI_ID": "1022:15C7"}, "pci", nil, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	_, err := CheckHostSecurityAMDPSP(env)
	c.Check(err, ErrorMatches, `the kernel module "ccp" must be loaded`)
	c.Check(err, Equals, MissingKernelModuleError("ccp"))
}

func (s *hostSecurityAMDSuite) TestCheckHostSecurityErrNoPSPDevice(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices())
	_, err := CheckHostSecurityAMDPSP(env)
	c.Check(err, ErrorMatches, `unsupported platform: no PSP PCI device`)
	c.Check(err, FitsTypeOf, &UnsupportedPlatformError{})
}

func (s *hostSecurityAMDSuite) TestCheckHostSecurityErrUnsupportedFamily(c *C) {
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", nil, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(device),
		efitest.WithAMD64Environment("AuthenticAMD", 0x16, nil, 0, nil),
	)
	_, err := CheckHostSecurityAMDPSP(env)
	c.Check(err, ErrorMatches, `unsupported platform: unsupported CPU family`)
	c.Check(err, FitsTypeOf, &UnsupportedPlatformError{})
}

func (s *hostSecurityAMDSuite) TestCheckHostSecurityErrNoSecurityReporting1(c *C) {
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", nil, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(device),
		efitest.WithAMD64Environment("AuthenticAMD", 0x1a, nil, 0, nil),
	)
	_, err := CheckHostSecurityAMDPSP(env)
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
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(device),
		efitest.WithAMD64Environment("AuthenticAMD", 0x1a, nil, 0, nil),
	)
	_, err := CheckHostSecurityAMDPSP(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: PSP debug lock is not enabled`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityAMDSuite) TestDetectAMDPreOSMeasurementConfig(c *C) {
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2",
			map[string]string{"DRIVER": "ccp"},
			"pci",
			map[string][]byte{"tsme_status": []byte("1\n")},
			nil),
		efitest.NewMockSysfsDevice(
			"/sys/devices/platform/firmware-attributes/hp-bioscfg",
			nil,
			"firmware-attributes",
			map[string][]byte{
				"attributes/Measure Additional DMA Settings/current_value": []byte("PCR7\n"),
				"attributes/SVM CPU Virtualization/current_value":          []byte("Enable\n"),
				"attributes/DMA Protection/current_value":                  []byte("Enable\n"),
				"attributes/Pre-boot DMA Protection/current_value":         []byte("All PCIe Devices\n"),
			},
			nil),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices...))

	config, err := DetectAMDPreOSMeasurementConfig(env)
	c.Check(err, IsNil)
	c.Check(config, DeepEquals, &AMDPreOSMeasurementConfig{
		TSMEEnabled:               true,
		HPPreBootDMAConfigEnabled: true,
	})
}

func (s *hostSecurityAMDSuite) TestDetectAMDPreOSMeasurementConfigWithoutHPMeasurement(c *C) {
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2",
			map[string]string{"DRIVER": "ccp"},
			"pci",
			map[string][]byte{"tsme_status": []byte("0\n")},
			nil),
		efitest.NewMockSysfsDevice(
			"/sys/devices/platform/firmware-attributes/hp-bioscfg",
			nil,
			"firmware-attributes",
			map[string][]byte{
				"attributes/Measure Additional DMA Settings/current_value": []byte("Do not measure\n"),
			},
			nil),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices...))

	config, err := DetectAMDPreOSMeasurementConfig(env)
	c.Check(err, IsNil)
	c.Check(config, DeepEquals, &AMDPreOSMeasurementConfig{})
}

func (s *hostSecurityAMDSuite) TestDetectAMDPreOSMeasurementConfigMissingTSMEStatus(c *C) {
	device := efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2",
		map[string]string{"DRIVER": "ccp"},
		"pci",
		nil,
		nil)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))

	_, err := DetectAMDPreOSMeasurementConfig(env)
	c.Check(err, ErrorMatches, `cannot determine TSME status: device attribute does not exist`)
}

func (s *hostSecurityAMDSuite) TestDetectAMDPreOSMeasurementConfigRejectsUnsupportedMeasuredHPConfig(c *C) {
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2",
			map[string]string{"DRIVER": "ccp"},
			"pci",
			map[string][]byte{"tsme_status": []byte("1\n")},
			nil),
		efitest.NewMockSysfsDevice(
			"/sys/devices/platform/firmware-attributes/hp-bioscfg",
			nil,
			"firmware-attributes",
			map[string][]byte{
				"attributes/Measure Additional DMA Settings/current_value": []byte("PCR7\n"),
				"attributes/SVM CPU Virtualization/current_value":          []byte("Disable\n"),
			},
			nil),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices...))

	_, err := DetectAMDPreOSMeasurementConfig(env)
	c.Check(err, ErrorMatches, `unsupported platform: unsupported HP SVM CPU Virtualization firmware setting "Disable"`)
}
