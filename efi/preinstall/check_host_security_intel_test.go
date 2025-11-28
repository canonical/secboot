//go:build amd64

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
	"bytes"
	"errors"
	"io"

	. "gopkg.in/check.v1"

	"github.com/canonical/cpuid"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type hostSecurityIntelSuite struct{}

var _ = Suite(&hostSecurityIntelSuite{})

type mockMEISysfsDevice struct {
	fwVer    []byte
	fwStatus []byte
}

func (*mockMEISysfsDevice) Path() string                              { return "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0" }
func (*mockMEISysfsDevice) Properties() map[string]string             { return nil }
func (*mockMEISysfsDevice) Subsystem() string                         { return "mei" }
func (*mockMEISysfsDevice) Parent() (internal_efi.SysfsDevice, error) { return nil, nil }

func (d *mockMEISysfsDevice) AttributeReader(attr string) (io.ReadCloser, error) {
	switch attr {
	case "fw_ver":
		if len(d.fwVer) == 0 {
			return nil, internal_efi.ErrNoDeviceAttribute
		}
		return io.NopCloser(bytes.NewReader(d.fwVer)), nil
	case "fw_status":
		if len(d.fwStatus) == 0 {
			return nil, internal_efi.ErrNoDeviceAttribute
		}
		return io.NopCloser(bytes.NewReader(d.fwStatus)), nil
	default:
		return nil, internal_efi.ErrNoDeviceAttribute
	}
}

func (s *hostSecurityIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfs1(c *C) {
	dev := &mockMEISysfsDevice{
		fwStatus: []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}

	regs, err := ReadIntelHFSTSRegistersFromMEISysfs(dev)
	c.Check(err, IsNil)
	c.Check(regs, DeepEquals, HfstsRegisters{
		Hfsts1: 0x94000245,
		Hfsts2: 0x09F10506,
		Hfsts3: 0x00000020,
		Hfsts4: 0x00004000,
		Hfsts5: 0x00041F03,
		Hfsts6: 0xC7E003CB,
	})
}

func (s *hostSecurityIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfs2(c *C) {
	dev := &mockMEISysfsDevice{
		fwStatus: []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E0034B
`),
	}

	regs, err := ReadIntelHFSTSRegistersFromMEISysfs(dev)
	c.Check(err, IsNil)
	c.Check(regs, Equals, HfstsRegisters{
		Hfsts1: 0x94000245,
		Hfsts2: 0x09F10506,
		Hfsts3: 0x00000020,
		Hfsts4: 0x00004000,
		Hfsts5: 0x00041F03,
		Hfsts6: 0xC7E0034B,
	})
}

func (s *hostSecurityIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfsErrNoAttr(c *C) {
	dev := &mockMEISysfsDevice{}

	_, err := ReadIntelHFSTSRegistersFromMEISysfs(dev)
	c.Check(err, ErrorMatches, `device attribute does not exist`)
}

func (s *hostSecurityIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfsErrTooMany(c *C) {
	dev := &mockMEISysfsDevice{
		fwStatus: []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
00000000
`),
	}

	_, err := ReadIntelHFSTSRegistersFromMEISysfs(dev)
	c.Check(err, ErrorMatches, `invalid fw_status format: too many entries`)
}

func (s *hostSecurityIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfsErrInvalidLineLen(c *C) {
	dev := &mockMEISysfsDevice{
		fwStatus: []byte(`94000245
09F10506
00000020
00004000
00041F03
7E003CB
`),
	}

	_, err := ReadIntelHFSTSRegistersFromMEISysfs(dev)
	c.Check(err, ErrorMatches, `invalid fw_status format: unexpected line length for line 5 \(7 chars\)`)
}

func (s *hostSecurityIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfsErrInvalidLine(c *C) {
	dev := &mockMEISysfsDevice{
		fwStatus: []byte(`94000245
09F10506
00000020
00004000
00041F03
G7E003CB
`),
	}

	_, err := ReadIntelHFSTSRegistersFromMEISysfs(dev)
	c.Check(err, ErrorMatches, `invalid fw_status format: cannot scan line 5: expected integer`)
}

func (s *hostSecurityIntelSuite) TestReadIntelHFSTSRegistersFromMEISysfsErrNotEnough(c *C) {
	dev := &mockMEISysfsDevice{
		fwStatus: []byte(`94000245
09F10506
00000020
00004000
00041F03
`),
	}

	_, err := ReadIntelHFSTSRegistersFromMEISysfs(dev)
	c.Check(err, ErrorMatches, `invalid fw_status format: not enough entries`)
}

func (s *hostSecurityIntelSuite) TestReadIntelMeVersionFromMEISysfs1(c *C) {
	dev := &mockMEISysfsDevice{
		fwVer: []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
	}

	ver, err := ReadIntelMEVersionFromMEISysfs(dev)
	c.Check(err, IsNil)
	c.Check(ver, DeepEquals, MeVersion{
		Platform: 0,
		Major:    16,
		Minor:    1,
		Hotfix:   27,
		Buildno:  2176,
	})
}

func (s *hostSecurityIntelSuite) TestReadIntelMeVersionFromMEISysfs2(c *C) {
	dev := &mockMEISysfsDevice{
		fwVer: []byte(`0:8.1.65.1586
0:8.1.65.1586
0:8.1.52.1496
`),
	}

	ver, err := ReadIntelMEVersionFromMEISysfs(dev)
	c.Check(err, IsNil)
	c.Check(ver, DeepEquals, MeVersion{
		Platform: 0,
		Major:    8,
		Minor:    1,
		Hotfix:   65,
		Buildno:  1586,
	})
}

func (s *hostSecurityIntelSuite) TestReadIntelMeVersionFromMEISysfsErrNoAttr(c *C) {
	dev := &mockMEISysfsDevice{}
	_, err := ReadIntelMEVersionFromMEISysfs(dev)
	c.Check(err, ErrorMatches, `device attribute does not exist`)
}

func (s *hostSecurityIntelSuite) TestReadIntelMeVersionFromMEISysfsErrInvalidVer(c *C) {
	dev := &mockMEISysfsDevice{
		fwVer: []byte(`0:16.1.27
0:16.1.27.2176
0:16.0.15.1624
`),
	}
	_, err := ReadIntelMEVersionFromMEISysfs(dev)
	c.Check(err, ErrorMatches, `invalid fw_ver: unexpected EOF`)
}

func (s *hostSecurityIntelSuite) TestCalculateIntelMEFamilyCSME(c *C) {
	c.Check(CalculateIntelMEFamily(MeVersion{Major: 11}, 0x94000245), Equals, MeFamilyCsme)
}

func (s *hostSecurityIntelSuite) TestCalculateIntelMEFamilyME(c *C) {
	c.Check(CalculateIntelMEFamily(MeVersion{Major: 9}, 0x94000245), Equals, MeFamilyMe)
}

func (s *hostSecurityIntelSuite) TestCalculateIntelMEFamilyTXE1(c *C) {
	c.Check(CalculateIntelMEFamily(MeVersion{Major: 5}, 0x94000245), Equals, MeFamilyTxe)
}

func (s *hostSecurityIntelSuite) TestCalculateIntelMEFamilyTXE2(c *C) {
	c.Check(CalculateIntelMEFamily(MeVersion{Major: 4}, 0x94000245), Equals, MeFamilyTxe)
}

func (s *hostSecurityIntelSuite) TestCalculateIntelMEFamilySPS(c *C) {
	c.Check(CalculateIntelMEFamily(MeVersion{Major: 4}, 0x940F0245), Equals, MeFamilySps)
}

func (s *hostSecurityIntelSuite) TestCalculateIntelMEFamilyUnkown(c *C) {
	c.Check(CalculateIntelMEFamily(MeVersion{Major: 0}, 0x940F0245), Equals, MeFamilyUnknown)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardGoodFVMECSME11(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, IsNil)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardGoodFVECSME11(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E002CB
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, IsNil)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardGoodFVMECSME18(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:18.0.5.2141
0:18.0.5.2141
0:18.0.5.2066
`),
		"fw_status": []byte(`A4000245
09110500
00000020
00000000
02F61F03
40200000
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, IsNil)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardGoodFVECSME18(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:18.0.5.2141
0:18.0.5.2141
0:18.0.5.2066
`),
		"fw_status": []byte(`A4000245
09110500
00000020
00000000
02F21F03
40200000
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, IsNil)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardGoodFVMECSME18WithOtherMEIDevices(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:18.0.5.2141
0:18.0.5.2141
0:18.0.5.2066
`),
		"fw_status": []byte(`A4000245
09110500
00000020
00000000
02F61F03
40200000
`),
	}
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/0000:00:16.0-082ee5a7-7c25-470a-9643-0c06f0466ea1", nil, "mei", attrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
		efitest.NewMockSysfsDevice("/sys/devices/platform/intel_vsc/mei/mei1", map[string]string{"DEVNAME": "mei1"}, "mei", nil, efitest.NewMockSysfsDevice(
			"/sys/devices/platform", map[string]string{"DRIVER": "intel_vsc"}, "platform", nil, nil,
		)),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(devices...))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, IsNil)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrNoDevices(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts()
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `cannot obtain devices for mei subsystem: nil devices`)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrNoMEModule(c *C) {
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0", map[string]string{"PCI_CLASS": "78000", "PCI_ID": "8086:7E70"}, "pci", nil, nil)
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `the kernel module "mei_me" must be loaded`)
	c.Check(err, Equals, MissingKernelModuleError("mei_me"))
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrNoMEDevice1(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices())
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `unsupported platform: no MEI PCI device`)
	c.Check(err, FitsTypeOf, &UnsupportedPlatformError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrNoMEDevice2(c *C) {
	device := efitest.NewMockSysfsDevice("/sys/devices/platform/intel_vsc/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", nil, efitest.NewMockSysfsDevice(
		"/sys/devices/platform", map[string]string{"DRIVER": "intel_vsc"}, "platform", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `unsupported platform: no MEI PCI device`)
	c.Check(err, FitsTypeOf, &UnsupportedPlatformError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrFwVer(c *C) {
	attrs := map[string][]byte{
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `cannot obtain ME version from sysfs: device attribute does not exist`)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrHFSTSRegisters(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `cannot read HFSTS registers from sysfs: device attribute does not exist`)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrUnsupportedMEFamily(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:8.1.65.1586
0:8.1.65.1586
0:8.1.52.1496
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `unsupported platform: unsupported ME family`)
	c.Check(err, FitsTypeOf, &UnsupportedPlatformError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrOperationModeOverrideJumper(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94040245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: invalid ME operation mode`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrOperationModeDebug(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94020245
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: invalid ME operation mode`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrMfgMode(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000255
09F10506
00000020
00004000
00041F03
C7E003CB
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: ME is in manufacturing mode`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrACMNotActive(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:18.0.5.2141
0:18.0.5.2141
0:18.0.5.2066
`),
		"fw_status": []byte(`A4000245
09110500
00000020
00000000
02F61E02
40200000
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: BootGuard ACM is not active`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrACMNotDone(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:18.0.5.2141
0:18.0.5.2141
0:18.0.5.2066
`),
		"fw_status": []byte(`A4000245
09110500
00000020
00000000
02F61E03
40200000
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: BootGuard ACM is not active`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrNoFPFSOCLock(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
87E003CB
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: BootGuard OTP fuses are not locked`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrBootGuardDisable(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
D7E003CB
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: BootGuard is disabled`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrUnsupportedNoFVMECSME11(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E00002
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: unsupported BootGuard profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrUnsupportedVMProfileCSME11(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E0030A
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: unsupported BootGuard profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrInvalidProfileCSME11(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": []byte(`94000245
09F10506
00000020
00004000
00041F03
C7E0024A
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: cannot determine BootGuard profile: invalid profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrInvalidProfileCSME18(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:18.0.5.2141
0:18.0.5.2141
0:18.0.5.2066
`),
		"fw_status": []byte(`A4000245
09110500
00000020
00000000
02F61F01
40200000
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: invalid BootGuard profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrUnsupportedNoFVMEProfileCSME18(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:18.0.5.2141
0:18.0.5.2141
0:18.0.5.2066
`),
		"fw_status": []byte(`A4000245
09110500
00000020
00000000
02E21F03
40200000
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: unsupported BootGuard profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelBootGuardErrUnsupportedVMProfileCSME18(c *C) {
	attrs := map[string][]byte{
		"fw_ver": []byte(`0:18.0.5.2141
0:18.0.5.2141
0:18.0.5.2066
`),
		"fw_status": []byte(`A4000245
09110500
00000020
00000000
02EE1F03
40200000
`),
	}
	device := efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
		"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
	))
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithSysfsDevices(device))
	err := CheckHostSecurityIntelBootGuard(env)
	c.Check(err, ErrorMatches, `no hardware root-of-trust properly configured: unsupported BootGuard profile`)
	c.Check(err, FitsTypeOf, &NoHardwareRootOfTrustError{})
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelCPUDebuggingLockedDisabledCPUID(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0xc80: 0}))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	c.Check(CheckHostSecurityIntelCPUDebuggingLocked(amd64Env), IsNil)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelCPUDebuggingLockedDisabledMSR(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 0x40000000}))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	c.Check(CheckHostSecurityIntelCPUDebuggingLocked(amd64Env), IsNil)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelCPUDebuggingLockedDisabledAvailable(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 0}))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	c.Check(CheckHostSecurityIntelCPUDebuggingLocked(amd64Env), Equals, ErrCPUDebuggingNotLocked)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelCPUDebuggingLockedEnabled(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 1}))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	c.Check(CheckHostSecurityIntelCPUDebuggingLocked(amd64Env), Equals, ErrCPUDebuggingNotLocked)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelCPUDebuggingLockedErrMissingMSR(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{}))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	err = CheckHostSecurityIntelCPUDebuggingLocked(amd64Env)
	c.Check(err, ErrorMatches, `cannot read MSRs: missing MSR support`)
	c.Check(errors.Is(err, internal_efi.ErrNoMSRSupport), testutil.IsTrue)
}

func (s *hostSecurityIntelSuite) TestCheckHostSecurityIntelCPUDebuggingLockedErrNoMSRSupport(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 0, nil))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	err = CheckHostSecurityIntelCPUDebuggingLocked(amd64Env)
	c.Check(err, ErrorMatches, `the kernel module "msr" must be loaded`)
	c.Check(err, Equals, MissingKernelModuleError("msr"))
}
