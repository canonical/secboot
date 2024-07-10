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

	. "gopkg.in/check.v1"

	"github.com/intel-go/cpuid"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type fwProtectionsAMD64Suite struct{}

var _ = Suite(&fwProtectionsAMD64Suite{})

func (s *fwProtectionsAMD64Suite) TestCheckCPUDebuggingLockedMSRDisabledCPUID(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", nil, 1, map[uint32]uint64{0xc80: 0}))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	c.Check(CheckCPUDebuggingLockedMSR(amd64Env), IsNil)
}

func (s *fwProtectionsAMD64Suite) TestCheckCPUDebuggingLockedMSRDisabledMSR(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 0x40000000}))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	c.Check(CheckCPUDebuggingLockedMSR(amd64Env), IsNil)
}

func (s *fwProtectionsAMD64Suite) TestCheckCPUDebuggingLockedMSRDisabledAvailable(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 0}))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	c.Check(CheckCPUDebuggingLockedMSR(amd64Env), Equals, ErrCPUDebuggingNotLocked)
}

func (s *fwProtectionsAMD64Suite) TestCheckCPUDebuggingLockedMSREnabled(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 1}))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	c.Check(CheckCPUDebuggingLockedMSR(amd64Env), Equals, ErrCPUDebuggingNotLocked)
}

func (s *fwProtectionsAMD64Suite) TestCheckCPUDebuggingLockedMSRErrMissingMSR(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{}))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	c.Check(CheckCPUDebuggingLockedMSR(amd64Env), ErrorMatches, `MSR does not exist`)
}

func (s *fwProtectionsAMD64Suite) TestCheckCPUDebuggingLockedMSRErrNoMSRValues(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 0, map[uint32]uint64{0xc80: 0x40000000}))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	c.Check(CheckCPUDebuggingLockedMSR(amd64Env), ErrorMatches, `no MSR values returned`)
}

func (s *fwProtectionsAMD64Suite) TestDetermineCPUVendorIntel(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineIntel", nil, 0, nil))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	vendor, err := DetermineCPUVendor(amd64Env)
	c.Check(err, IsNil)
	c.Check(vendor, Equals, CpuVendorIntel)
}

func (s *fwProtectionsAMD64Suite) TestDetermineCPUVendorAMD(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("AuthenticAMD", nil, 0, nil))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	vendor, err := DetermineCPUVendor(amd64Env)
	c.Check(err, IsNil)
	c.Check(vendor, Equals, CpuVendorAMD)
}

func (s *fwProtectionsAMD64Suite) TestDetermineCPUVendorUnknown(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(efitest.WithAMD64Environment("GenuineInte", nil, 0, nil))
	amd64Env, err := env.AMD64()
	c.Assert(err, IsNil)

	_, err = DetermineCPUVendor(amd64Env)
	c.Check(err, ErrorMatches, `unknown CPU vendor: GenuineInte`)
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsGood(c *C) {
	meiAttrs := map[string][]byte{
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
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices),
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	result, err := CheckPlatformFirmwareProtections(env, log)
	c.Check(err, IsNil)
	c.Check(result, Equals, PlatformFirmwareProtectionsTPMLocality3IsProtected)
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsNoTXT(c *C) {
	meiAttrs := map[string][]byte{
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
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices),
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	result, err := CheckPlatformFirmwareProtections(env, log)
	c.Check(err, IsNil)
	c.Check(result, Equals, PlatformFirmwareProtectionsResultFlags(0))
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsErrNotAMD64(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts()

	_, err := CheckPlatformFirmwareProtections(env, nil)
	c.Check(err, ErrorMatches, `cannot obtain AMD64 environment: not a AMD64 host`)
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsErrUnrecognizedCpuVendor(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineInte", nil, 0, nil),
	)

	_, err := CheckPlatformFirmwareProtections(env, nil)
	c.Check(err, ErrorMatches, `cannot determine CPU vendor: unknown CPU vendor: GenuineInte`)
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsErrAMDNotSupportedYet(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("AuthenticAMD", nil, 0, nil),
	)

	_, err := CheckPlatformFirmwareProtections(env, nil)
	c.Check(err, ErrorMatches, `TODO: checking platform firmware protections is not yet implemented for AMD`)
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsErrMEI(c *C) {
	meiAttrs := map[string][]byte{
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
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices),
		efitest.WithAMD64Environment("GenuineIntel", nil, 0, nil),
	)

	_, err := CheckPlatformFirmwareProtections(env, nil)
	c.Check(err, ErrorMatches, `encountered an error when determining platform firmware protections using Intel MEI: no hardware root-of-trust properly configured: ME is in manufacturing mode: no firmware protections are enabled`)

	var nhrotErr *NoHardwareRootOfTrustError
	c.Check(errors.As(err, &nhrotErr), testutil.IsTrue)
	c.Check(nhrotErr, ErrorMatches, `no hardware root-of-trust properly configured: ME is in manufacturing mode: no firmware protections are enabled`)
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsSecureBootPolicyFirmwareDebugging(c *C) {
	meiAttrs := map[string][]byte{
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
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices),
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})

	_, err := CheckPlatformFirmwareProtections(env, log)
	c.Check(err, ErrorMatches, `encountered an error whilst checking the TCG log for degraded firmware settings: the platform firmware contains a debugging endpoint enabled`)
	c.Check(errors.Is(err, ErrUEFIDebuggingEnabled), testutil.IsTrue)
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsNoIOMMU(c *C) {
	meiAttrs := map[string][]byte{
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
	devices := map[string][]internal_efi.SysfsDevice{
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices),
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	_, err := CheckPlatformFirmwareProtections(env, log)
	c.Check(err, ErrorMatches, `encountered an error whilst checking sysfs to determine that kernel IOMMU support is enabled: no kernel IOMMU support was detected`)
	c.Check(errors.Is(err, ErrNoKernelIOMMU), testutil.IsTrue)
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsCPUDebuggingUnlocked(c *C) {
	meiAttrs := map[string][]byte{
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
	devices := map[string][]internal_efi.SysfsDevice{
		"iommu": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("dmar0", "/sys/devices/virtual/iommu/dmar0", "iommu", nil),
			efitest.NewMockSysfsDevice("dmar1", "/sys/devices/virtual/iommu/dmar1", "iommu", nil),
		},
		"mei": []internal_efi.SysfsDevice{
			efitest.NewMockSysfsDevice("mei0", "/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", "mei", meiAttrs),
		},
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices),
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 0x0}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	_, err := CheckPlatformFirmwareProtections(env, log)
	c.Check(err, ErrorMatches, `encountered an error when determining CPU debugging configuration from MSRs: CPU debugging features are not disabled and locked`)
	c.Check(errors.Is(err, ErrCPUDebuggingNotLocked), testutil.IsTrue)
}
