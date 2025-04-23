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

	"github.com/canonical/cpuid"
	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type fwProtectionsAMD64Suite struct{}

var _ = Suite(&fwProtectionsAMD64Suite{})

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

	protectedStartupLocalities, err := CheckPlatformFirmwareProtections(env, log)
	c.Check(err, IsNil)
	c.Check(protectedStartupLocalities, Equals, tpm2.LocalityThree|tpm2.LocalityFour)
	c.Check(protectedStartupLocalities.Values(), DeepEquals, []uint8{3, 4})
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

	protectedStartupLocalities, err := CheckPlatformFirmwareProtections(env, log)
	c.Check(err, IsNil)
	c.Check(protectedStartupLocalities, Equals, tpm2.Locality(0))
	c.Check(protectedStartupLocalities.Values(), DeepEquals, []uint8(nil))
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsErrNotAMD64(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts()

	_, err := CheckPlatformFirmwareProtections(env, nil)
	c.Check(err, ErrorMatches, `unsupported platform: cannot determine CPU vendor: not a AMD64 host`)

	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsErrUnrecognizedCpuVendor(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineInte", nil, 0, nil),
	)

	_, err := CheckPlatformFirmwareProtections(env, nil)
	c.Check(err, ErrorMatches, `unsupported platform: cannot determine CPU vendor: unknown CPU vendor: GenuineInte`)

	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsErrAMDNotSupportedYet(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("AuthenticAMD", nil, 0, nil),
	)

	_, err := CheckPlatformFirmwareProtections(env, nil)
	c.Check(err, ErrorMatches, `unsupported platform: checking platform firmware protections is not yet implemented for AMD`)
	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
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
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})

	protectedStartupLocalities, err := CheckPlatformFirmwareProtections(env, log)
	c.Check(err, ErrorMatches, `the platform firmware contains a debugging endpoint enabled`)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrUEFIDebuggingEnabled})
	c.Check(protectedStartupLocalities, Equals, tpm2.LocalityThree|tpm2.LocalityFour)
	c.Check(protectedStartupLocalities.Values(), DeepEquals, []uint8{3, 4})
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
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	protectedStartupLocalities, err := CheckPlatformFirmwareProtections(env, log)
	c.Check(err, ErrorMatches, `no kernel IOMMU support was detected`)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrNoKernelIOMMU})
	c.Check(protectedStartupLocalities, Equals, tpm2.LocalityThree|tpm2.LocalityFour)
	c.Check(protectedStartupLocalities.Values(), DeepEquals, []uint8{3, 4})
}

func (s *fwProtectionsAMD64Suite) TestCheckPlatformFirmwareProtectionsSecureBootPolicyFirmwareDebuggingAndNoIOMMU(c *C) {
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
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})

	protectedStartupLocalities, err := CheckPlatformFirmwareProtections(env, log)
	c.Check(err, ErrorMatches, `2 errors detected:
- the platform firmware contains a debugging endpoint enabled
- no kernel IOMMU support was detected
`)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrUEFIDebuggingEnabled, ErrNoKernelIOMMU})
	c.Check(protectedStartupLocalities, Equals, tpm2.LocalityThree|tpm2.LocalityFour)
	c.Check(protectedStartupLocalities.Values(), DeepEquals, []uint8{3, 4})
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
