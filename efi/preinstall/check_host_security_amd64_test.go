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

type hostSecurityAMD64Suite struct{}

var _ = Suite(&hostSecurityAMD64Suite{})

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityGood(c *C) {
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices...),
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	c.Check(CheckHostSecurity(env, log), IsNil)
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityErrNotAMD64(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts()

	err := CheckHostSecurity(env, nil)
	c.Check(err, ErrorMatches, `unsupported platform: cannot determine CPU vendor: not a AMD64 host`)

	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityErrUnrecognizedCpuVendor(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineInte", nil, 0, nil),
	)

	err := CheckHostSecurity(env, nil)
	c.Check(err, ErrorMatches, `unsupported platform: cannot determine CPU vendor: unknown CPU vendor: GenuineInte`)

	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityErrAMDNotSupportedYet(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("AuthenticAMD", nil, 0, nil),
	)

	err := CheckHostSecurity(env, nil)
	c.Check(err, ErrorMatches, `unsupported platform: checking host security is not yet implemented for AMD`)
	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityErrMEI(c *C) {
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices...),
		efitest.WithAMD64Environment("GenuineIntel", nil, 0, nil),
	)

	err := CheckHostSecurity(env, nil)
	c.Check(err, ErrorMatches, `encountered an error when checking Intel BootGuard configuration: no hardware root-of-trust properly configured: ME is in manufacturing mode`)

	var nhrotErr *NoHardwareRootOfTrustError
	c.Check(errors.As(err, &nhrotErr), testutil.IsTrue)
	c.Check(nhrotErr, ErrorMatches, `no hardware root-of-trust properly configured: ME is in manufacturing mode`)
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecuritySecureBootPolicyFirmwareDebugging(c *C) {
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices...),
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})

	err := CheckHostSecurity(env, log)
	c.Check(err, ErrorMatches, `the platform firmware contains a debugging endpoint enabled`)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrUEFIDebuggingEnabled})
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityNoIOMMU(c *C) {
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices...),
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	err := CheckHostSecurity(env, log)
	c.Check(err, ErrorMatches, `no kernel IOMMU support was detected`)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrNoKernelIOMMU})
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecuritySecureBootPolicyFirmwareDebuggingAndNoIOMMU(c *C) {
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices...),
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})

	err := CheckHostSecurity(env, log)
	c.Check(err, ErrorMatches, `2 errors detected:
- the platform firmware contains a debugging endpoint enabled
- no kernel IOMMU support was detected
`)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrUEFIDebuggingEnabled, ErrNoKernelIOMMU})
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityCPUDebuggingUnlocked(c *C) {
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
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices...),
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 0x0}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	err := CheckHostSecurity(env, log)
	c.Check(err, ErrorMatches, `encountered an error when checking Intel CPU debugging configuration: CPU debugging features are not disabled and locked`)
	c.Check(errors.Is(err, ErrCPUDebuggingNotLocked), testutil.IsTrue)
}

func (s *hostSecurityAMD64Suite) TestCheckDiscreteTPMPartialResetAttackMitigationStatusNotRequiredAMD(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("AuthenticAMD", nil, 0, nil),
	)

	status, err := CheckDiscreteTPMPartialResetAttackMitigationStatus(env, NewPCRBankResults(tpm2.HashAlgorithmSHA256, 0, [8]PcrResults{
		MakePCRResults(
			false,
			make(tpm2.Digest, 32),
			testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
			testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
			nil,
		),
	}))
	c.Check(err, IsNil)
	c.Check(status, Equals, DtpmPartialResetAttackMitigationNotRequired)
}

func (s *hostSecurityAMD64Suite) TestCheckDiscreteTPMPartialResetAttackMitigationStatusIntelNotDiscrete(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1)}),
	)

	status, err := CheckDiscreteTPMPartialResetAttackMitigationStatus(env, NewPCRBankResults(tpm2.HashAlgorithmSHA256, 0, [8]PcrResults{
		MakePCRResults(
			false,
			make(tpm2.Digest, 32),
			testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
			testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
			nil,
		),
	}))
	c.Check(err, IsNil)
	c.Check(status, Equals, DtpmPartialResetAttackMitigationNotRequired)
}

func (s *hostSecurityAMD64Suite) TestCheckDiscreteTPMPartialResetAttackMitigationStatusIntelUnavailableInvalidPCR0(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SMX}, 4, map[uint32]uint64{0x13a: (2 << 1)}),
	)

	status, err := CheckDiscreteTPMPartialResetAttackMitigationStatus(env, NewPCRBankResults(tpm2.HashAlgorithmSHA256, 3, [8]PcrResults{
		MakePCRResults(
			false,
			make(tpm2.Digest, 32),
			testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
			testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
			nil,
		),
	}))
	c.Check(err, IsNil)
	c.Check(status, Equals, DtpmPartialResetAttackMitigationUnavailable)
}

func (s *hostSecurityAMD64Suite) TestCheckDiscreteTPMPartialResetAttackMitigationStatusIntelPreferred(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SMX}, 4, map[uint32]uint64{0x13a: (2 << 1)}),
	)

	status, err := CheckDiscreteTPMPartialResetAttackMitigationStatus(env, NewPCRBankResults(tpm2.HashAlgorithmSHA256, 3, [8]PcrResults{
		MakePCRResults(
			false,
			make(tpm2.Digest, 32),
			testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
			testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
			nil,
		),
	}))
	c.Check(err, IsNil)
	c.Check(status, Equals, DtpmPartialResetAttackMitigationPreferred)
}

func (s *hostSecurityAMD64Suite) TestCheckDiscreteTPMPartialResetAttackMitigationStatusIntelUnavailableSL0(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineIntel", []uint64{cpuid.SMX}, 4, map[uint32]uint64{0x13a: (2 << 1)}),
	)

	status, err := CheckDiscreteTPMPartialResetAttackMitigationStatus(env, NewPCRBankResults(tpm2.HashAlgorithmSHA256, 0, [8]PcrResults{
		MakePCRResults(
			false,
			make(tpm2.Digest, 32),
			testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
			testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
			nil,
		),
	}))
	c.Check(err, IsNil)
	c.Check(status, Equals, DtpmPartialResetAttackMitigationUnavailable)
}

func (s *hostSecurityAMD64Suite) TestCheckDiscreteTPMPartialResetAttackMitigationStatusIntelUnavailableNoTXT(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineIntel", nil, 4, map[uint32]uint64{0x13a: (2 << 1)}),
	)

	status, err := CheckDiscreteTPMPartialResetAttackMitigationStatus(env, NewPCRBankResults(tpm2.HashAlgorithmSHA256, 3, [8]PcrResults{
		MakePCRResults(
			false,
			make(tpm2.Digest, 32),
			testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
			testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
			nil,
		),
	}))
	c.Check(err, IsNil)
	c.Check(status, Equals, DtpmPartialResetAttackMitigationUnavailable)
}

func (s *hostSecurityAMD64Suite) TestCheckDiscreteTPMPartialResetAttackMitigationStatusErrUnsupportedCpuVendor(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineInte", nil, 0, nil),
	)

	_, err := CheckDiscreteTPMPartialResetAttackMitigationStatus(env, NewPCRBankResults(tpm2.HashAlgorithmSHA256, 0, [8]PcrResults{}))
	c.Check(err, ErrorMatches, `unsupported platform: cannot determine CPU vendor: unknown CPU vendor: GenuineInte`)
	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
}
