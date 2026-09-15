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

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityIntelGood(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": fwStatusBase,
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
		efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	integrity, err := CheckHostSecurity(env, log)
	c.Check(err, IsNil)
	c.Check(integrity, Equals, PlatformFirmwareIntegrityVerified)
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityErrNotAMD64(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts()

	_, err := CheckHostSecurity(env, nil)
	c.Check(err, ErrorMatches, `unsupported platform: cannot determine CPU vendor: not a AMD64 host`)

	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityAMDGoodVerified(c *C) {
	pspAttrs := map[string][]byte{
		"boot_integrity": []byte(`1
`),
		"debug_lock_on": []byte(`1
`),
		"fused_part": []byte(`1
`),
	}
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", pspAttrs, nil),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices...),
		efitest.WithAMD64Environment("AuthenticAMD", 0x1a, nil, 0, nil),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	integrity, err := CheckHostSecurity(env, log)
	c.Check(err, IsNil)
	c.Check(integrity, Equals, PlatformFirmwareIntegrityVerified)
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityAMDGoodMeasured(c *C) {
	pspAttrs := map[string][]byte{
		"boot_integrity": []byte(`0
`),
		"debug_lock_on": []byte(`1
`),
		"fused_part": []byte(`1
`),
	}
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", pspAttrs, nil),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices...),
		efitest.WithAMD64Environment("AuthenticAMD", 0x1a, nil, 0, nil),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	integrity, err := CheckHostSecurity(env, log)
	c.Check(err, IsNil)
	c.Check(integrity, Equals, PlatformFirmwareIntegrityMeasured)
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityErrUnrecognizedCpuVendor(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("GenuineInte", 0x6, nil, 0, nil),
	)

	_, err := CheckHostSecurity(env, nil)
	c.Check(err, ErrorMatches, `unsupported platform: cannot determine CPU vendor: unknown CPU vendor: GenuineInte`)

	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityIntelErrMEI(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": fwStatusManufacturingMode,
	}
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices...),
		efitest.WithAMD64Environment("GenuineIntel", 0x6, nil, 0, nil),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})
	_, err := CheckHostSecurity(env, log)
	c.Check(err, ErrorMatches, `encountered an error when checking Intel BootGuard configuration: no hardware root-of-trust properly configured: system is in manufacturing mode`)

	// Check that there is a NoHardwareRootOfTrustError
	// While with go1.23 errors.As() can unwrap automatically, with go1.18 we need to unwrap manually.
	var nhrotErr *NoHardwareRootOfTrustError
	var cErr CompoundError
	c.Check(errors.As(err, &cErr), testutil.IsTrue)
	foundNhrot := false
	for _, e := range cErr.Unwrap() {
		if errors.As(e, &nhrotErr) {
			foundNhrot = true
		}
	}
	c.Check(foundNhrot, testutil.IsTrue)
	c.Check(nhrotErr, ErrorMatches, `no hardware root-of-trust properly configured: system is in manufacturing mode`)
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityAMDErrPSP(c *C) {
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:08.1/0000:c1:00.2", map[string]string{"DRIVER": "ccp"}, "pci", nil, nil),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices...),
		efitest.WithAMD64Environment("AuthenticAMD", 0x1a, nil, 0, nil),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	_, err := CheckHostSecurity(env, log)
	c.Check(err, ErrorMatches, `encountered an error when checking the AMD PSP configuration: no hardware root-of-trust properly configured: PSP security reporting not available`)

	// Check that there is a NoHardwareRootOfTrustError
	// While with go1.23 errors.As() can unwrap automatically, with go1.18 we need to unwrap manually.
	var nhrotErr *NoHardwareRootOfTrustError
	var cErr CompoundError
	c.Check(errors.As(err, &cErr), testutil.IsTrue)
	foundNhrot := false
	for _, e := range cErr.Unwrap() {
		if errors.As(e, &nhrotErr) {
			foundNhrot = true
		}
	}
	c.Check(foundNhrot, testutil.IsTrue)
	c.Check(nhrotErr, ErrorMatches, `no hardware root-of-trust properly configured: PSP security reporting not available`)
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecuritySecureBootPolicyFirmwareDebugging(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": fwStatusBase,
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
		efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})

	_, err := CheckHostSecurity(env, log)
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
		"fw_status": fwStatusBase,
	}
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices...),
		efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	_, err := CheckHostSecurity(env, log)
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
		"fw_status": fwStatusBase,
	}
	devices := []internal_efi.SysfsDevice{
		efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", meiAttrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)),
	}
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithSysfsDevices(devices...),
		efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{cpuid.SDBG, cpuid.SMX}, 4, map[uint32]uint64{0xc80: 0x40000000}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{FirmwareDebugger: true})

	_, err := CheckHostSecurity(env, log)
	c.Check(err, ErrorMatches, `2 errors detected:
- the platform firmware contains a debugging endpoint enabled
- no kernel IOMMU support was detected
`)
	var tmpl CompoundError
	c.Assert(err, Implements, &tmpl)
	c.Check(err.(CompoundError).Unwrap(), DeepEquals, []error{ErrUEFIDebuggingEnabled, ErrNoKernelIOMMU})
}

func (s *hostSecurityAMD64Suite) TestCheckHostSecurityIntelErrCPUDebuggingUnlocked(c *C) {
	meiAttrs := map[string][]byte{
		"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
		"fw_status": fwStatusBase,
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
		efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{cpuid.SDBG}, 4, map[uint32]uint64{0xc80: 0x0}),
	)
	log := efitest.NewLog(c, &efitest.LogOptions{})

	_, err := CheckHostSecurity(env, log)
	c.Check(err, ErrorMatches, `encountered an error when checking Intel CPU debugging configuration: CPU debugging features are not disabled and locked`)
	c.Check(errors.Is(err, ErrCPUDebuggingNotLocked), testutil.IsTrue)
}

func (s *hostSecurityAMD64Suite) TestCheckDiscreteTPMPartialResetAttackMitigationStatusNotRequiredAMD(c *C) {
	env := efitest.NewMockHostEnvironmentWithOpts(
		efitest.WithAMD64Environment("AuthenticAMD", 0x1a, nil, 0, nil),
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
		efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{cpuid.SMX}, 4, map[uint32]uint64{0x13a: (3 << 1)}),
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
		efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{cpuid.SMX}, 4, map[uint32]uint64{0x13a: (2 << 1)}),
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
		efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{cpuid.SMX}, 4, map[uint32]uint64{0x13a: (2 << 1)}),
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
		efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{cpuid.SMX}, 4, map[uint32]uint64{0x13a: (2 << 1)}),
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
		efitest.WithAMD64Environment("GenuineIntel", 0x6, nil, 4, map[uint32]uint64{0x13a: (2 << 1)}),
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
		efitest.WithAMD64Environment("GenuineInte", 0x6, nil, 0, nil),
	)

	_, err := CheckDiscreteTPMPartialResetAttackMitigationStatus(env, NewPCRBankResults(tpm2.HashAlgorithmSHA256, 0, [8]PcrResults{}))
	c.Check(err, ErrorMatches, `unsupported platform: cannot determine CPU vendor: unknown CPU vendor: GenuineInte`)
	var upe *UnsupportedPlatformError
	c.Check(errors.As(err, &upe), testutil.IsTrue)
}

func (s *hostSecurityAMD64Suite) TestDetectAMDPreOSMeasurementConfig(c *C) {
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

func (s *hostSecurityAMD64Suite) TestDetectAMDPreOSMeasurementConfigWithoutHPMeasurement(c *C) {
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

func (s *hostSecurityAMD64Suite) TestDetectAMDPreOSMeasurementConfigMissingTSMEStatus(c *C) {
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

func (s *hostSecurityAMD64Suite) TestDetectAMDPreOSMeasurementConfigRejectsUnsupportedMeasuredHPConfig(c *C) {
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
