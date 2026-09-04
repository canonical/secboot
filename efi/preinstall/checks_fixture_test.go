// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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
	. "github.com/snapcore/secboot/efi/preinstall"
	internal_efi "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	. "gopkg.in/check.v1"
)

type runChecksHostCapabilities uint32

const (
	runChecksHostCapabilityValid runChecksHostCapabilities = 1 << iota

	// Platform/runtime topology.
	runChecksHostCapabilityVirtualMachine
	runChecksHostCapabilityNotVirtualMachine
	runChecksHostCapabilityNoKernelIOMMU
	runChecksHostCapabilityFirmwareTPM
	runChecksHostCapabilityDiscreteTPM

	// Hardware security properties.
	runChecksHostCapabilityInsufficientHWRootOfTrust

	// Discrete-TPM locality properties.
	runChecksHostCapabilityStartupLocality0AccessibleFromOS
	runChecksHostCapabilityStartupLocality3InaccessibleFromOS
	runChecksHostCapabilityStartupLocality3AccessibleFromOS
	runChecksHostCapabilityStartupLocality4InaccessibleFromOS
	runChecksHostCapabilityStartupLocality4AccessibleFromOS
)

// runChecksHostFixture abstracts host-specific details from scenario logic in
// the shared RunChecks and RunChecksContext tests.
type runChecksHostFixture struct {
	name string
	// capabilities represent high level abstractions of one or more aspects of a host fixture
	// that tests can use to determine if the fixture meets the requirements for a given scenario.
	//
	// For example, a scenario that tests fTPM-specific behavior may fail when run on a fixture
	// with a dTPM. Depending on the level of the behavior being tested, this failure may not be
	// particularly meaningful, and it may make more sense for the test to only run on fixtures
	// that actually provide an fTPM.
	//
	// Capabilities simply summarize and label information encoded in other fields of the fixture.
	// Declaring a capability by itself does not instantiate any mock behaviors, and it is the
	// responsibility of the author to make sure that the capabilities are a faithful reflection
	// of the actual behavior of the fixture.
	capabilities            runChecksHostCapabilities
	environment             efitest.MockHostEnvironmentOption
	virtualizationMode      string
	virtualizationDetection internal_efi.DetectVirtMode
	sysfsDevices            []internal_efi.SysfsDevice

	// arch is the GOARCH that this fixture emulates; host security checks dispatch on it at runtime.
	arch string

	// additionalExpectedFlags allows a host fixture to inject fixture-specific
	// CheckResultFlags to the expected value. For example, platforms that validate
	// platformFirmwareIntegrity via measured boot instead of reading a fused key will
	// report RequireLockToPlatformFirmware, which needs to be OR'd against the
	// test-specific expected flags.
	additionalExpectedFlags CheckResultFlags
}

func runChecksHostFixturesFor(c *C, required runChecksHostCapabilities) []runChecksHostFixture {
	var matches []runChecksHostFixture
	for _, fixture := range runChecksPlatformHostFixtures() {
		if fixture.capabilities&required == required {
			matches = append(matches, fixture)
		}
	}
	if len(matches) == 0 {
		c.Skip("no platform fixture provides the required host capabilities")
	}
	return matches
}

func (f *runChecksHostFixture) newEnvironment(options ...efitest.MockHostEnvironmentOption) internal_efi.HostEnvironment {
	base := []efitest.MockHostEnvironmentOption{
		f.environment,
		efitest.WithVirtMode(f.virtualizationMode, f.virtualizationDetection),
	}
	devices := append([]internal_efi.SysfsDevice(nil), f.sysfsDevices...)
	base = append(base, efitest.WithSysfsDevices(devices...))
	return efitest.NewMockHostEnvironmentWithOpts(append(base, options...)...)
}

func (f *runChecksHostFixture) mockRuntimeGOARCH(s interface{ AddCleanup(func()) }) {
	s.AddCleanup(MockRuntimeGOARCH(f.arch))
}

const (
	exampleARM64CPUManufacturer = "Example Manufacturer"
	exampleARM64CPUVersion      = "Example OP-TEE SoC"
)

func init() {
	RegisterARM64TestPlatform(exampleARM64CPUManufacturer, exampleARM64CPUVersion)
}

func runChecksArm64TPMDevice(driver string) internal_efi.SysfsDevice {
	parent := efitest.NewMockSysfsDevice(
		"/sys/devices/platform/firmware-tpm",
		map[string]string{"DRIVER": driver},
		"platform",
		nil,
		nil,
	)

	return efitest.NewMockSysfsDevice(
		"/sys/devices/platform/firmware-tpm/tpm/tpm0",
		map[string]string{"DEVNAME": "tpm0"},
		"tpm",
		nil,
		parent,
	)
}

// runChecksPlatformHostFixtures returns an array of mock platform host configurations
// for testing. Each fixture can define an EFI environment with CPU features, a set of sysfs
// devices, virtualization information, and host ISA. Each fixture also includes a set of
// "capabilities" which can be used by tests to decide whether they should expect a
// certain fixture to work for a given test scenario or not.
//
// To add fixtures, append them to the array returned by this function. To add capabilities,
// add them to the const block at the top of this file and then audit the existing fixtures
// and add the new capability to any existing fixtures to which it might apply.
func runChecksPlatformHostFixtures() []runChecksHostFixture {
	intelDevices := func(status []byte, withIOMMU bool) []internal_efi.SysfsDevice {
		attrs := map[string][]byte{
			"fw_ver": []byte(`0:16.1.27.2176
0:16.1.27.2176
0:16.0.15.1624
`),
			"fw_status": status,
		}
		var devices []internal_efi.SysfsDevice
		if withIOMMU {
			devices = append(devices,
				efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar0", nil, "iommu", nil, nil),
				efitest.NewMockSysfsDevice("/sys/devices/virtual/iommu/dmar1", nil, "iommu", nil, nil),
			)
		}
		return append(devices, efitest.NewMockSysfsDevice("/sys/devices/pci0000:00/0000:00:16.0/mei/mei0", map[string]string{"DEVNAME": "mei0"}, "mei", attrs, efitest.NewMockSysfsDevice(
			"/sys/devices/pci0000:00:16:0", map[string]string{"DRIVER": "mei_me"}, "pci", nil, nil,
		)))
	}

	newDevices := func(tpmDriver string, withIOMMU bool) []internal_efi.SysfsDevice {
		devices := []internal_efi.SysfsDevice{runChecksArm64TPMDevice(tpmDriver)}
		if withIOMMU {
			devices = append([]internal_efi.SysfsDevice{efitest.NewMockSysfsDevice("/sys/devices/platform/smmu0", nil, "iommu", nil, nil)}, devices...)
		}
		return devices
	}

	return []runChecksHostFixture{
		// amd64 fixtures
		{
			name: "intel-ptt",
			capabilities: runChecksHostCapabilityValid |
				runChecksHostCapabilityNotVirtualMachine |
				runChecksHostCapabilityFirmwareTPM,
			environment:             efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{internal_efi.CPUIDFeatureSDBG, internal_efi.CPUIDFeatureSMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
			virtualizationMode:      internal_efi.VirtModeNone,
			virtualizationDetection: internal_efi.DetectVirtModeAll,
			sysfsDevices:            intelDevices(fwStatusBase, true),
			arch:                    "amd64",
		},
		{
			name: "intel-dtpm-smx",
			capabilities: runChecksHostCapabilityValid |
				runChecksHostCapabilityNotVirtualMachine |
				runChecksHostCapabilityDiscreteTPM |
				runChecksHostCapabilityStartupLocality0AccessibleFromOS |
				runChecksHostCapabilityStartupLocality3InaccessibleFromOS |
				runChecksHostCapabilityStartupLocality4InaccessibleFromOS,
			environment:             efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{internal_efi.CPUIDFeatureSDBG, internal_efi.CPUIDFeatureSMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (2 << 1)}),
			virtualizationMode:      internal_efi.VirtModeNone,
			virtualizationDetection: internal_efi.DetectVirtModeAll,
			sysfsDevices:            intelDevices(fwStatusBase, true),
			arch:                    "amd64",
		},
		{
			name: "intel-dtpm-no-smx",
			capabilities: runChecksHostCapabilityValid |
				runChecksHostCapabilityNotVirtualMachine |
				runChecksHostCapabilityDiscreteTPM |
				runChecksHostCapabilityStartupLocality0AccessibleFromOS |
				runChecksHostCapabilityStartupLocality3AccessibleFromOS |
				runChecksHostCapabilityStartupLocality4AccessibleFromOS,
			environment:             efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{internal_efi.CPUIDFeatureSDBG}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (2 << 1)}),
			virtualizationMode:      internal_efi.VirtModeNone,
			virtualizationDetection: internal_efi.DetectVirtModeAll,
			sysfsDevices:            intelDevices(fwStatusBase, true),
			arch:                    "amd64",
		},
		{
			name:                    "intel-ptt-no-kernel-iommu",
			capabilities:            runChecksHostCapabilityNotVirtualMachine | runChecksHostCapabilityNoKernelIOMMU | runChecksHostCapabilityFirmwareTPM,
			environment:             efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{internal_efi.CPUIDFeatureSDBG, internal_efi.CPUIDFeatureSMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
			virtualizationMode:      internal_efi.VirtModeNone,
			virtualizationDetection: internal_efi.DetectVirtModeAll,
			sysfsDevices:            intelDevices(fwStatusBase, false),
			arch:                    "amd64",
		},
		{
			name:                    "intel-mfg-mode",
			capabilities:            runChecksHostCapabilityNotVirtualMachine | runChecksHostCapabilityInsufficientHWRootOfTrust,
			environment:             efitest.WithAMD64Environment("GenuineIntel", 0x6, []uint64{internal_efi.CPUIDFeatureSDBG, internal_efi.CPUIDFeatureSMX}, 4, map[uint32]uint64{0xc80: 0x40000000, 0x13a: (3 << 1)}),
			virtualizationMode:      internal_efi.VirtModeNone,
			virtualizationDetection: internal_efi.DetectVirtModeAll,
			sysfsDevices:            intelDevices(fwStatusManufacturingMode, true),
			arch:                    "amd64",
		},
		// RunChecks skips host security checks inside a VM, so the emulated
		// architecture is irrelevant here; we keep exactly one virtual-machine
		// fixture rather than duplicating it per-arch.
		{
			name:                    "virtual-machine",
			capabilities:            runChecksHostCapabilityVirtualMachine,
			environment:             func(*efitest.MockHostEnvironment) {},
			virtualizationMode:      "qemu",
			virtualizationDetection: internal_efi.DetectVirtModeVM,
			arch:                    "amd64",
		},
		// arm64 fixtures
		{
			name: "example-arm64-optee-ftpm",
			capabilities: runChecksHostCapabilityValid |
				runChecksHostCapabilityNotVirtualMachine |
				runChecksHostCapabilityFirmwareTPM,
			environment:             efitest.WithARM64Environment(exampleARM64CPUManufacturer, exampleARM64CPUVersion),
			virtualizationMode:      internal_efi.VirtModeNone,
			virtualizationDetection: internal_efi.DetectVirtModeAll,
			sysfsDevices:            newDevices("optee-ftpm", true),
			additionalExpectedFlags: RequireLockToPlatformFirmware,
			arch:                    "arm64",
		},
		{
			name:                    "example-arm64-optee-ftpm-no-kernel-iommu",
			capabilities:            runChecksHostCapabilityNotVirtualMachine | runChecksHostCapabilityNoKernelIOMMU | runChecksHostCapabilityFirmwareTPM,
			environment:             efitest.WithARM64Environment(exampleARM64CPUManufacturer, exampleARM64CPUVersion),
			virtualizationMode:      internal_efi.VirtModeNone,
			virtualizationDetection: internal_efi.DetectVirtModeAll,
			sysfsDevices:            newDevices("optee-ftpm", false),
			additionalExpectedFlags: RequireLockToPlatformFirmware,
			arch:                    "arm64",
		},
	}
}
