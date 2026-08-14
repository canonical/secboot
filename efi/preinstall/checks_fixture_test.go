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

// Platform identity capabilities do not imply security properties. In
// particular, HasIntelBootGuard does not imply that any TPM startup locality is
// inaccessible from the OS; fixtures must declare locality properties
// separately.

// runChecksHostFixture abstracts host-specific details from scenario logic in
// the shared RunChecks and RunChecksContext tests.
type runChecksHostFixture struct {
	name                    string
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

// intelDevices builds the mock Intel MEI/IOMMU sysfs topology.
func intelDevices(status []byte, withIOMMU bool) []internal_efi.SysfsDevice {
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

func runChecksPlatformHostFixtures() []runChecksHostFixture {
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
	}
}
