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

package preinstall

import (
	"errors"
	"fmt"

	"github.com/canonical/tcglog-parser"
	"github.com/intel-go/cpuid"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

const (
	ia32DebugInterfaceMSR = 0xc80

	ia32DebugEnable uint64 = 1 << 0
	ia32DebugLock   uint64 = 1 << 30
)

func checkCPUDebuggingLockedMSR(env internal_efi.HostEnvironmentAMD64) error {
	// Check for "Silicon Debug Interface", returned in bit 11 of %ecx when calling
	// cpuid with %eax=1.
	debugSupported := env.HasCPUIDFeature(cpuid.SDBG)
	if !debugSupported {
		return nil
	}

	vals, err := env.ReadMSRs(ia32DebugInterfaceMSR)
	if err != nil {
		return err
	}
	if len(vals) == 0 {
		return errors.New("no MSR values returned")
	}

	for _, val := range vals {
		if val&ia32DebugEnable > 0 || val&ia32DebugLock == 0 {
			return ErrCPUDebuggingNotLocked
		}
	}

	return nil
}

type cpuVendor int

const (
	cpuVendorUnknown cpuVendor = iota
	cpuVendorIntel
	cpuVendorAMD
)

func determineCPUVendor(env internal_efi.HostEnvironmentAMD64) (cpuVendor, error) {
	switch env.CPUVendorIdentificator() {
	case "GenuineIntel":
		return cpuVendorIntel, nil
	case "AuthenticAMD":
		return cpuVendorAMD, nil
	default:
		return cpuVendorUnknown, fmt.Errorf("unknown CPU vendor: %s", env.CPUVendorIdentificator())
	}
}

// checkPlatformFirmwareProtections is the main entry point for verifying that platform firmware
// protections are sufficient.
func checkPlatformFirmwareProtections(env internal_efi.HostEnvironment, log *tcglog.Log) (result platformFirmwareProtectionsResultFlags, err error) {
	amd64Env, err := env.AMD64()
	if err != nil {
		return 0, fmt.Errorf("cannot obtain AMD64 environment: %w", err)
	}

	cpuVendor, err := determineCPUVendor(amd64Env)
	if err != nil {
		return 0, fmt.Errorf("cannot determine CPU vendor: %w", err)
	}

	switch cpuVendor {
	case cpuVendorIntel:
		if err := checkPlatformFirmwareProtectionsIntelMEI(env); err != nil {
			return 0, fmt.Errorf("encountered an error when determining platform firmware protections using Intel MEI: %w", err)
		}
		if amd64Env.HasCPUIDFeature(cpuid.SMX) {
			// The Intel TXT spec says that locality 3 is only available to ACMs
			result |= platformFirmwareProtectionsTPMLocality3IsProtected
		}
	case cpuVendorAMD:
		return 0, &UnsupportedPlatformError{errors.New("checking platform firmware protections is not yet implemented for AMD")}
	default:
		panic("not reached")
	}

	if err := checkSecureBootPolicyPCRForDegradedFirmwareSettings(log); err != nil {
		return 0, fmt.Errorf("encountered an error whilst checking the TCG log for degraded firmware settings: %w", err)
	}
	if err := checkForKernelIOMMU(env); err != nil {
		return 0, fmt.Errorf("encountered an error whilst checking sysfs to determine that kernel IOMMU support is enabled: %w", err)
	}
	if err := checkCPUDebuggingLockedMSR(amd64Env); err != nil {
		return 0, fmt.Errorf("encountered an error when determining CPU debugging configuration from MSRs: %w", err)
	}

	return result, nil
}
