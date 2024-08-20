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

	"github.com/canonical/go-tpm2"
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
func checkPlatformFirmwareProtections(env internal_efi.HostEnvironment, log *tcglog.Log) (protectedStartupLocalities tpm2.Locality, err error) {
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
			// The Intel TXT spec says that locality 4 is basically only available
			// to microcode, and is locked before handing over to an ACM which
			// has access to locality 3. Access to this is meant to be locked at the
			// hardware level before running non-Intel code, although I'm not sure if
			// this is only relevant in the D-CRTM case where the SINIT ACM has access
			// to locality 3, and it locks access to it, leaving access to localities 2
			// and 1 to the measured launch environment and dynamic OS respectively. We
			// rely on the property of localities 3 and 4 being protected somewhat in order
			// to attempt to mitigate discrete TPM reset attacks on Intel platforms (basically
			// by including PCR0 in the policy, even though it's otherwise useless to include
			// it, but locality 3 or 4 access is required in order to reconstruct PCR0 after a
			// TPM reset. Mark localities 3 and 4 as protected if we have the right instructions
			// for implementing a D-CRTM with Intel TXT (which I think is SMX).
			protectedStartupLocalities |= tpm2.LocalityThree | tpm2.LocalityFour
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

	return protectedStartupLocalities, nil
}
