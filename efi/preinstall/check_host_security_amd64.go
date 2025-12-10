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
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// checkHostSecurity is the main entry point for verifying that the host security
// is sufficient. Errors that can't be resolved or which should prevent further checks from running
// are returned immediately and without any wrapping. Errors that can be resolved and which shouldn't
// prevent further checks from running are returned wrapped in [joinError].
func checkHostSecurity(env internal_efi.HostEnvironment, log *tcglog.Log) error {
	cpuVendor, err := determineCPUVendor(env)
	if err != nil {
		return &UnsupportedPlatformError{fmt.Errorf("cannot determine CPU vendor: %w", err)}
	}

	amd64Env, err := env.AMD64()
	if err != nil {
		return fmt.Errorf("cannot obtain AMD64 environment: %w", err)
	}

	switch cpuVendor {
	case cpuVendorIntel:
		if err := checkHostSecurityIntelBootGuard(env); err != nil {
			return fmt.Errorf("encountered an error when checking Intel BootGuard configuration: %w", err)
		}
		if err := checkHostSecurityIntelCPUDebuggingLocked(amd64Env); err != nil {
			return fmt.Errorf("encountered an error when checking Intel CPU debugging configuration: %w", err)
		}
	case cpuVendorAMD:
		return &UnsupportedPlatformError{errors.New("checking host security is not yet implemented for AMD")}
	default:
		panic("not reached")
	}

	var errs []error

	if err := checkSecureBootPolicyPCRForDegradedFirmwareSettings(log); err != nil {
		var ce CompoundError
		if !errors.As(err, &ce) {
			return fmt.Errorf("encountered an error whilst checking the TCG log for degraded firmware settings: %w", err)
		}
		errs = append(errs, ce.Unwrap()...)
	}
	if err := checkForKernelIOMMU(env); err != nil {
		switch {
		case errors.Is(err, ErrNoKernelIOMMU):
			errs = append(errs, err)
		default:
			return fmt.Errorf("encountered an error whilst checking sysfs to determine that kernel IOMMU support is enabled: %w", err)
		}
	}

	if len(errs) > 0 {
		return joinErrors(errs...)
	}

	return nil
}

// checkDiscreteTPMPartialResetAttackMitigationStatus determines whether a partial mitigation
// against discrete TPM reset attacks should be enabled. See the documentation for
// RequestPartialDiscreteTPMResetAttackMitigation.
func checkDiscreteTPMPartialResetAttackMitigationStatus(env internal_efi.HostEnvironment, logResults *pcrBankResults) (discreteTPMPartialResetAttackMitigationStatus, error) {
	cpuVendor, err := determineCPUVendor(env)
	if err != nil {
		return dtpmPartialResetAttackMitigationUnknown, &UnsupportedPlatformError{fmt.Errorf("cannot determine CPU vendor: %w", err)}
	}

	if cpuVendor != cpuVendorIntel {
		// Only enable this on Intel systems.
		return dtpmPartialResetAttackMitigationNotRequired, nil
	}

	amd64Env, err := env.AMD64()
	if err != nil {
		return dtpmPartialResetAttackMitigationUnknown, fmt.Errorf("cannot obtain AMD64 environment: %w", err)
	}

	discreteTPM, err := isTPMDiscrete(env)
	if err != nil {
		return dtpmPartialResetAttackMitigationUnknown, &TPM2DeviceError{err}
	}

	switch {
	case !discreteTPM:
		// Not a discrete TPM.
		return dtpmPartialResetAttackMitigationNotRequired, nil
	case !logResults.Lookup(internal_efi.PlatformFirmwarePCR).Ok():
		// PCR0 is unusable.
		return dtpmPartialResetAttackMitigationUnavailable, nil
	}

	restrictedLocalities := restrictedTPMLocalitiesIntel(amd64Env)
	for _, locality := range restrictedLocalities.Values() {
		if locality == logResults.StartupLocality {
			// The startup locality is not available to the OS, so
			// we can enable the migitation because PCR0 cannot
			// be recreated from the OS.
			return dtpmPartialResetAttackMitigationPreferred, nil
		}
	}

	// The startup locality is available to the OS, so the mitigation
	// is unavailable even though it would have been desired because
	// PCR0 can be recreated from the OS.
	return dtpmPartialResetAttackMitigationUnavailable, nil
}
