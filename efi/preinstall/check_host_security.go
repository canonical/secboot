// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024-2026 Canonical Ltd
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
	"bytes"
	"errors"
	"fmt"
	"runtime"

	"github.com/canonical/tcglog-parser"
	"github.com/pilebones/go-udev/netlink"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// runtimeGOARCH is the architecture that host security checks are performed
// for. It is a variable so that tests can run the checks for architectures
// other than the one the test binary was built for.
var runtimeGOARCH = runtime.GOARCH

// discreteTPMPartialResetAttackMitigationStatus indicates whether a partial mitigation against
// discrete TPM reset attacks should be enabled. See the documentation for
// RequestPartialDiscreteTPMResetAttackMitigation
type discreteTPMPartialResetAttackMitigationStatus int

const (
	// dtpmPartialResetAttackMitigationUnknown indicates that it is not known if
	// partial mitigation is required, because of an error.
	dtpmPartialResetAttackMitigationUnknown discreteTPMPartialResetAttackMitigationStatus = iota

	// dtpmPartialResetAttackMitigationNotRequired indicates that no partial mitigation
	// is required.
	dtpmPartialResetAttackMitigationNotRequired

	// dtpmPartialResetAttackMitigationPreferred indicates that a partial mitigation
	// is desired.
	dtpmPartialResetAttackMitigationPreferred

	// dtpmPartialResetAttackMitigationUnavailable indicates that a partial
	// mitigation is desired but not possible.
	dtpmPartialResetAttackMitigationUnavailable
)

// platformFirmwareIntegrityConfig indicates how the root-of-trust provides
// assurances of the platform firmware integrity.
type platformFirmwareIntegrityConfig int

const (
	// platformFirmwareIntegrityNone indicates that no firmware integrity assurances
	// are provided.
	platformFirmwareIntegrityNone platformFirmwareIntegrityConfig = iota

	// platformFirmwareIntegrityMeasured indicates that firmware integrity is provided
	// by measured boot.
	platformFirmwareIntegrityMeasured

	// platformFirmwareIntegrityVerified indicates that firmware integrity is provided
	// by verifying it against a key that is fused into the platform.
	platformFirmwareIntegrityVerified
)

// checkForKernelIOMMU checks that the kernel has enabled some sort of DMA protection.
// On Intel devices, the domains are defined by the DMAR ACPI table. The check is quite
// simple, and based on the fwupd HSI checks. If it is not enabled, a [ErrNoKernelIOMMU]
// error is returned.
// XXX: Figure out whether this is genuinely sufficient, eg:
//   - Should we only mandate this if there are externally facing ports, or internal ports
//     that are accessible to the user
//   - Are all externally facing ports protected?
//   - Are internal ports accessible to the user protected?
//   - Are all addon devices with embedded controllers protected?
//
// This function is going to need some additional work later on.
func checkForKernelIOMMU(env internal_efi.HostEnvironment) error {
	devices, err := env.EnumerateDevices(&netlink.RuleDefinition{
		Env: map[string]string{
			"SUBSYSTEM": "iommu",
		},
	})
	switch {
	case err != nil:
		return err
	case len(devices) == 0:
		return ErrNoKernelIOMMU
	default:
		return nil
	}
}

// checkSecureBootPolicyPCRForDegradedFirmwareSettings checks PCR7 for the indication of degraded
// firmware settings:
//   - Whether a debugging endpoint is enabled, via the presence of a EV_EFI_ACTION event with the
//     "UEFI Debug Mode" string. This is defined in the TCG PC-Client PFP spec. If one is detected,
//     a [ErrUEFIDebuggingEnabled] error is returned, wrapped in [joinError].
//   - Whether DMA protection was disabled at some point, via the presence of a EV_EFI_ACTION event
//     with the "DMA Protection Disabled" string. This is a Windows requirement. If disabled, a
//     [ErrInsufficientDMAProtection] error is returned, wrapped in [joinError].
func checkSecureBootPolicyPCRForDegradedFirmwareSettings(log *tcglog.Log) error {
	var errs []error

	events := log.Events
Loop:
	for len(events) > 0 {
		// Pop next event
		event := events[0]
		events = events[1:]

		if event.PCRIndex != internal_efi.SecureBootPolicyPCR {
			continue
		}

		switch event.EventType {
		case tcglog.EventTypeEFIAction:
			switch {
			case event.Data == tcglog.FirmwareDebuggerEvent:
				// Debugger enabled
				errs = append(errs, ErrUEFIDebuggingEnabled)
			case event.Data == tcglog.DMAProtectionDisabled:
				// DMA protection was disabled bt the firmware at some point
				errs = append(errs, ErrInsufficientDMAProtection)
			case bytes.Equal(event.Data.Bytes(), append([]byte(tcglog.DMAProtectionDisabled), 0x00)):
				// XXX: My Dell NULL terminates this string which causes decoding to fail,
				//  as the TCG PC Client Platform Firmware Profile spec says that the event
				//  data in EV_EFI_ACTION events should not be NULL terminated.
				errs = append(errs, ErrInsufficientDMAProtection)
			}
		case tcglog.EventTypeEFIVariableAuthority:
			break Loop
		}
	}

	// We'll reach here if we encounter an EV_EFI_VARIABLE_AUTHORITY event or
	// we get to the end of the log.
	if len(errs) > 0 {
		return joinErrors(errs...)
	}
	return nil
}

// Architecture-specific host security checks are dispatched at runtime rather than
// selected by build constraints, so that all architectures' checks are compiled and
// testable everywhere.

// checkHostSecurity is the main entry point for verifying that the host security
// is sufficient. Errors that can't be resolved or which should prevent further checks from running
// are returned immediately and without any wrapping. Errors that can be resolved and which shouldn't
// prevent further checks from running are returned wrapped in [joinError].
func checkHostSecurity(env internal_efi.HostEnvironment, log *tcglog.Log) (platformFirmwareIntegrityConfig, error) {
	switch runtimeGOARCH {
	case "amd64":
		return checkHostSecurityAMD64(env, log)
	case "arm64":
		return checkHostSecurityARM64(env, log)
	default:
		return platformFirmwareIntegrityNone, &UnsupportedPlatformError{fmt.Errorf("checking host security is not implemented on %s", runtimeGOARCH)}
	}
}

// checkDiscreteTPMPartialResetAttackMitigationStatus determines whether a partial mitigation
// against discrete TPM reset attacks should be enabled. See the documentation for
// RequestPartialDiscreteTPMResetAttackMitigation.
func checkDiscreteTPMPartialResetAttackMitigationStatus(env internal_efi.HostEnvironment, logResults *pcrBankResults) (discreteTPMPartialResetAttackMitigationStatus, error) {
	switch runtimeGOARCH {
	case "amd64":
		return checkDiscreteTPMPartialResetAttackMitigationStatusAMD64(env, logResults)
	case "arm64":
		return checkDiscreteTPMPartialResetAttackMitigationStatusARM64(env, logResults)
	default:
		return dtpmPartialResetAttackMitigationNotRequired, nil
	}
}

func checkHostSecurityAMD64(env internal_efi.HostEnvironment, log *tcglog.Log) (platformFirmwareIntegrityConfig, error) {
	cpuVendor, err := determineCPUVendor(env)
	if err != nil {
		return platformFirmwareIntegrityNone, &UnsupportedPlatformError{fmt.Errorf("cannot determine CPU vendor: %w", err)}
	}

	amd64Env, err := env.AMD64()
	if err != nil {
		return platformFirmwareIntegrityNone, fmt.Errorf("cannot obtain AMD64 environment: %w", err)
	}

	var errs []error

	var integrity platformFirmwareIntegrityConfig
	switch cpuVendor {
	case cpuVendorIntel:
		if err := checkHostSecurityIntelBootGuard(env); err != nil {
			var nohwrotErr *NoHardwareRootOfTrustError
			ctxErr := fmt.Errorf("encountered an error when checking Intel BootGuard configuration: %w", err)
			if !errors.As(err, &nohwrotErr) {
				return platformFirmwareIntegrityNone, ctxErr
			}
			errs = append(errs, ctxErr)
		}
		if err := checkHostSecurityIntelCPUDebuggingLocked(amd64Env); err != nil {
			return platformFirmwareIntegrityNone, fmt.Errorf("encountered an error when checking Intel CPU debugging configuration: %w", err)
		}
		if len(errs) == 0 {
			integrity = platformFirmwareIntegrityVerified
		}
	case cpuVendorAMD:
		integrity, err = checkHostSecurityAMDPSP(env)
		if err != nil {
			ctxErr := fmt.Errorf("encountered an error when checking the AMD PSP configuration: %w", err)
			var nohwrotErr *NoHardwareRootOfTrustError
			if !errors.As(err, &nohwrotErr) {
				return platformFirmwareIntegrityNone, ctxErr
			}
			errs = append(errs, ctxErr)
		}
	default:
		panic("not reached")
	}

	if err := checkSecureBootPolicyPCRForDegradedFirmwareSettings(log); err != nil {
		var ce CompoundError
		if !errors.As(err, &ce) {
			return platformFirmwareIntegrityNone, fmt.Errorf("encountered an error whilst checking the TCG log for degraded firmware settings: %w", err)
		}
		errs = append(errs, ce.Unwrap()...)
	}
	if err := checkForKernelIOMMU(env); err != nil {
		switch {
		case errors.Is(err, ErrNoKernelIOMMU):
			errs = append(errs, err)
		default:
			return platformFirmwareIntegrityNone, fmt.Errorf("encountered an error whilst checking sysfs to determine that kernel IOMMU support is enabled: %w", err)
		}
	}

	if len(errs) > 0 {
		return platformFirmwareIntegrityNone, joinErrors(errs...)
	}

	return integrity, nil
}

func checkDiscreteTPMPartialResetAttackMitigationStatusAMD64(env internal_efi.HostEnvironment, logResults *pcrBankResults) (discreteTPMPartialResetAttackMitigationStatus, error) {
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

// checkHostSecurityARM64Platform selects the platform-specific firmware
// integrity check. Tests replace this to supply synthetic platforms.
var checkHostSecurityARM64Platform = func(env internal_efi.HostEnvironmentARM64, cpuManufacturer string) (platformFirmwareIntegrityConfig, error) {
	return platformFirmwareIntegrityNone, &UnsupportedPlatformError{fmt.Errorf("unsupported CPU manufacturer: %s", cpuManufacturer)}
}

func checkHostSecurityARM64(env internal_efi.HostEnvironment, log *tcglog.Log) (platformFirmwareIntegrityConfig, error) {
	arm64Env, err := env.ARM64()
	if err != nil {
		return platformFirmwareIntegrityNone, &UnsupportedPlatformError{fmt.Errorf("cannot obtain ARM64 environment: %w", err)}
	}

	cpuManufacturer, err := arm64Env.CPUManufacturer()
	if err != nil {
		return platformFirmwareIntegrityNone, &UnsupportedPlatformError{fmt.Errorf("cannot determine CPU manufacturer: %w", err)}
	}

	integrity, err := checkHostSecurityARM64Platform(arm64Env, cpuManufacturer)
	if err != nil {
		return platformFirmwareIntegrityNone, err
	}

	return checkHostSecurityARM64Generic(env, log, integrity)
}

func checkHostSecurityARM64Generic(env internal_efi.HostEnvironment, log *tcglog.Log, integrity platformFirmwareIntegrityConfig) (platformFirmwareIntegrityConfig, error) {
	var errs []error

	if err := checkSecureBootPolicyPCRForDegradedFirmwareSettings(log); err != nil {
		var ce CompoundError
		if !errors.As(err, &ce) {
			return platformFirmwareIntegrityNone, fmt.Errorf("encountered an error whilst checking the TCG log for degraded firmware settings: %w", err)
		}
		errs = append(errs, ce.Unwrap()...)
	}

	if err := checkForKernelIOMMU(env); err != nil {
		switch {
		case errors.Is(err, ErrNoKernelIOMMU):
			errs = append(errs, err)
		default:
			return platformFirmwareIntegrityNone, fmt.Errorf("encountered an error whilst checking sysfs to determine that kernel IOMMU support is enabled: %w", err)
		}
	}

	if len(errs) > 0 {
		return integrity, joinErrors(errs...)
	}

	return integrity, nil
}

// checkDiscreteTPMPartialResetAttackMitigationStatusARM64 determines whether a partial mitigation
// against discrete TPM reset attacks should be enabled.
func checkDiscreteTPMPartialResetAttackMitigationStatusARM64(env internal_efi.HostEnvironment, _ *pcrBankResults) (discreteTPMPartialResetAttackMitigationStatus, error) {
	discreteTPM, err := isTPMDiscrete(env)
	if err != nil {
		return dtpmPartialResetAttackMitigationUnknown, &TPM2DeviceError{err}
	}
	if !discreteTPM {
		return dtpmPartialResetAttackMitigationNotRequired, nil
	}

	// ARM64 has no generic mechanism to establish that the TPM startup locality
	// is protected by the hardware root of trust, so PCR0 binding cannot be relied
	// on to mitigate an independent reset of a discrete TPM.
	return dtpmPartialResetAttackMitigationUnavailable, nil
}
