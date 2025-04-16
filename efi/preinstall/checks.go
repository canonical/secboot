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
	"context"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	secboot_efi "github.com/snapcore/secboot/efi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// CheckFlags can be used to customize the behaviour or [RunChecks] and [NewRunChecksContext].
type CheckFlags int

const (
	// CheckFlagsDefault is the default flags for RunChecks and
	// NewRunChecksContext if no other flags are supplied.
	CheckFlagsDefault CheckFlags = 0

	// PlatformFirmwareProfileSupportRequired indicates that support for
	// [secboot_efi.WithPlatformFirmwareProfile] to generate profiles for
	// PCR 0 is not optional.
	PlatformFirmwareProfileSupportRequired CheckFlags = 1 << iota

	// PlatformConfigProfileSupportRequired indicates that support for
	// generating profiles for PCR 1 is not optional.
	//
	// Note that this currently is not supported by the
	// [github.com/snapcore/secboot/efi] package.
	PlatformConfigProfileSupportRequired

	// DriversAndAppsProfileSupportRequired indicates that support for
	// [secboot_efi.WithDriversAndAppsProfile] to generate profiles for
	// PCR 2 is not optional.
	DriversAndAppsProfileSupportRequired

	// DriversAndAppsConfigProfileSupportRequired indicates that support
	// for generating profiles for PCR 3 is not optional.
	//
	// Note that this currently is not supported by the
	// [github.com/snapcore/secboot/efi] package.
	DriversAndAppsConfigProfileSupportRequired

	// BootManagerCodeProfileSupportRequired indicates that support for
	// [secboot_efi.WithBootManagerCodeProfile] to generate profiles for
	// PCR 4 is not optional.
	BootManagerCodeProfileSupportRequired

	// BootManagerConfigProfileSupportRequired indicates that support
	// for generating profiles for PCR 5 is not optional.
	//
	// Note that this currently is not supported by the
	// [github.com/snapcore/secboot/efi] package.
	BootManagerConfigProfileSupportRequired

	// SecureBootPolicyProfileSupportRequired indicates that support for
	// [secboot_efi.WithSecureBootPolicyProfile] to generate profiles for
	// PCR 7 is not optional.
	SecureBootPolicyProfileSupportRequired

	// PermitWeakPCRBanks permits selecting a weak PCR algorithm if
	// no other valid ones are available. This currently only includes
	// SHA1. Without this, RunChecks will only test for SHA2-512, SHA2-384,
	// and SHA2-256.
	PermitWeakPCRBanks

	// PostInstallChecks indicates that the tests are being executed
	// post-install as opposed to pre-install.
	PostInstallChecks

	// PermitVirtualMachine will prevent RunChecks from returning an error if the
	// code is detected to be running in a virtual machine. As parts of the TCB, such
	// as the initial firmware code and the vTPM implementation are under control of
	// the host environment and there isn't a proper hardware root-of-trust, this
	// configuration offers little benefit, but may be useful for testing - particularly
	// in CI environments. If a virtual machine is detected, the checks for platform
	// firmware protections are skipped entirely.
	PermitVirtualMachine

	// PermitNoDiscreteTPMResetMitigation will prevent RunChecks from returning an error
	// if a discrete TPM is detected and the TPM startup locality is accessible from ring
	// 0 code (platform firmware and privileged OS code), which prevents the ability to
	// enable a mitigation against reset attacks. See the description of the
	// DiscreteTPMDetected flag for more details.
	PermitNoDiscreteTPMResetMitigation

	// PermitVARSuppliedDrivers will prevent RunChecks from returning an error if the
	// platform is running any value-added-retailer supplied drivers, which are included in
	// a PCR policy when using [secboot_efi.WithDriversAndAppsProfile]. These can be loaded
	// by BDS by the presence of "Driver####" variables containing load options and a
	// "DriverOrder" variable, or automatically if the firmware finds a PE image in the ROM
	// of a connected PCI device (a so-called option ROM).
	PermitVARSuppliedDrivers

	// PermitSysPrepApplications will prevent RunChecks from returning an error if the
	// platform boot contained any system preparation applications, which are included in
	// a PCR policy when using [secboot_efi.WithBootManagerCodeProfile]. These may increase
	// fragility of PCR4 values if they are outside of the control of the OS. These are
	// loaded by BDS by the presence of "SysPrep####" variables containing load options and
	// a "SysPrepOrder" variable.
	PermitSysPrepApplications

	// PermitAbsoluteComputrace will prevent RunChecks from returning an error if the presence
	// of a component of Absolute is detected to be executing before the operating system. The
	// presence of this is included in profiles that use [secboot_efi.WithBootManagerCodeProfile].
	// In general, it is better to disable this component entirely.
	PermitAbsoluteComputrace

	// PermitNotVerifyingAllBootManagerCodeDigests permits the checks for
	// [secboot_efi.WithBootManagerCodeProfile] to not verify all of the EV_EFI_BOOT_SERVICES_APPLICATION
	// digests that appear in the log to ensure that they contain an Authenticode digest that matches a
	// boot component associated with the current boot. Note that the checks must at least verify the
	// first OS component, so the location of this must be supplied to RunChecks. This isn't generally
	// advisable - the results of testing are more accurate if the caller to RunChecks supplies the
	// sequence of all EFI applications that executed before ExitBootServices for the current boot.
	PermitNotVerifyingAllBootManagerCodeDigests

	// PermitWeakSecureBootAlgorithms will prevent RunChecks from returning an error if any secure boot
	// verification events on the current boot indicate the presence of weak algorithms, such as
	// authenticating a binary with SHA1, or a CA with a 1024-bit RSA public key, or the signer of the
	// initial boot loader having a 1024-bit RSA public key. This does have some limitations because the
	// log doesn't indicate the properties of the actual signing certificate or the algorithms used to
	// sign each binary, so it's not possible to determine whether signing certificates for non-OS
	// components are strong enough.
	//
	// It is generally a bad idea to use this flag.
	PermitWeakSecureBootAlgorithms

	// PermitPreOSVerificationUsingDigests will prevent RunChecks from returning an error if any pre-OS
	// secure boot verifications use a type other than a X.509 certificate. The use of Authenticode digests
	// in db make profiles that use [secboot_efi.WithSecureBootPolicyProfile] inherently fragile with
	// regards to firmware updates because db has to be changed accordingly each time, so this is not
	// advisable.
	PermitPreOSVerificationUsingDigests

	// PermitEmptyPCRBanks will prevent RunChecks from returning an error if there are any PCR banks
	// (those are PCR banks that are enabled but which firmware doesn't perform measurements to). This
	// is generally ok for full-disk encryption, but completely breaks the remote attestation model
	// because it allows an adversary to trivially spoof an entire trusted platform from software.
	PermitEmptyPCRBanks
)

var (
	runChecksEnv internal_efi.HostEnvironment = internal_efi.DefaultEnv
)

// RunChecks performs checks on the current host environment in order to determine if it's suitable for FDE.
// This is only intended to work on EFI systems. The supplied context is used as the parent context to which
// to attach the backend for reading from EFI variables. The behaviour can be customized by the supplied flags.
// For [secboot_efi.WithBootManagerCodeProfile] and [secboot_efi.WithSecureBootPolicyProfile] support, the
// caller must supply at least the initial boot loader for the current boot via loadedImages, although note
// that [secboot_efi.WithBootManagerCodeProfile] also requires the secondary boot loader to be supplied to. It
// is best to supply all images that executed before ExitBootServices, in the correct order.
//
// This can return many types of errors. Some errors may be returned immediately, such as
// [ErrVirtualMachineDetected], *[TPM2DeviceError] and *[MeasuredBootError]. Other errors aren't returned
// immediately and instead are collected whilst the checks continue to execute, and are returned wrapped in
// a type that implements [CompoundError]. Errors that are associated with a specific PCR will be returned
// wrapped in one of the PCR-specific error types: [PlatformFirmwarePCRError] (0), [PlatformConfigPCRError] (1),
// [DriversAndAppsPCRError] (2), [DriversAndAppsConfigPCRError] (3), [BootManagerCodePCRError] (4),
// [BootManagerConfigPCRError] (5), or [SecureBootPolicyPCRError] (7).
//
// Success doesn't guarantee that it's possible to select a safe combination of profiles for sealing - the
// returned CheckResult must be supplied to [WithAutoTCGPCRProfile] along with a [PCRProfileOptionsFlags]
// which is intended for user customization im order to automatically select an appropriate combination of
// profiles for sealing, and this can still fail.
func RunChecks(ctx context.Context, flags CheckFlags, loadedImages []secboot_efi.Image) (result *CheckResult, err error) {
	var (
		deferredErrs []error // Errors to return at the end of this function
		warnings     []error // Warnings to return via CheckResult at the end of the function
	)
	result = new(CheckResult)

	virtMode, err := detectVirtualization(runChecksEnv)
	if err != nil {
		return nil, fmt.Errorf("cannot detect virtualization mode: %w", err)
	}
	switch {
	case virtMode == detectVirtNone:
		// ok - not virtualized
	case virtMode == detectVirtVM && flags&PermitVirtualMachine == 0:
		// VM detected and not permitted
		return nil, ErrVirtualMachineDetected
	case virtMode == detectVirtVM:
		// VM detected and permitted. Note that we are running in a VM.
		result.Flags |= RunningInVirtualMachine
	default:
		panic("not reached")
	}

	var checkTPMFlags checkTPM2DeviceFlags
	if virtMode == detectVirtVM {
		checkTPMFlags |= checkTPM2DeviceInVM
	}
	if flags&PostInstallChecks > 0 {
		checkTPMFlags |= checkTPM2DevicePostInstall
	}
	tpm, err := openAndCheckTPM2Device(runChecksEnv, checkTPMFlags)
	if err != nil {
		var ce CompoundError
		if !errors.As(err, &ce) {
			// Return this error immediately.
			return nil, &TPM2DeviceError{err}
		}
		for _, e := range ce.Unwrap() {
			deferredErrs = append(deferredErrs, &TPM2DeviceError{e})
		}
	}
	defer tpm.Close()

	// Grab the TCG log.
	log, err := runChecksEnv.ReadEventLog()
	if err != nil {
		return nil, &MeasuredBootError{err}
	}

	// Build a list of mandatory PCRs based on the supplied flags. The call to
	// checkFirmwareLogAndChoosePCRBank will return an error if any of these PCRs
	// are inconsistent with the reconstructed log.
	var mandatoryPcrs tpm2.HandleList
	if flags&PlatformFirmwareProfileSupportRequired > 0 {
		mandatoryPcrs = append(mandatoryPcrs, internal_efi.PlatformFirmwarePCR)
	}
	if flags&PlatformConfigProfileSupportRequired > 0 {
		mandatoryPcrs = append(mandatoryPcrs, internal_efi.PlatformConfigPCR)
	}
	if flags&DriversAndAppsProfileSupportRequired > 0 {
		mandatoryPcrs = append(mandatoryPcrs, internal_efi.DriversAndAppsPCR)
	}
	if flags&DriversAndAppsConfigProfileSupportRequired > 0 {
		mandatoryPcrs = append(mandatoryPcrs, internal_efi.DriversAndAppsConfigPCR)
	}
	if flags&BootManagerCodeProfileSupportRequired > 0 {
		mandatoryPcrs = append(mandatoryPcrs, internal_efi.BootManagerCodePCR)
	}
	if flags&BootManagerConfigProfileSupportRequired > 0 {
		mandatoryPcrs = append(mandatoryPcrs, internal_efi.BootManagerConfigPCR)
	}
	if flags&SecureBootPolicyProfileSupportRequired > 0 {
		mandatoryPcrs = append(mandatoryPcrs, internal_efi.SecureBootPolicyPCR)
	}

	var checkLogFlags checkFirmwareLogFlags
	if flags&PermitEmptyPCRBanks > 0 {
		checkLogFlags |= checkFirmwareLogPermitEmptyPCRBanks
	}
	if flags&PermitWeakPCRBanks > 0 {
		checkLogFlags |= checkFirmwareLogPermitWeakPCRBanks
	}

	logResults, err := checkFirmwareLogAndChoosePCRBank(tpm, log, mandatoryPcrs, checkLogFlags)
	switch {
	case tpm2.IsTPMError(err, tpm2.AnyErrorCode, tpm2.AnyCommandCode) ||
		tpm2.IsTPMWarning(err, tpm2.AnyWarningCode, tpm2.AnyCommandCode) ||
		isInvalidTPMResponse(err) || isTPMCommunicationError(err):
		return nil, &TPM2DeviceError{err}
	case isEmptyPCRBanksError(err):
		// Save this error and return it unwrapped when the checks complete
		deferredErrs = append(deferredErrs, err)
	case err != nil:
		return nil, &MeasuredBootError{err}
	}

	// Record the chosen PCR algorithm.
	result.PCRAlg = logResults.Alg

	// Record errors for non-mandatory PCRs as warnings.
	for pcr, err := range logResults.pcrErrs() {
		err = wrapPCRError(pcr, err)
		switch pcr {
		case 0:
			result.Flags |= NoPlatformFirmwareProfileSupport
		case 1:
			result.Flags |= NoPlatformConfigProfileSupport
		case 2:
			result.Flags |= NoDriversAndAppsProfileSupport
		case 3:
			result.Flags |= NoDriversAndAppsConfigProfileSupport
		case 4:
			result.Flags |= NoBootManagerCodeProfileSupport
		case 5:
			result.Flags |= NoBootManagerConfigProfileSupport
		case 7:
			result.Flags |= NoSecureBootPolicyProfileSupport
		}
		warnings = append(warnings, err)
	}

	discreteTPM := false

	if virtMode == detectVirtNone {
		// Only run host security checks if we are not in a VM
		protectedLocalities, err := checkHostSecurity(runChecksEnv, log)
		if err != nil {
			var ce CompoundError
			if !errors.As(err, &ce) {
				return nil, &HostSecurityError{err}
			}
			for _, e := range ce.Unwrap() {
				deferredErrs = append(deferredErrs, &HostSecurityError{e})
			}
		}

		discreteTPM, err = isTPMDiscrete(runChecksEnv)
		if err != nil {
			return nil, &TPM2DeviceError{err}
		}

		if discreteTPM {
			switch logResults.StartupLocality {
			case 0:
				// TPM2_Startup occurred from locality 0. Mark PCR0 as reconstructible
				// from anything that runs as part of the static OS (only applicable to
				// discrete TPMs that can be reset independently of the host CPU, which
				// isn't really meant to be possible).
				switch {
				case flags&PermitNoDiscreteTPMResetMitigation > 0:
					result.Flags |= StartupLocalityNotProtected
				default:
					deferredErrs = append(deferredErrs, &HostSecurityError{ErrTPMStartupLocalityNotProtected})
				}
			case 3:
				// TPM2_Startup occurred from locality 3. Mark PCR0 as reconstructible
				// from anything that runs as part of the static OS for the reasons stated
				// above if access to locality 3 isn't protected.
				switch {
				case protectedLocalities&tpm2.LocalityThree == 0 && flags&PermitNoDiscreteTPMResetMitigation > 0:
					result.Flags |= StartupLocalityNotProtected
				case protectedLocalities&tpm2.LocalityThree == 0:
					deferredErrs = append(deferredErrs, &HostSecurityError{ErrTPMStartupLocalityNotProtected})
				}
			case 4:
				// There were H-CRTM events.  Mark PCR0 as reconstructible from anything that
				// runs as part of the static OS for the reasons stated above if access to
				// locality 4 isn't protected.
				switch {
				case protectedLocalities&tpm2.LocalityFour == 0 && flags&PermitNoDiscreteTPMResetMitigation > 0:
					result.Flags |= StartupLocalityNotProtected
				case protectedLocalities&tpm2.LocalityFour == 0:
					deferredErrs = append(deferredErrs, &HostSecurityError{ErrTPMStartupLocalityNotProtected})
				}
			}
		}
	}

	if discreteTPM {
		// Note that a discrete TPM was detected.
		result.Flags |= DiscreteTPMDetected
	}

	if logResults.Lookup(internal_efi.PlatformConfigPCR).Ok() {
		// PCR1 profiles are not supported yet.
		err := &PlatformConfigPCRError{errors.New("generating profiles for PCR 1 is not supported yet")}
		switch {
		case flags&PlatformConfigProfileSupportRequired > 0:
			deferredErrs = append(deferredErrs, err)
		default:
			result.Flags |= NoPlatformConfigProfileSupport
			warnings = append(warnings, err)
		}
	}

	if logResults.Lookup(internal_efi.DriversAndAppsPCR).Ok() {
		// Only run PCR2 checks if we established earlier that the PCR value matches
		// the reconstructed log value.
		pcr2Results := checkDriversAndAppsMeasurements(log)
		switch {
		case pcr2Results == driversAndAppsPresent && flags&PermitVARSuppliedDrivers == 0:
			deferredErrs = append(deferredErrs, ErrVARSuppliedDriversPresent)
		case pcr2Results == driversAndAppsPresent:
			result.Flags |= VARDriversPresent
		}
	}

	if logResults.Lookup(internal_efi.DriversAndAppsConfigPCR).Ok() {
		// PCR3 profiles are not supported yet
		err := &DriversAndAppsConfigPCRError{errors.New("generating profiles for PCR 3 is not supported yet")}
		switch {
		case flags&DriversAndAppsConfigProfileSupportRequired > 0:
			deferredErrs = append(deferredErrs, err)
		default:
			result.Flags |= NoDriversAndAppsConfigProfileSupport
			warnings = append(warnings, err)
		}
	}

	if logResults.Lookup(internal_efi.BootManagerCodePCR).Ok() {
		// Only run PCR4 checks if we established earlier that the PCR value matches
		// the reconstructed log value.
		pcr4Result, err := checkBootManagerCodeMeasurements(ctx, runChecksEnv, log, result.PCRAlg, loadedImages)
		switch {
		case err != nil && flags&BootManagerCodeProfileSupportRequired > 0:
			deferredErrs = append(deferredErrs, &BootManagerCodePCRError{err})
		case err != nil:
			result.Flags |= NoBootManagerCodeProfileSupport
			warnings = append(warnings, &BootManagerCodePCRError{err})
		default:
			if pcr4Result&bootManagerCodeSysprepAppsPresent > 0 {
				result.Flags |= SysPrepApplicationsPresent
			}
			if pcr4Result&bootManagerCodeAbsoluteComputraceRunning > 0 {
				result.Flags |= AbsoluteComputraceActive
			}
			if pcr4Result&bootManagerCodeNotAllLaunchDigestsVerified > 0 {
				result.Flags |= NotAllBootManagerCodeDigestsVerified
			}

			if result.Flags&SysPrepApplicationsPresent > 0 && flags&PermitSysPrepApplications == 0 {
				// SysPrep applications were detected but these are not permitted.
				deferredErrs = append(deferredErrs, ErrSysPrepApplicationsPresent)
			}
			if result.Flags&AbsoluteComputraceActive > 0 && flags&PermitAbsoluteComputrace == 0 {
				// Absolute was detected but this is not permitted.
				deferredErrs = append(deferredErrs, ErrAbsoluteComputraceActive)
			}
			if result.Flags&NotAllBootManagerCodeDigestsVerified > 0 && flags&PermitNotVerifyingAllBootManagerCodeDigests == 0 {
				// Not all boot manager code launch digests were verified, and this was not allowed.
				// As we can't verify that this PCR is ok to be used, wrap this in BootManagerCodePCRError.
				deferredErrs = append(deferredErrs, &BootManagerCodePCRError{ErrNotAllBootManagerCodeDigestsVerified})
			}
		}
	}

	if logResults.Lookup(internal_efi.BootManagerConfigPCR).Ok() {
		// PCR5 profiles are not supported yet
		err := &BootManagerConfigPCRError{errors.New("generating profiles for PCR 5 is not supported yet")}
		switch {
		case flags&BootManagerConfigProfileSupportRequired > 0:
			deferredErrs = append(deferredErrs, err)
		default:
			result.Flags |= NoBootManagerConfigProfileSupport
			warnings = append(warnings, err)
		}
	}

	if logResults.Lookup(internal_efi.SecureBootPolicyPCR).Ok() {
		// Only run PCR7 checks if we established earlier that the PCR value matches
		// the reconstructed log value.
		var iblImage secboot_efi.Image
		if len(loadedImages) > 0 {
			iblImage = loadedImages[0]
		}
		pcr7Result, err := checkSecureBootPolicyMeasurementsAndObtainAuthorities(ctx, runChecksEnv, log, result.PCRAlg, iblImage)
		switch {
		case err != nil && flags&SecureBootPolicyProfileSupportRequired > 0:
			deferredErrs = append(deferredErrs, &SecureBootPolicyPCRError{err})
		case err != nil:
			result.Flags |= NoSecureBootPolicyProfileSupport
			warnings = append(warnings, &SecureBootPolicyPCRError{err})
		default:
			if pcr7Result.Flags&secureBootIncludesWeakAlg > 0 {
				result.Flags |= WeakSecureBootAlgorithmsDetected
			}
			if pcr7Result.Flags&secureBootPreOSVerificationIncludesDigest > 0 {
				result.Flags |= PreOSVerificationUsingDigestsDetected
			}
			result.UsedSecureBootCAs = pcr7Result.UsedAuthorities

			// Only return these errors if PCR7 is required.
			if result.Flags&WeakSecureBootAlgorithmsDetected > 0 && flags&PermitWeakSecureBootAlgorithms == 0 {
				// We don't support weak secure boot verification algorithms
				deferredErrs = append(deferredErrs, ErrWeakSecureBootAlgorithmDetected)
			}
			if result.Flags&PreOSVerificationUsingDigestsDetected > 0 && flags&PermitPreOSVerificationUsingDigests == 0 {
				// We don't support the verification of pre-OS components using digests
				deferredErrs = append(deferredErrs, ErrPreOSVerificationUsingDigests)
			}
		}
	}

	if len(deferredErrs) > 0 {
		return nil, joinErrors(deferredErrs...)
	}

	if len(warnings) > 0 {
		result.Warnings = joinErrors(warnings...).(CompoundError)
	}
	return result, nil
}
