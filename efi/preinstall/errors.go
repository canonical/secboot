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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

func indentLines(n int, str string) string {
	r := bytes.NewReader([]byte(str))
	w := new(bytes.Buffer)
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		fmt.Fprintf(w, "%*s%s", n, "", line)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(w, "%*serror occurred whilst indenting: %v", n, "", err)
			break
		}
	}
	return w.String()
}

// RunChecksErrors is returned unwrapped from [RunChecks] containing a collection
// of errors found during the process of running various tests on the platform.
// It provides a mechanism to access each individual error.
type RunChecksErrors struct {
	errs []error
}

func (e *RunChecksErrors) Error() string {
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "one or more errors detected:\n")
	for _, err := range e.errs {
		fmt.Fprintf(w, "%s\n", indentLines(2, "- "+err.Error()))
	}
	return w.String()
}

// NumErrors returns the number of errors.
func (e *RunChecksErrors) NumErrors() int {
	return len(e.errs)
}

// UnwrapError unwraps the specific error at the specified index (zero-indexed).
func (e *RunChecksErrors) UnwrapError(n int) error {
	if n > len(e.errs)-1 {
		return errors.New("error index out of range")
	}
	return e.errs[n]
}

func (e *RunChecksErrors) addErr(err error) {
	e.errs = append(e.errs, err)
}

var (
	// ErrVirtualMachineDetected is returned unwrapped from RunChecks when running
	// in a virtual machine and the PermitVirtualMachine flag was not supplied.
	// This error can be bypassed with the PermitVirtualMachine flag.
	ErrVirtualMachineDetected = errors.New("virtual machine environment detected")
)

// Errors related to checking platform firmware protections.

// PlatformFirmwareProtectionError is returned wrapped in [RunChecksError] if there
// is an issue with how the platform firmware is protected. This won't be returned
// if the PermitVirtualMachine flag is supplied to [RunChecks] and the current
// environment is a virtual machine.
type PlatformFirmwareProtectionError struct {
	err error
}

func (e *PlatformFirmwareProtectionError) Error() string {
	return "error with platform firmware protection configuration: " + e.err.Error()
}

func (e *PlatformFirmwareProtectionError) Unwrap() error {
	return e.err
}

// NoHardwareRootOfTrustError is returned wrapped in [PlatformFirmwareProtectionError]
// if the platform firmware is not protected by a properly configured hardware root-of-trust.
// This won't be returned if the PermitVirtualMachine flag is supplied to [RunChecks] and the
// current environment is a virtual machine.
type NoHardwareRootOfTrustError struct {
	err error
}

func (e *NoHardwareRootOfTrustError) Error() string {
	return "no hardware root-of-trust properly configured: " + e.err.Error()
}

func (e *NoHardwareRootOfTrustError) Unwrap() error {
	return e.err
}

// UnsupportedPlatformError is returned wrapped in [PlatformFirmwareProtectionError]
// if this platform is not supported for FDE. This won't be returned if the
// PermitVirtualMachine flag is supplied to [RunChecks] and the current environment
// is a virtual machine.
type UnsupportedPlatformError struct {
	err error
}

func (e *UnsupportedPlatformError) Error() string {
	return "unsupported platform: " + e.err.Error()
}

func (e *UnsupportedPlatformError) Unwrap() error {
	return e.err
}

var (
	// ErrCPUDebuggingNotLocked is returned wrapped in PlatformFirmwareProtectionError
	// if the CPU has silicon debugging features but these have not been disabled and
	// locked by the platform firmware. This won't be returned if the PermitVirtualMachine
	// flag is supplied to RunChecks and the current environment is a virtual machine.
	ErrCPUDebuggingNotLocked = errors.New("CPU debugging features are not disabled and locked")

	// ErrInsufficientDMAProtection is returned wrapped in PlatformFirmwareProtectionError
	// if the platform firmware indicates that I/O DMA protection was disabled at some point.
	// This won't be returned if the PermitVirtualMachine flag is supplied to RunChecks and
	// the current environment is a virtual machine.
	ErrInsufficientDMAProtection = errors.New("the platform firmware indicates that DMA protections are insufficient")

	// ErrNoKernelIOMMU is returned wrapped in PlatformFirmwareProtectionError if there is
	// no IOMMU active. This won't be returned if the PermitVirtualMachine flag is supplied
	// to RunChecks and the current environment is a virtual machine.
	ErrNoKernelIOMMU = errors.New("no kernel IOMMU support was detected")

	// ErrUEFIDebuggingEnabled is returned wrapped in PlatformFirmwareProtectionError if the
	// platform firmware has a debugging endpoint enabled. This won't be returned if the
	// PermitVirtualMachine flag is supplied to RunChecks and the current environment is a
	// virtual machine.
	ErrUEFIDebuggingEnabled = errors.New("the platform firmware contains a debugging endpoint enabled")

	// ErrTPMStartupLocalityNotProtected is returned wrapped in RunChecksErrors if access to
	// the TPM's startup locality is available to platform firmware or privileged code. This
	// means that it's not possible to provide a mitigation against reseet attacks (see the
	// description of DiscreteTPMDetected). This error is only relevant for discrete TPMs.
	// It can be permitted by passing the PermitNoDiscreteTPMResetMitigation flag to RunChecks.
	ErrTPMStartupLocalityNotProtected = errors.New("access to the discrete TPM's startup locality is available to platform firmware and privileged OS code, preventing any mitigation against reset attacks")
)

// Errors related to checking the TPM device.

// TPM2DeviceError is returned unwrapped from [RunChecks] if there is an issue with
// the TPM device.
type TPM2DeviceError struct {
	err error
}

func (e *TPM2DeviceError) Error() string {
	return "error with TPM2 device: " + e.err.Error()
}

func (e *TPM2DeviceError) Unwrap() error {
	return e.err
}

var (
	// ErrNoTPM2Device is returned wrapped in TPM2DeviceError if there is no TPM2
	// device available.
	ErrNoTPM2Device = internal_efi.ErrNoTPM2Device

	// ErrTPMLockout is returned wrapped in TPM2DeviceError if the TPM is in DA
	// lockout mode. If the existing lockout hierarchy authorization value is not
	// known then the TPM will most likely need to be cleared in order to fix this.
	// This test only runs during pre-install, and not if the PostInstall flag is passed
	// to RunChecks.
	ErrTPMLockout = errors.New("TPM is in DA lockout mode")

	// ErrTPMInsufficientNVCounters is returned wrapped in TPM2DeviceError if there are
	// insufficient NV counters available for PCR policy revocation. If this is still
	// the case after a TPM clear then it means that the platform firmware is using most
	// of the allocation of available counters for itself, and maybe the feature needs
	// to be disabled by snapd (although this would require an option to skip this check).
	// This test only runs during pre-install, and not if the PostInstall flag is passed
	// to RunChecks.
	ErrTPMInsufficientNVCounters = errors.New("insufficient NV counters available")

	// ErrNoPCClientTPM is returned wrapped in TPM2DeviceError if a TPM2 device exists but
	// it doesn't claim to be meet the requirements for PC-Client. Note that swtpm used
	// by VM's don't behave correctly here, so we account for that instead of returning
	// an error.
	ErrNoPCClientTPM = errors.New("TPM2 device is present but it is not a PC-Client TPM")

	// ErrTPMDisabled is returned wrapped in TPM2DeviceError if a TPM2 device exists but
	// it is currently disabled. It can be reenabled by the firmware by making use of the
	// [github.com/canonical/go-tpm2/ppi.PPI] interface, obtained by using
	// [github.com/canonical/go-tpm2/linux/RawDevice.PhysicalPresenceInterface].
	ErrTPMDisabled = errors.New("TPM2 device is present but is currently disabled by the platform firmware")
)

// TPMHierarchyOwnedError is returned wrapped in TPM2DeviceError if the authorization value
// for the specified hierarchy is set, but the PostInstallChecks flag isn't set. If a
// hierarchy is owned during pre-install, the TPM will most likely need to be cleared.
type TPM2HierarchyOwnedError struct {
	Hierarchy tpm2.Handle
}

func (e *TPM2HierarchyOwnedError) Error() string {
	var hierarchy string
	switch e.Hierarchy {
	case tpm2.HandleOwner:
		hierarchy = "owner"
	case tpm2.HandleLockout:
		hierarchy = "lockout"
	case tpm2.HandleEndorsement:
		hierarchy = "endorsement"
	default:
		hierarchy = "unknwon"
	}

	return "TPM " + hierarchy + " hierarchy is currently owned"
}

// Errors related to general TCG log checks and PCR bank selection.

// TCGLogError is returned unwrapped from [RunChecks] if there is a general issue with the
// TCG log supplied by the firmware.
type TCGLogError struct {
	err error
}

func (e *TCGLogError) Error() string {
	return "error with TCG log: " + e.err.Error()
}

func (e *TCGLogError) Unwrap() error {
	return e.err
}

// NoSuitablePCRAlgorithmError is returned wrapped in [TCGLogError] if there is no suitable PCR
// bank where the log matches the TPM values when reconstructed. As multiple errors can occur
// during testing (multiple banks and multiple PCRs), this error wraps each individual error
// that occurred and provides access to them.
type NoSuitablePCRAlgorithmError struct {
	bankErrs map[tpm2.HashAlgorithmId]error                 // bankErrs apply to an entire PCR bank
	pcrErrs  map[tpm2.HashAlgorithmId]map[tpm2.Handle]error // pcrErrs apply to a single PCR in a single bank
}

func (e *NoSuitablePCRAlgorithmError) Error() string {
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "no suitable PCR algorithm available:\n")

	// Note that this function iterates over the supportedAlgs and supportedPcrs
	// slices rather than the maps directly to ensure consistent ordering (which
	// go maps don't guarantee when iterating over keys).
	for _, alg := range supportedAlgs {
		// Print error for this PCR bank first, if there is one.
		if err, isErr := e.bankErrs[alg]; isErr {
			// We have a general error for this PCR bank
			fmt.Fprintf(w, "- %v: %v.\n", alg, err)
		}

		// Then print errors associated with individual PCRs in this bank.
		pcrErrs, hasPcrErrs := e.pcrErrs[alg]
		if !hasPcrErrs {
			// We have no individual PCR errors for this bank
			continue
		}
		for _, pcr := range supportedPcrs {
			if err, isErr := pcrErrs[pcr]; isErr {
				// We have an error for this PCR
				fmt.Fprintf(w, "- %v(PCR%d): %v.\n", alg, pcr, err)
			}
		}
	}
	return w.String()
}

// UnwrapBankError returns the error associated with the specified PCR bank if one
// occurred, or nil if none occurred.
func (e *NoSuitablePCRAlgorithmError) UnwrapBankError(alg tpm2.HashAlgorithmId) error {
	return e.bankErrs[alg]
}

// UnwrapPCRError returns the error associated with the specified PCR in the specified
// bank if one occurred, or nil if none occurred.
func (e *NoSuitablePCRAlgorithmError) UnwrapPCRError(alg tpm2.HashAlgorithmId, pcr tpm2.Handle) error {
	pcrErrs, exists := e.pcrErrs[alg]
	if !exists {
		return nil
	}
	return pcrErrs[pcr]
}

// setBankErr sets an error for an entire PCR bank
func (e *NoSuitablePCRAlgorithmError) setBankErr(alg tpm2.HashAlgorithmId, err error) {
	if e.bankErrs == nil {
		e.bankErrs = make(map[tpm2.HashAlgorithmId]error)
	}
	e.bankErrs[alg] = err
}

// setPcrErrs sets errors for individual PCRs associated with a bank
func (e *NoSuitablePCRAlgorithmError) setPcrErrs(results *pcrBankResults) {
	if e.pcrErrs == nil {
		e.pcrErrs = make(map[tpm2.HashAlgorithmId]map[tpm2.Handle]error)
	}
	e.pcrErrs[results.Alg] = results.pcrErrs()
}

// Errors related to platform firmware PCR checks

// PlatformFirmwarePCRError is returned as a warning in [CheckResult] if the
// PlatformFirmwareProfileSupportRequired flag is not supplied to [RunChecks],
// to indicate that [github.com/snapcore/secboot/efi.WithPlatformFirmwareProfile]
// cannot be used to add a profile for PCR 0.
//
// If the PlatformFirmwareProfileSupportRequiredflag is supplied to [RunChecks],
// an alternative error will be returned via [NoSuitablePCRAlgorithmError] instead
// if the PCR 0 value is inconsistent with the reconstructed TCG log value.
type PlatformFirmwarePCRError struct {
	err error
}

func (e *PlatformFirmwarePCRError) Error() string {
	return "error with platform firmware (PCR0) measurements: " + e.err.Error()
}

func (e *PlatformFirmwarePCRError) Unwrap() error {
	return e.err
}

// Errors related to platform config PCR checks

// PlatformConfigPCRError is returned wrapped in [RunChecksErrors] if the
// PlatformConfigProfileSupportRequired flag is supplied to [RunChecks],
// because there currently is no support in [github.com/snapcore/secboot/efi]
// for generating profiles for PCR 1.
//
// It is returned as a warning in [CheckResult] instead if the
// PlatformConfigProfileSupportRequired flag is not supplied to [RunChecks].
//
// If the PlatformConfigProfileSupportRequiredflag is supplied to [RunChecks],
// an alternative error will be returned via [NoSuitablePCRAlgorithmError] instead
// if the PCR 1 value is inconsistent with the reconstructed TCG log value.
type PlatformConfigPCRError struct {
	err error
}

func (e *PlatformConfigPCRError) Error() string {
	return "error with platform config (PCR1) measurements: " + e.err.Error()
}

func (e *PlatformConfigPCRError) Unwrap() error {
	return e.err
}

// Errors related to drivers and apps PCR checks.

// DriversAndAppsPCRError is returned wrapped in [RunChecksErrors] if the
// DriversAndAppsProfileSupportRequired flag is supplied to [RunChecks] and
// an error occurs that means that
// [github.com/snapcore/secboot/efi.WithDriversAndAppsProfile] cannot be used
// to generate profiles for PCR 2.
//
// It is returned as a warning in [CheckResult] instead if the
// DriversAndAppsProfileSupportRequired flag is not supplied to [RunChecks].
//
// If the DriversAndAppsProfileSupportRequiredflag is supplied to [RunChecks],
// an alternative error will be returned via [NoSuitablePCRAlgorithmError] instead
// if the PCR 2 value is inconsistent with the reconstructed TCG log value.
type DriversAndAppsPCRError struct {
	err error
}

func (e *DriversAndAppsPCRError) Error() string {
	return "error with drivers and apps (PCR2) measurements: " + e.err.Error()
}

func (e *DriversAndAppsPCRError) Unwrap() error {
	return e.err
}

var (
	// ErrVARSuppliedDriversPresent is returned wrapped in RunChecksErrors
	// if value-added-retailer drivers are detected to be running.
	// These can be permitted by supplying the PermitVARSuppliedDrivers flag
	// to RunChecks.
	ErrVARSuppliedDriversPresent = errors.New("value added retailer supplied drivers were detected to be running")
)

// Errors related to drivers and apps config PCR checks

// DriversAndAppsConfigPCRError is returned wrapped in [RunChecksErrors] if the
// DriversAndAppsConfigProfileSupportRequired flag is supplied to [RunChecks],
// because there currently is no support in [github.com/snapcore/secboot/efi]
// for generating profiles for PCR 3.
//
// It is returned as a warning in [CheckResult] instead if the
// DriversAndAppsConfigProfileSupportRequired flag is not supplied to [RunChecks].
//
// If the DriversAndAppsConfigProfileSupportRequiredflag is supplied to [RunChecks],
// an alternative error may be returned via [NoSuitablePCRAlgorithmError] instead
// if the PCR 3 value is inconsistent with the reconstructed TCG log value.
type DriversAndAppsConfigPCRError struct {
	err error
}

func (e *DriversAndAppsConfigPCRError) Error() string {
	return "error with drivers and apps config (PCR3) measurements: " + e.err.Error()
}

func (e *DriversAndAppsConfigPCRError) Unwrap() error {
	return e.err
}

// Errors related to boot manager code PCR checks

// BootManagerCodePCRError is returned wrapped in [RunChecksErrors] if the
// BootManagerCodeProfileSupportRequired flag is supplied to [RunChecks]
// and an error occurs that means that
// [github.com/snapcore/secboot/efi.WithBootManagerCodeProfile] cannot be
// used to generate profiles for PCR 4.
//
// It is returned as a warning in [CheckResult] instead if the
// BootManagerCodeProfileSupportRequired flag is not supplied to [RunChecks].
//
// If the BootManagerCodeProfileSupportRequiredflag is supplied to [RunChecks],
// an alternative error will be returned via [NoSuitablePCRAlgorithmError] instead
// if the PCR 4 value is inconsistent with the reconstructed TCG log value.
type BootManagerCodePCRError struct {
	err error
}

func (e *BootManagerCodePCRError) Error() string {
	return "error with boot manager code (PCR4) measurements: " + e.err.Error()
}

func (e *BootManagerCodePCRError) Unwrap() error {
	return e.err
}

var (
	// ErrSysPrepApplicationsPresent is returned wrapped in RunChecksErrors
	// if system preparation applications were detected to be running.
	// These can be permitted by supplying the PermitSysPrepApplications flag
	// to RunChecks.
	ErrSysPrepApplicationsPresent = errors.New("system preparation applications were detected to be running")

	// ErrAbsoluteComputraceActive is returned wrapped in RunChecksErrors
	// if Absolute was detected to be active. It is advised that this firmware
	// is disabled if possible.
	// This can be permitted by supplying the PermitAbsoluteComputrace flag
	// to RunChecks.
	ErrAbsoluteComputraceActive = errors.New("Absolute was detected to be active and it is advised that this is disabled")

	// ErrNotAllBootManagerCodeDigestsVerified is returned wrapped in RunChecksErrors
	// if it wasn't possible to verify the launch digest for every
	// EV_EFI_BOOT_SERVICES_APPLICATION event against a supplied set of launch applications
	// for the current boot.
	// This error can be bypassed by supplying the PermitNotVerifyingAllBootManagerCodeDigests
	// flag to RunChecks.
	ErrNotAllBootManagerCodeDigestsVerified = errors.New("not all EV_EFI_BOOT_SERVICES_APPLICATION boot manager launch digests could be verified")
)

// Errors related to boot manager config PCR checks

// BootManagerConfigPCRError is returned wrapped in [RunChecksErrors] if the
// BootManagerConfigProfileSupportRequired flag is supplied to [RunChecks],
// because there currently is no support in [github.com/snapcore/secboot/efi] for
// generating profiles for PCR 5.
//
// It is returned as a warning in [CheckResult] instead if the
// BootManagerConfigProfileSupportRequired flag is not supplied to [RunChecks].
//
// If the BootManagerConfigProfileSupportRequiredflag is supplied to [RunChecks],
// an alternative error will be returned via [NoSuitablePCRAlgorithmError] instead
// if the PCR 5 value is inconsistent with the reconstructed TCG log value.
type BootManagerConfigPCRError struct {
	err error
}

func (e *BootManagerConfigPCRError) Error() string {
	return "error with boot manager config (PCR5) measurements: " + e.err.Error()
}

func (e *BootManagerConfigPCRError) Unwrap() error {
	return e.err
}

// Errors related to secure boot policy PCR checks.

// SecureBootPolicyPCRError is returned wrapped in [RunChecksErrors] if the
// SecureBootPolicyProfileSupportRequired flag is supplied to [RunChecks]
// and an error occurs that means that
// [github.com/snapcore/secboot/efi.WithSecureBootPolicyProfile] cannot be
// used to generate profiles for PCR 7.
//
// It is returned as a warning in [CheckResult] instead if the
// SecureBootPolicyProfileSupportRequired flag is not supplied to [RunChecks].
//
// If the SecureBootPolicyProfileSupportRequiredflag is supplied to [RunChecks],
// an alternative error will be returned via [NoSuitablePCRAlgorithmError] instead
// if the PCR 7 value is inconsistent with the reconstructed TCG log value.
type SecureBootPolicyPCRError struct {
	err error
}

func (e *SecureBootPolicyPCRError) Error() string {
	return "error with secure boot policy (PCR7) measurements: " + e.err.Error()
}

func (e *SecureBootPolicyPCRError) Unwrap() error {
	return e.err
}

var (
	// ErrNoSecureBoot is returned wrapped in SecureBootPolicyPCRError to indicate
	// that secure boot is disabled.
	ErrNoSecureBoot = errors.New("secure boot should be enabled in order to generate secure boot profiles")

	// ErrNoDeployedMode is returned wrapped in SecureBootPolicyPCRError to indicate
	// that deployed mode is not enabled. In the future, this package will permit
	// generation of profiles on systems that implement UEFI >= 2.5 that are in user
	// mode, but this is not the case today.
	ErrNoDeployedMode = errors.New("deployed mode should be enabled in order to generate secure boot profiles")

	// ErrWeakSecureBootAlgorithmDetected is returned wrapped in RunChecksErrors and
	// indicates that weak algorithms were detected during secure boot verification,
	// such as authenticating a binary with SHA-1, or a CA with a 1024-bit RSA public key,
	// or the signer of the initial boot loader having a 1024-bit RSA public key. This does
	// have some limitations because the TCG log doesn't indicate the properties of the
	// actual signing certificates or the algorithms used to sign each binary, so it's
	// not possible to determine whether signing certificates for non-OS components are
	// strong enough.
	// This can be bypassed by supplying the PermitWeakSecureBootAlgorithms flag to
	// RunChecks.
	ErrWeakSecureBootAlgorithmDetected = errors.New("a weak cryptographic algorithm was detected during secure boot verification")

	// ErrPreOSVerificationUsingDigests is returned wrapped in RunChecksErrors and
	// indicates that pre-OS components were authenticated using Authenticode digests
	// rather than a X.509 certificate. This makes PCR7 inherently fragile with regards
	// to firmware updates because db has to be changed accordingly each time.
	// This can be bypassed by supplying the PermitPreOSVeriricationUsingDigests flag
	// to RunChecks.
	ErrPreOSVerificationUsingDigests = errors.New("some pre-OS components were authenticated from the authorized signature database using an Authenticode digest")
)
