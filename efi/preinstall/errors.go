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

// indentLines is a helper for managing indenting in nested multi-line
// errors.
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

// RunChecksErrors may be returned unwrapped from [RunChecks] containing a collection
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

// Errors related to checking platform firmware protections.

// NoHardwareRootOfTrustError is returned wrapped from [RunChecks] if the platform
// firmware is not protected by a hardware root-of-trust. This won't be returned if
// the PermitVirtualMachine flag is supplied to [RunChecks] and the current
// environment is a virtual machine.
type NoHardwareRootOfTrustError struct {
	err error
}

func (e *NoHardwareRootOfTrustError) Error() string {
	return "no hardware root-of-trust properly configured: " + e.err.Error()
}

func (e *NoHardwareRootOfTrustError) Unwrap() error {
	return e.err
}

// UnsupportedPlatformError is returned wrapped from [RunChecks] if this platform
// is not supported for FDE.
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
	// ErrCPUDebuggingNotLocked is returned wrapped from RunChecks if the CPU
	// has silicon debugging features but these have not been disabled and
	// locked by the platform firmware. This won't be returned if the
	// PermitVirtualMachine flag is supplied to RunChecks and the current
	// environment is a virtual machine.
	ErrCPUDebuggingNotLocked = errors.New("CPU debugging features are not disabled and locked")

	// ErrInsufficientDMAProtection is returned wrapped from RunChecks if the platform
	// firmware indicates that I/O DMA protection was disabled at some point. This won't
	// be returned if the PermitVirtualMachine flag is supplied to RunChecks and the current
	// environment is a virtual machine.
	ErrInsufficientDMAProtection = errors.New("the platform firmware indicates that DMA protections are insufficient")

	// ErrNoKernelIOMMU is returned wrapped from RunChecks if there is no IOMMU active. This
	// won't be returned if the PermitVirtualMachine flag is supplied to RunChecks and
	// the current environment is a virtual machine.
	ErrNoKernelIOMMU = errors.New("no kernel IOMMU support was detected")

	// ErrUEFIDebuggingEnabled is returned wrapped from RunChecks if the platform firmware
	// has a debugging endpoint enabled. This won't be returned if the PermitVirtualMachine
	// flag is supplied to RunChecks and the current environment is a virtual machine.
	ErrUEFIDebuggingEnabled = errors.New("the platform firmware contains a debugging endpoint enabled")
)

// Errors related to checking the TPM device.

var (
	// ErrNoTPM2Device is returned wrapped from RunChecks if there is no
	// TPM2 device available.
	ErrNoTPM2Device = internal_efi.ErrNoTPM2Device

	// ErrTPMLockout is returned wrapped from RunChecks if the TPM is in DA
	// lockout mode. If the existing lockout hierarchy authorization value is not
	// known then the TPM will most likely need to be cleared in order to fix this.
	ErrTPMLockout = errors.New("TPM is in DA lockout mode")

	// ErrTPMLockoutAlreadyOwned is returned wrapped from RunChecks if the authorization
	// value for the lockout hierarchy is already set but the PostInstallChecks flag isn't
	// supplied. If the lockout hierarchy is set at pre-install time, then the TPM will
	// most likely need to be cleared.
	ErrTPMLockoutAlreadyOwned = errors.New("TPM lockout hierarchy is already owned")

	// ErrUnsupportedTPMOwnership is returned wrapped from RunChecks if the authorization
	// value for the owner or endorsement hierarchies are set, which currently isn't
	// supported by snapd. Snapd needs the use of both of these hierarchies, so if we
	// want to support something other than snapd taking ownership of these in the future,
	// this will need coordination with snapd.
	ErrUnsupportedTPMOwnership = errors.New("either the TPM's storage or endorsement hierarchy is owned and this isn't currently supported")

	// ErrTPMInsufficientNVCounters is returned wrapped from RunChecks if there are
	// insufficient NV counters available for PCR policy revocation. If this is still
	// the case after a TPM clear then it means that the platform firmware is using
	// most of the allocation of available counters for itself, and maybe the
	// feature needs to be disabled by snapd.
	ErrTPMInsufficientNVCounters = errors.New("insufficient NV counters available")

	// ErrNoPCClientTPM is returned wrapped from RunChecks if a TPM2 device exists
	// but it doesn't claim to be meet the requirements for PC-Client. Note that swtpm
	// used by VM's don't behave correctly here, so we account for that instead of
	// returning an error.
	ErrNoPCClientTPM = errors.New("TPM2 device is present but it is not a PC-Client TPM")

	// ErrTPMDisabled is returned wrapped from RunChecks if a TPM2 device exists but
	// it is currently disabled. It can be reenabled by the firmware by making use of the
	// [github.com/canonical/go-tpm2/ppi.PPI] interface, obtained by using
	// [github.com/canonical/go-tpm2/linux/RawDevice.PhysicalPresenceInterface].
	ErrTPMDisabled = errors.New("TPM2 device is present but is currently disabled by the platform firmware")
)

// Errors related to general TCG log checks and PCR bank selection.

// NoSuitablePCRAlgorithmError is returned wrapped from [RunChecks] if there is no suitable PCR bank
// where the log matches the TPM values when reconstructed. As multiple errors can occur during
// testing (multiple banks and multiple PCRs), this error tries to keep as much information as
// possible
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

// Errors related to secure boot policy PCR checks.

var (
	// ErrNoSecureBoot is returned wrapped from DetectSupport to indicate that secure boot is disabled
	ErrNoSecureBoot = errors.New("secure boot should be enabled in order to generate secure boot profiles")

	// ErrNoDeployedMode is returned wrapped from DetectSupport to indicate that deployed mode is not
	// enabled. In the future, this package will permit generation of profiles on systems that implement
	// UEFI >= 2.5 that are in user mode, but this is not the case today.
	ErrNoDeployedMode = errors.New("deployed mode should be enabled in order to generate secure boot profiles")
)

// RequiredUnsupportedPCRsError is returned from methods of [PCRProfileAutoEnablePCRsOption]
// when a valid PCR configuration cannot be created based on the supplied [PCRProfileOptionsFlags]
// and [CheckResult].
type RequiredUnsupportedPCRsError struct {
	PCRs tpm2.HandleList
}

func newRequiredUnsupportedPCRsError(required tpm2.HandleList, flags CheckResultFlags) *RequiredUnsupportedPCRsError {
	var pcrs tpm2.HandleList
	for _, pcr := range required {
		var flag CheckResultFlags
		switch pcr {
		case 0:
			flag = NoPlatformFirmwareProfileSupport
		case 1:
			flag = NoPlatformConfigProfileSupport
		case 2:
			flag = NoDriversAndAppsProfileSupport
		case 3:
			flag = NoDriversAndAppsConfigProfileSupport
		case 4:
			flag = NoBootManagerCodeProfileSupport
		case 5:
			flag = NoBootManagerConfigProfileSupport
		case 7:
			flag = NoSecureBootPolicyProfileSupport
		}

		if flags&flag > 0 {
			pcrs = append(pcrs, pcr)
		}
	}

	return &RequiredUnsupportedPCRsError{pcrs}
}

func (e *RequiredUnsupportedPCRsError) Error() string {
	switch len(e.PCRs) {
	case 1:
		return fmt.Sprintf("PCR %v is required, but is unsupported", e.PCRs[0])
	default:
		return fmt.Sprintf("PCRs %v are required, but are unsupported", e.PCRs)
	}
}
