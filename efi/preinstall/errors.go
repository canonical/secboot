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
	"strings"

	"github.com/canonical/go-tpm2"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// makeIndentedListItem turns the supplied string into a list item by prepending
// the supplied marker string (which could be a bullet point or numeric character)
// to the supplied string, useful for displaying multiple errors. In a multi-line
// string, subsequent lines in the supplied string will all be aligned with the start
// of the first line after the marker. The indentation argument specifies the
// indentation of the maker, in the number of characters.
func makeIndentedListItem(indentation int, marker, str string) string {
	scanner := bufio.NewScanner(bytes.NewReader([]byte(str)))

	// lastLineEndsInNewline is needed as a flag to determine whether we need
	// to return our string with a newline terminator. This is because, whilst
	// the default bufio.Scanner implementation, which uses bufio.ScanLines,
	// returns each line of text separately, it does not return the newline
	// characters. We do a bit of a hack here to intercept the bufio.ScanLines
	// call to determine if the last line was terminated with a newline character.
	lastLineEndsInNewline := false
	scanner.Split(func(data []byte, atEOF bool) (adv int, token []byte, err error) {
		adv, token, err = bufio.ScanLines(data, atEOF)
		if atEOF {
			switch {
			case len(data) == 0:
				// The last call was with data and !atEOF, so the last byte
				// had to have been a newline in order to end up here.
				lastLineEndsInNewline = true
			case adv == len(data) && data[len(data)-1] == byte('\n'):
				// The data argument contains all of the remaining data, we
				// advanced to the end of it, and the last character is a
				// newline.
				lastLineEndsInNewline = true
			}
		}
		return adv, token, err
	})

	w := new(bytes.Buffer)

	// Start the first line with a hyphen, at the specified indentation.
	fmt.Fprintf(w, "%*s%s ", indentation, "", marker)
	firstLine := true // we treat the first and subsequent lines differently.
	for scanner.Scan() {
		if firstLine {
			io.WriteString(w, scanner.Text())
			firstLine = false
			continue
		}

		// Subsequent lines should be aligned with the first line.
		fmt.Fprintf(w, "\n%*s%s", indentation+2, "", scanner.Text())
	}
	if scanner.Err() != nil {
		// If an error occurred in scanning, add the error message to our output.
		fmt.Fprintf(w, "\n%*s<scanner error: %v>", indentation+2, "", scanner.Err())
	}
	if lastLineEndsInNewline {
		io.WriteString(w, "\n")
	}
	return w.String()
}

// RunChecksErrors may be returned unwrapped from [RunChecks] containing a collection
// of errors found during the process of running various tests on the platform.
// It provides a mechanism to access each individual error. This is used as an alternative
// to aborting early, in order for the caller to gather as much information as possible.
// Where an error is related to a specific PCR, the error will be wrapped by one of the
// PCR-specific error types: [PlatformFirmwarePCRError] (0), [PlatformConfigPCRError] (1),
// [DriversAndAppsPCRError] (2), [DriversAndAppsConfigPCRError] (3),
// [BootManagerCodePCRError] (4), [BootManagerConfigPCRError] (5), or
// [SecureBootPolicyPCRError] (7).
type RunChecksErrors struct {
	Errs []error // All of the errors collected during the execution of RunChecks
}

func (e *RunChecksErrors) Error() string {
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "one or more errors detected:\n")
	for _, err := range e.Errs {
		io.WriteString(w, makeIndentedListItem(0, "-", err.Error()))
	}
	return w.String()
}

func (e *RunChecksErrors) addErr(err error) {
	e.Errs = append(e.Errs, err)
}

// CompoundError is an interface for accessing wrapped errors from an error type that
// wraps more than one error.
type CompoundError interface {
	Unwrap() []error
}

// joinError is a simple implementation of the type of the same name from the
// errors package in go 1.20.
type joinError struct {
	errs []error
}

func joinErrors(errs ...error) error {
	return &joinError{errs: errs}
}

func (e *joinError) Error() string {
	switch {
	case len(e.errs) == 0:
		return ""
	case len(e.errs) == 1:
		return e.errs[0].Error()
	default:
		var b strings.Builder
		io.WriteString(&b, e.errs[0].Error())
		for _, err := range e.errs[1:] {
			io.WriteString(&b, "\n")
			io.WriteString(&b, err.Error())
		}
		return b.String()
	}
}

func (e *joinError) Unwrap() []error {
	return e.errs
}

var (
	// ErrVirtualMachineDetected is returned unwrapped from RunChecks when running
	// in a virtual machine and the PermitVirtualMachine flag was not supplied.
	// This error can be bypassed with the PermitVirtualMachine flag.
	ErrVirtualMachineDetected = errors.New("virtual machine environment detected")
)

// Errors related to checking platform firmware protections.

// HostSecurityError may be returned unwrapped or wrapped in [RunChecksError] if there is
// an issue with the security properties of the system. This won't be returned if the
// PermitVirtualMachine flag is supplied to [RunChecks] and the current environment is a
// virtual machine. This will only be returned unwrapped for errors that can't be
// resolved or which prevent execution of the remaining checks.
type HostSecurityError struct {
	err error
}

func (e *HostSecurityError) Error() string {
	return "error with system security: " + e.err.Error()
}

func (e *HostSecurityError) Unwrap() error {
	return e.err
}

// NoHardwareRootOfTrustError is returned wrapped in [HostSecurityError] if the platform
// firmware is not protected by a properly configured hardware root-of-trust. This won't
// be returned if the PermitVirtualMachine flag is supplied to [RunChecks] and the current
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

// UnsupportedPlatformError is returned wrapped in [HostSecurityError] if this platform
// is not supported for FDE. This won't be returned if the PermitVirtualMachine flag is
// supplied to [RunChecks] and the current environment is a virtual machine.
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
	// ErrCPUDebuggingNotLocked is returned wrapped in HostSecurityError if the CPU has
	// silicon debugging features but these have not been disabled and locked by the
	// platform firmware. This won't be returned if the PermitVirtualMachine flag is
	// supplied to RunChecks and the current environment is a virtual machine.
	ErrCPUDebuggingNotLocked = errors.New("CPU debugging features are not disabled and locked")

	// ErrInsufficientDMAProtection is returned wrapped in HostSecurityError if the platform
	// firmware indicates that I/O DMA protection was disabled at some point. This won't be
	// returned if the PermitVirtualMachine flag is supplied to RunChecks and the current
	// environment is a virtual machine.
	ErrInsufficientDMAProtection = errors.New("the platform firmware indicates that DMA protections are insufficient")

	// ErrNoKernelIOMMU is returned wrapped in HostSecurityError if there is no IOMMU active.
	// This won't be returned if the PermitVirtualMachine flag is supplied to RunChecks and
	// the current environment is a virtual machine.
	ErrNoKernelIOMMU = errors.New("no kernel IOMMU support was detected")

	// ErrUEFIDebuggingEnabled is returned wrapped in HostSecurityError if the platform
	// firmware has a debugging endpoint enabled. This won't be returned if the PermitVirtualMachine
	// flag is supplied to RunChecks and the current environment is a virtual machine.
	ErrUEFIDebuggingEnabled = errors.New("the platform firmware contains a debugging endpoint enabled")

	// ErrTPMStartupLocalityNotProtected is returned wrapped in HostSecurityError if access to
	// the TPM's startup locality is available to platform firmware or privileged code. This
	// means that it's not possible to provide a mitigation against reseet attacks (see the
	// description of DiscreteTPMDetected). This error is only relevant for discrete TPMs.
	// It can be permitted by passing the PermitNoDiscreteTPMResetMitigation flag to RunChecks.
	ErrTPMStartupLocalityNotProtected = errors.New("access to the discrete TPM's startup locality is available to platform firmware and privileged OS code, preventing any mitigation against reset attacks")
)

// Errors related to checking the TPM device.

// TPM2DeviceError is returned unwrapped from [RunChecks] if there is an issue with
// the TPM device, or any TPM commands fail unexpectedly.
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
	// lockout mode. This is checked after verifying that the authorization value for
	// the lockout hierarchy is empty, so it may be easy to clear this as long as the
	// lockout hierarchy is available. This test only runs during pre-install, and
	// not if the PostInstall flag is passed to RunChecks.
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

	// ErrTPMFailure is returned wrapped in TPM2DeviceError is the TPM device is in
	// failure mode. A TPM device in failure mode can only execute commands to obtain
	// test results, or fetch a limited set of permanent properties to determine the
	// manufactuer, vendor name or firmware version. Resetting a device in failure mode
	// may clear it but it's possible that the failure may occur again during the next
	// boot cycle, in which case, it's likely that there is a fault somewhere with the
	// TPM's hardware (in the case of dTPMs) or the TPM's firmware.
	ErrTPMFailure = errors.New("TPM2 device is in failure mode")
)

// TPM2OwnedHierarchiesError is returned wrapped in [TPM2DeviceError] if any hierarchies
// are owned in some way, either because they have an authorization value set or because
// they have an authorization policy set, and the PostInstallChecks flag isn't set. If
// a hierarchy is owned with an authorization value during pre-install, the TPM will
// probably have to be cleared. If a hierarchy has an authorization policy set but no
// authorization value, then it is trivial to rectify using the TPM2_SetPrimaryPolicy
// command.
type TPM2OwnedHierarchiesError struct {
	WithAuthValue  tpm2.HandleList
	WithAuthPolicy tpm2.HandleList
}

func (e *TPM2OwnedHierarchiesError) Error() string {
	str := new(bytes.Buffer)
	io.WriteString(str, "one or more of the TPM hierarchies is already owned:\n")
	for _, handle := range e.WithAuthValue {
		io.WriteString(str, makeIndentedListItem(0, "-", fmt.Sprintf("%v has an authorization value\n", handle)))
	}
	for _, handle := range e.WithAuthPolicy {
		io.WriteString(str, makeIndentedListItem(0, "-", fmt.Sprintf("%v has an authorization policy\n", handle)))
	}
	return str.String()
}

func (e *TPM2OwnedHierarchiesError) addAuthValue(hierarchy tpm2.Handle) {
	e.WithAuthValue = append(e.WithAuthValue, hierarchy)
}

func (e *TPM2OwnedHierarchiesError) addAuthPolicy(hierarchy tpm2.Handle) {
	e.WithAuthPolicy = append(e.WithAuthPolicy, hierarchy)
}

func (e *TPM2OwnedHierarchiesError) isEmpty() bool {
	return len(e.WithAuthValue) == 0 && len(e.WithAuthPolicy) == 0
}

// Errors related to general TCG log checks and PCR bank selection.

var (
	// ErrPCRBankMissingFromLog may be returned wrapped by NoSuitablePCRAlgorithmError
	// in the event where a PCR bank does not exist in the TCG log.
	ErrPCRBankMissingFromLog = errors.New("the PCR bank is missing from the TCG log")
)

// PCRValueMismatchError may be returned, indirectly wrapped (via a PCR-specific error type) by
// NoSuitablePCRAlgorithmError for a specific PCR, in the case where there is a mismatch between
// the actual PCR value and the value reconstructed from the TCG log.
type PCRValueMismatchError struct {
	PCRValue tpm2.Digest // The PCR value obtained from the TPM.
	LogValue tpm2.Digest // The expected value reconstructed from the TCG log.
}

func (e *PCRValueMismatchError) Error() string {
	return fmt.Sprintf("PCR value mismatch (actual from TPM %#x, reconstructed from log %#x)", e.PCRValue, e.LogValue)
}

// EmptyPCRBanksError may be returned unwrapped in the event where one or more TCG defined PCR
// banks seem to be active but not extended by firmware and not present in the log. This doesn't
// matter so much for FDE because we can select a good bank, but is a serious firmware bug for
// any scenario that requires remote attestation, because it permits an entire trusted computing
// environment to be spoofed by an adversary in software.
//
// If a PCR bank is missing from the TCG log but is enabled on the TPM with empty PCRs, the bank
// will be recorded to the Algs field.
//
// This error can be ignored by passing the PermitEmptyPCRBanks flag to [RunChecks]. This is
// generally ok, as long as the device is not going to be used for any kind of remote attestation.
type EmptyPCRBanksError struct {
	Algs []tpm2.HashAlgorithmId
}

func (e *EmptyPCRBanksError) Error() string {
	var algs []string
	for _, alg := range e.Algs {
		algs = append(algs, fmt.Sprintf("%v", alg))
	}

	var s string
	switch len(e.Algs) {
	case 0:
		return "internal error: invalid EmptyPCRBanksError"
	case 1:
		s = fmt.Sprintf("bank for %s is", algs[0])
	default:
		s = fmt.Sprintf("banks for %s are", strings.Join(algs, ", "))
	}
	return fmt.Sprintf("the PCR %s missing from the TCG log but active and with one or more empty PCRs on the TPM", s)
}

func isEmptyPCRBanksError(err error) bool {
	var e *EmptyPCRBanksError
	return errors.As(err, &e)
}

// NoSuitablePCRAlgorithmError is returned wrapped in [MeasuredBootError] if it wasn't possible to
// select a suitable PCR bank, which may happen under the following conditions:
//   - The TCG log doesn't contain digests for a supported digest algorithm (SHA-256, SHA-384
//     or SHA-512).
//   - The TCG log is inconsistent with the TPM values when the log is reconstructed for one
//     or more mandatory PCRs, for all algorithms in the log.
//   - PCR 0 is mandatory and there is an issue with the way that the startup locality event
//     (if present) is recorded.
//   - There is a problem with the sequence of measurements that isn't specific to a PCR or
//     a PCR bank, and which is incompatible with predicting PCR policies.
//
// As multiple errors can occur during testing, this error wraps each individual error that
// occurred and provides access to them, keyed by the PCR bank. Where an error is related to
// a specific PCR, the error will be wrapped by one of the PCR-specific error types:
// [PlatformFirmwarePCRError] (0), [PlatformConfigPCRError] (1), [DriversAndAppsPCRError] (2),
// [DriversAndAppsConfigPCRError] (3), [BootManagerCodePCRError] (4), [BootManagerConfigPCRError]
// (5), or [SecureBootPolicyPCRError] (7).
type NoSuitablePCRAlgorithmError struct {
	Errs map[tpm2.HashAlgorithmId][]error
}

func newNoSuitablePCRAlgorithmError() *NoSuitablePCRAlgorithmError {
	return &NoSuitablePCRAlgorithmError{
		Errs: make(map[tpm2.HashAlgorithmId][]error),
	}
}

func (e *NoSuitablePCRAlgorithmError) Error() string {
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "no suitable PCR algorithm available:\n")

	// Note that this function iterates over the supportedAlgs slice rather than
	// the map directly to ensure consistent ordering (which go maps don't guarantee
	// when iterating over keys).
	for _, alg := range supportedAlgs {
		for _, err := range e.Errs[alg] {
			fmt.Fprintf(w, "- %v: %v.\n", alg, err)
		}
	}
	return w.String()
}

// addErr adds an error for the specified PCR bank
func (e *NoSuitablePCRAlgorithmError) addErr(alg tpm2.HashAlgorithmId, err error) {
	e.Errs[alg] = append(e.Errs[alg], err)
}

func (e *NoSuitablePCRAlgorithmError) isEmpty() bool {
	return len(e.Errs) == 0
}

// MeasuredBootError is returned unwrapped from [RunChecks] if there is a general issue with
// or detected from the TCG measurement log supplied by the firmware.
type MeasuredBootError struct {
	err error
}

func (e *MeasuredBootError) Error() string {
	return "error with or detected from measurement log: " + e.err.Error()
}

func (e *MeasuredBootError) Unwrap() error {
	return e.err
}

// Errors related to platform firmware PCR checks

// PlatformFirmwarePCRError may be returned if the PCR 0 value is inconsistent with
// the value reconstructed from the TCG log or there is an issue with the way the
// startup locality event (if present) is recorded.
//
// If an error occurs, this error will be returned as a warning in [CheckResult] if
// the PlatformFirmwareProfileSupportRequired flag is not supplied to [RunChecks],
// to indicate that [github.com/snapcore/secboot/efi.WithPlatformFirmwareProfile]
// cannot be used to generate profiles for PCR 0.
//
// If an error occurs, this error will be returned wrapped in
// [NoSuitablePCRAlgorithmError] if the PlatformFirmwareProfileSupportRequired flag
// is supplied to [RunChecks].
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

// PlatformConfigPCR may be returned if the PCR 1 value is inconsistent with the
// value reconstructed from the TCG log.
//
// This error will currently always be returned as a warning in [CheckResult] if
// the PlatformConfigProfileSupportRequired flag is not supplied to [RunChecks],
// because there is currently no support in [github.com/snapcore/secboot/efi] for
// generating profiles for PCR 1.
//
// This error will be returned wrapped wrapped in [NoSuitablePCRAlgorithmError]
// if the PlatformConfigProfileSupportRequired flag is supplied to [RunChecks]
// and the PCR 1 value is inconsistent with the value recorded from the TCG log.
//
// This error will otherwise currently always be returned wrapped in
// [RunChecksErrors] if the PlatformConfigProfileSupportRequired flag is supplied
// to [RunChecks] because there is currently no support in
// [github.com/snapcore/secboot/efi] for generating profiles for PCR 1.
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

// DriversAndAppsError may be returned if the PCR 2 value is inconsistent with the
// value reconstructed from the TCG log.
//
// If an error occurs, this error will be returned as a warning in [CheckResult] if
// the DriversAndAppsProfileSupportRequired flag is not supplied to [RunChecks],
// to indicate that [github.com/snapcore/secboot/efi.WithDriversAndAppsProfile]
// cannot be used to generate profiles for PCR 2.
//
// If an error occurs, this error will be returned wrapped in
// [NoSuitablePCRAlgorithmError] if the DriversAndAppsProfileSupportRequired flag
// is supplied to [RunChecks].
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

// DriversAndAppsConfigPCRError may be returned if the PCR 3 value is inconsistent
// with the value reconstructed from the TCG log.
//
// This error will currently always be returned as a warning in [CheckResult] if
// the DriversAndAppsConfigProfileSupportRequired flag is not supplied to
// [RunChecks], because there is currently no support in
// [github.com/snapcore/secboot/efi] for generating profiles for PCR 3.
//
// This error will be returned wrapped wrapped in [NoSuitablePCRAlgorithmError]
// if the DriversAndAppsConfigProfileSupportRequired flag is supplied to
// [RunChecks] and the PCR 3 value is inconsistent with the value recorded from
// the TCG log.
//
// This error will otherwise currently always be returned wrapped in
// [RunChecksErrors] if the DriversAndAppsConfigProfileSupportRequired flag is
// supplied to [RunChecks] because there is currently no support in
// [github.com/snapcore/secboot/efi] for generating profiles for PCR 3.
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

// BootManagerCodePCRError may be returned if the PCR 4 value is inconsistent with
// the value reconstructed from the TCG log, or if there are any other errors with
// the way that measurements are performed to PCR 4, or any errors occur when
// checking the measurements performed to PCR 4, eg:
//   - Errors that occur when trying to read required EFI variables.
//   - Event data decode errors from PCR 4 events in the TCG log.
//   - Duplicated EV_OMIT_BOOT_DEVICE_EVENTS event.
//   - Unexpected or misplaced EV_EFI_ACTION events.
//   - EV_EFI_BOOT_SERVICES_APPLICATION events that occur before secure boot policy
//     is measured.
//   - Unexpected event types before the OS-present phase.
//   - The presence of system prepartion apps when the firmware indicates they are
//     not supported.
//   - EV_EFI_BOOT_SERVICES_APPLICATION events that occur in the OS-present phase
//     but aren't associated with the OS launch or Absolute.
//   - Duplicated EV_EFI_BOOT_SERVICES_APPLICATION events associated with Absolute.
//   - It wasn't possible to check the EV_EFI_BOOT_SERVICES_APPLICATION event digests
//     are consistent with the current IBL (initial boot loader) and SBL (secondary
//     boot loader) because they were not supplied to [RunChecks].
//   - The EV_EFI_BOOT_SERVICES_APPLICATION event digests are not consistent with
//     the Authenticode digests of the current boot applications, as supplied to
//     [RunChecks].
//
// If an error occurs, this error will be returned as a warning in [CheckResult] if
// the BootManagerCodeProfileSupportRequired flag is not supplied to [RunChecks],
// to indicate that [github.com/snapcore/secboot/efi.WithBootManagerCodeProfile]
// cannot be used to generate profiles for PCR 4.
//
// This error will be returned wrapped wrapped in [NoSuitablePCRAlgorithmError]
// if the BootManagerCodeProfileSupportRequired flag is supplied to [RunChecks]
// and the PCR 4 value is inconsistent with the value recorded from the TCG log.
//
// If any other error occurs and the BootManagerCodeProfileSupportRequired flag is
// supplied to [RunChecks], this error will be returned wrapped in [RunChecksErrors].
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

	// ErrNotAllBootManagerCodeDigestsVerified is returned wrapped in BootManagerCodePCRError
	// if it wasn't possible to verify the launch digest for every
	// EV_EFI_BOOT_SERVICES_APPLICATION event against a supplied set of launch applications
	// for the current boot. This is generally an error with the way the RunChecks is used
	// because the caller should supply each image for the current boot. This error can be
	// bypassed by supplying the PermitNotVerifyingAllBootManagerCodeDigests flag to RunChecks.
	ErrNotAllBootManagerCodeDigestsVerified = errors.New("not all EV_EFI_BOOT_SERVICES_APPLICATION boot manager launch digests could be verified")
)

// Errors related to boot manager config PCR checks

// BootManagerConfigPCRError may be returned if the PCR 5 value is inconsistent
// with the value reconstructed from the TCG log.
//
// This error will currently always be returned as a warning in [CheckResult] if
// the BootManagerConfigProfileSupportRequired flag is not supplied to [RunChecks],
// because there is currently no support in [github.com/snapcore/secboot/efi]
// for generating profiles for PCR 5.
//
// This error will be returned wrapped wrapped in [NoSuitablePCRAlgorithmError]
// if the BootManagerConfigProfileSupportRequired flag is supplied to [RunChecks]
// and the PCR 5 value is inconsistent with the value recorded from the TCG log.
//
// This error will otherwise currently always be returned wrapped in
// [RunChecksErrors] if the BootManagerConfigProfileSupportRequired flag is
// supplied to [RunChecks] because there is currently no support in
// [github.com/snapcore/secboot/efi] for generating profiles for PCR 5.
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

// SecureBootPolicyPCRError may be returned if the PCR 7 value is inconsistent with
// the value reconstructed from the TCG log, or if there are any other errors with
// the way that measurements are performed to PCR 7, or any errors occur when
// checking the measurements performed to PCR 7, eg:
//   - Errors that occur when trying to read required EFI variables.
//   - Event data decode errors from PCR 7 events in the TCG log.
//   - The IBL (initial boot loader) for the current boot was not supplied to
//     [RunChecks].
//   - Secure boot is not enabled, or if supported, the system is not in deployed
//     mode, as [github.com/snapcore/secboot/efi.WithSecureBootPolicyProfile] only
//     generates profiles compatible with deployed mode.
//   - The firmware supports timestamp revocation or OS recovery, as these result
//     in additional measurements that are not yet supported by
//     [github.com/snapcore/secboot/efi.WithSecureBootPolicyProfile].
//   - There are insufficient, unexpected or out-of-order secure boot configuration
//     measurements.
//   - Measurement digests are not the tagged hash of the event data where that is
//     required.
//   - The variable data part of the event data for secure boot configuration events
//     is incorrectly formed (eg, SecureBoot is not a valid boolean, PK does not
//     contain a single X.509 EFI_SIGNATURE_LIST, other measurements do not contain
//     a valid signature database).
//   - Unexpected event types such as EV_EFI_ACTION events with the strings "UEFI
//     Debug Mode" (to indicate the presence of a firmware debugging endpoint) or
//     "DMA Protection Disabled" (to indicate that pre-boot DMA remapping was
//     disabled).
//   - Misplaced EV_EFI_VARIABLE_DRIVER_CONFIG or EV_EFI_VARIABLE_AUTHORITY events.
//   - The variable data part of the event data for secure boot verification events
//     is incorrectly formed (ie, not an EFI_SIGNATURE_DATA structure).
//   - There are EV_EFI_VARIABLE_AUTHORITY events measured by the firmware with
//     duplicate digests.
//   - There are EV_EFI_VARIABLE_AUTHORITY events measured by the firmware with
//     signatures that aren't present in the UEFI authorized signature database.
//   - There are EV_EFI_VARIABLE_AUTHORITY events measured by the firmware with
//     sources other than the UEFI authorized signature database.
//   - There is an EV_EFI_VARIABLE_AUTHORITY event during OS-present that isn't
//     followed immediately by an EV_EFI_BOOT_SERVICES_APPLICATION in PCR 4 for
//     the IBL launch.
//   - The secure boot signature attached to the IBL doesn't chain to a trust
//     anchor associated with an EV_EFI_VARIABLE_AUTHORITY event previously measured
//     by the firmware.
//   - There are EVI_EFI_VARIABLE_AUTHORITY events during OS-present that are
//     related to non X.509 EFI_SIGNATURE_LISTs.
//
// If an error occurs, this error will be returned as a warning in [CheckResult] if
// the SecureBootPolicyProfileSupportRequired flag is not supplied to [RunChecks],
// to indicate that [github.com/snapcore/secboot/efi.WithSecureBootPolicyProfile]
// cannot be used to generate profiles for PCR 7.
//
// This error will be returned wrapped wrapped in [NoSuitablePCRAlgorithmError]
// if the SecureBootPolicyProfileSupportRequired flag is supplied to [RunChecks]
// and the PCR 7 value is inconsistent with the value recorded from the TCG log.
//
// If any other error occurs and the SecureBootPolicyProfileSupportRequired flag is
// supplied to [RunChecks], this error will be returned wrapped in [RunChecksErrors].
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

// wrapPCRError wraps the supplied error with an error type for the specified PCR.
// This will panic if PCR isn't 0-5 or 7.
func wrapPCRError(pcr tpm2.Handle, err error) error {
	switch pcr {
	case 0:
		return &PlatformFirmwarePCRError{err}
	case 1:
		return &PlatformConfigPCRError{err}
	case 2:
		return &DriversAndAppsPCRError{err}
	case 3:
		return &DriversAndAppsConfigPCRError{err}
	case 4:
		return &BootManagerCodePCRError{err}
	case 5:
		return &BootManagerConfigPCRError{err}
	case 7:
		return &SecureBootPolicyPCRError{err}
	default:
		panic("invalid PCR")
	}
}

// UnsupportedReqiredPCRsError is returned from methods of [PCRProfileAutoEnablePCRsOption]
// when a valid PCR configuration cannot be created based on the supplied [PCRProfileOptionsFlags]
// and [CheckResult].
type UnsupportedRequiredPCRsError struct {
	PCRs tpm2.HandleList
}

func newUnsupportedRequiredPCRsError(required tpm2.HandleList, flags CheckResultFlags) *UnsupportedRequiredPCRsError {
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

	return &UnsupportedRequiredPCRsError{pcrs}
}

func (e *UnsupportedRequiredPCRsError) Error() string {
	switch len(e.PCRs) {
	case 1:
		return fmt.Sprintf("PCR %v is required, but is unsupported", e.PCRs[0])
	default:
		return fmt.Sprintf("PCRs %v are required, but are unsupported", e.PCRs)
	}
}
