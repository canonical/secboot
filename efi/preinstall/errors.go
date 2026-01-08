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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// makeIndentedListItem turns the supplied string into a list item by prepending
// the supplied marker string (which could be a bullet point or numeric character)
// to the supplied string, useful for displaying multiple errors. In a multi-line
// string, subsequent lines in the supplied string will all be aligned with the start
// of the first line after the marker. The indentation argument specifies the
// indentation of the marker, in the number of characters.
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

// CompoundError is an interface for accessing wrapped errors from an error type that
// wraps more than one error. The [RunChecks] and [RunChecksContext.Run] APIs may return
// multiple errors that are wrapped by a type implementing this interface, as an
// alternative to aborting early and returning individual errors as they occur. This is
// to ensure as much information is gathered as possible.
type CompoundError interface {
	Unwrap() []error
}

func unwrapCompoundError(err error) []error {
	if err == nil {
		return nil
	}
	errs, ok := err.(CompoundError)
	if !ok {
		return []error{err}
	}
	return errs.Unwrap()
}

// joinError is a simple implementation of the type of the same name from the
// errors package in go 1.20, with slightly nicer formatting in the Error
// implementation.
type joinError struct {
	errs []error
}

func joinErrors(errs ...error) error {
	return &joinError{errs: errs}
}

func (e *joinError) Error() string {
	switch {
	case len(e.errs) == 0:
		return "internal error: empty joinError"
	case len(e.errs) == 1:
		return e.errs[0].Error()
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d errors detected:\n", len(e.errs))
	for _, err := range e.errs {
		io.WriteString(&b, makeIndentedListItem(0, "-", err.Error()))
	}
	return b.String()
}

func (e *joinError) Unwrap() []error {
	return e.errs
}

// MissingKernelModuleError is returned unwrapped from [RunChecks] to indicate that
// the specified kernel module is not built as part of the currently executing kernel,
// but is required to be loaded in order for tests to continue. The caller is expected
// to load the required kernel module, which it can obtain by calling
// [MissingKernelModuleError.Module].
type MissingKernelModuleError string

func (e MissingKernelModuleError) Error() string {
	return fmt.Sprintf("the kernel module %q must be loaded", string(e))
}

// Module returns the name of the kernel module associated with this error, and
// which should be loaded before calling [RunChecks].
func (e MissingKernelModuleError) Module() string {
	return string(e)
}

var (
	// ErrVirtualMachineDetected is returned unwrapped from RunChecks when the current
	// OS is running in a virtual machine and the PermitVirtualMachine flag was not supplied.
	// As parts of the TCB, such as the initial firmware code and the vTPM are under the control
	// of the host environment, a system running in a virtual machine offers little benefit other
	// than being useful for testing. This error can be bypassed with the PermitVirtualMachine flag,
	// in which case it will be returned as a warning via CheckResult. Note that if the
	// PermitVirtualMachine flag is provided and the current OS is running in a virtual machine,
	// the host security checks will be skipped.
	ErrVirtualMachineDetected = errors.New("virtual machine environment detected")
)

// EFIVariableAccessError describes an error that occurred when reading an EFI variable and
// is returned unwrapped from [RunChecks].
type EFIVariableAccessError struct {
	err error
}

func (e *EFIVariableAccessError) Error() string {
	return fmt.Sprintf("cannot access EFI variable: %v", e.err)
}

func (e *EFIVariableAccessError) Unwrap() error {
	return e.err
}

var (
	// ErrSystemNotEFI is returned unwrapped from RunChecks if the current host
	// system does not appear to be an EFI system.
	ErrSystemNotEFI = errors.New("host system is not an EFI system")
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

	// ErrNoPartialDiscreteTPMResetAttackMitigation is returned wrapped in HostSecurityError as
	// a warning in CheckResult if a partial mitigation against TPM reset attacks cannot be used
	// when required. See the documentation for RequestPartialDiscreteTPMResetAttackMitigation for
	// more information.
	ErrNoPartialDiscreteTPMResetAttackMitigation = errors.New("cannot enable partial mitigation against discrete TPM reset attacks")
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

	// ErrTPMLockout is returned wrapped in TPM2DeviceError as a warning if the TPM is in
	// DA lockout mode. This only applies to the protection that is provided to DA protected
	// resources other than the lockout hierarchy. This error is only returned as a warning
	// because the failedTries counter should be reset to zero as part of the install
	// process (eg, via a subsequent call to [secboot_tpm2.Connection.EnsureProvisioned])
	// and should be reset to zero as part of a successful boot. If the lockout hierarchy
	// cannot be used, ErrTPMLockoutLockedOut will be returned for that. If there is no
	// authorization value for the lockout hierarchy and the lockout hierarchy is available
	// when RunChecks is called, a DA lockout will be cleared as part of the checks and this
	// error will not be returned.
	ErrTPMLockout = errors.New("TPM is in DA lockout mode")

	// ErrTPMLockoutLockoutOut is returned wrapped in TPM2DeviceError if the TPM's
	// lockout hierarchy is unavailable because it is locked out. This is not the same as
	// ErrTPMLockout. As there is no way to test for this other than by attempting an
	// operation that requires authorization of the lockout hierarchy, this test is only
	// performed after first verifying that the lockout hierarchy is not protected by an
	// authorization value. If it isn't, then the test attempts to use the lockout hierarchy
	// with an empty authorization value in order to clear the DA counter using the
	// TPM2_DictionaryAttackLockReset command. If this operation fails with TPM_RC_LOCKOUT
	// then this error will be returned to indicate that the lockout hierarchy is unavailable
	// due to it being locked out. It will remain locked out for the pre-programmed
	// lockoutRecovery time, or until the TPM is cleared using the platform hierarchy.
	ErrTPMLockoutLockedOut = errors.New("TPM's lockout hierarchy is unavailable because it is locked out")

	// ErrTPMLockoutAvailabilityNotChecked is returned as a warning if the availability of
	// the lockout hierarchy cannot be checked because the lockout hierarchy has a non-empty
	// authorization value.
	ErrTPMLockoutAvailabilityNotChecked = errors.New("availability of TPM's lockout hierarchy was not checked because the lockout hierarchy has an authorization value set")

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
	// by VMs don't behave correctly here, so we account for that instead of returning
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
	// manufacturer, vendor name or firmware version. Resetting a device in failure mode
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
	WithAuthValue  tpm2.HandleList `json:"with-auth-value"`
	WithAuthPolicy tpm2.HandleList `json:"with-auth-policy"`
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
	Algs []tpm2.HashAlgorithmId `json:"algs"`
}

func (e *EmptyPCRBanksError) Error() string {
	var algs []string
	for _, alg := range e.Algs {
		algs = append(algs, fmt.Sprintf("%v", alg))
	}

	var s string
	switch len(algs) {
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
// the PermitNoPlatformFirmwareProfileSupport flag is supplied to [RunChecks],
// to indicate that [github.com/snapcore/secboot/efi.WithPlatformFirmwareProfile]
// cannot be used to generate profiles for PCR 0.
//
// If an error occurs, this error will be returned wrapped in
// [NoSuitablePCRAlgorithmError] if the PermitNoPlatformFirmwareProfileSupport flag
// is not supplied to [RunChecks].
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

// PlatformConfigPCRError may be returned if the PCR 1 value is inconsistent with the
// value reconstructed from the TCG log.
//
// This error will currently always be returned as a warning in [CheckResult] if
// the PermitNoPlatformConfigProfileSupport flag is supplied to [RunChecks],
// because there is currently no support in [github.com/snapcore/secboot/efi] for
// generating profiles for PCR 1.
//
// This error will be returned wrapped in [NoSuitablePCRAlgorithmError] if the
// PermitNoPlatformConfigProfileSupport flag is not supplied to [RunChecks] and the
// PCR 1 value is inconsistent with the value recorded from the TCG log.
//
// This error will otherwise currently always be returned wrapped in a type that
// implements [CompoundError] if the PermitNoPlatformConfigProfileSupport flag is
// not supplied to [RunChecks] because there is currently no support in
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

// DriversAndAppsPCRError may be returned if the PCR 2 value is inconsistent with the
// value reconstructed from the TCG log.
//
// If an error occurs, this error will be returned as a warning in [CheckResult] if
// the PermitNoDriversAndAppsProfileSupport flag is supplied to [RunChecks],
// to indicate that [github.com/snapcore/secboot/efi.WithDriversAndAppsProfile]
// cannot be used to generate profiles for PCR 2.
//
// If an error occurs, this error will be returned wrapped in
// [NoSuitablePCRAlgorithmError] if the PermitNoDriversAndAppsProfileSupport flag
// is not supplied to [RunChecks].
type DriversAndAppsPCRError struct {
	err error
}

func (e *DriversAndAppsPCRError) Error() string {
	return "error with drivers and apps (PCR2) measurements: " + e.err.Error()
}

func (e *DriversAndAppsPCRError) Unwrap() error {
	return e.err
}

// LoadedImageFormat describes the format of a loaded image.
type LoadedImageFormat string

const (
	// LoadedImageFormatPE is a PE image. These images are measured using the
	// EV_EFI_BOOT_SERVICES_DRIVER, EV_EFI_RUNTIME_SERVICES_DRIVER and
	// EV_EFI_BOOT_SERVICES_APPLICATION event types.
	LoadedImageFormatPE LoadedImageFormat = "pe"

	// LoadedImageFormatBlob is an opaque blob. These images are measured using
	// the EV_EFI_PLATFORM_FIRMWARE_BLOB and EV_EFI_PLATFORM_FIRMWARE_BLOB2
	// event types.
	LoadedImageFormatBlob LoadedImageFormat = "blob"
)

type devicePathJSON struct {
	String string `json:"string"`
	Bytes  []byte `json:"bytes"`
}

type loadedImageInfoJSON struct {
	Format         LoadedImageFormat `json:"format"`
	Description    string            `json:"description,omitempty"`
	LoadOptionName string            `json:"load-option-name,omitempty"`
	DevicePath     devicePathJSON    `json:"device-path"`
	DigestAlg      hashAlgorithmId   `json:"digest-alg"`
	Digest         []byte            `json:"digest"`
}

// LoadedImageInfo contains information about a loaded image, which may be a
// driver or system preparation application.
type LoadedImageInfo struct {
	// Format is the format of the loaded image.
	Format LoadedImageFormat

	// Description is a human readable description of the loaded image,
	// if there is one.
	Description string

	// LoadOptionName is the name of the EFI variable containing the
	// associated EFI_LOAD_OPTION if there is one. This can be empty for
	// option ROMs and is empty for firmware blobs.
	LoadOptionName string

	// DevicePath is the EFI device path of the loaded image if it is
	// known.
	DevicePath efi.DevicePath

	// DigestAlg is the algorithm of the digest in the Digest field.
	DigestAlg tpm2.HashAlgorithmId

	// Digest is the digest of the loaded image, using the algorithm
	// specified in the DigestAlg field. When Format is LoadedImageFormatPE,
	// this is the Authenticode digest.
	Digest tpm2.Digest
}

// MarshalJSON implements [json.Marshaler].
func (i *LoadedImageInfo) MarshalJSON() ([]byte, error) {
	pathBytes, err := i.DevicePath.Bytes()
	if err != nil {
		return nil, fmt.Errorf("cannot encode device path: %w", err)
	}

	info := &loadedImageInfoJSON{
		Format:         i.Format,
		Description:    i.Description,
		LoadOptionName: i.LoadOptionName,
		DevicePath: devicePathJSON{
			String: i.DevicePath.String(),
			Bytes:  pathBytes,
		},
		DigestAlg: hashAlgorithmId(i.DigestAlg),
		Digest:    i.Digest,
	}
	return json.Marshal(info)
}

// UnmarshalJSON implements [json.Unmarshaler].
func (i *LoadedImageInfo) UnmarshalJSON(data []byte) error {
	var info *loadedImageInfoJSON
	if err := json.Unmarshal(data, &info); err != nil {
		return err
	}

	path, err := efi.ReadDevicePath(bytes.NewReader(info.DevicePath.Bytes))
	if err != nil {
		return fmt.Errorf("cannot decode device path: %w", err)
	}

	*i = LoadedImageInfo{
		Format:         info.Format,
		Description:    info.Description,
		LoadOptionName: info.LoadOptionName,
		DevicePath:     path,
		DigestAlg:      tpm2.HashAlgorithmId(info.DigestAlg),
		Digest:         info.Digest,
	}
	return nil
}

// String implements [fmt.Stringer].
func (i *LoadedImageInfo) String() string {
	var b strings.Builder
	if i.Description != "" {
		io.WriteString(&b, i.Description)
	} else {
		io.WriteString(&b, "[no description]")
	}
	if len(i.DevicePath) > 0 {
		fmt.Fprintf(&b, " path=%s", i.DevicePath)
	}
	switch i.Format {
	case LoadedImageFormatPE:
		io.WriteString(&b, " authenticode-digest")
	default:
		io.WriteString(&b, " digest")
	}
	fmt.Fprintf(&b, "=%v:%x", i.DigestAlg, i.Digest)
	if i.LoadOptionName != "" {
		fmt.Fprintf(&b, " load-option=%s", i.LoadOptionName)
	}

	return b.String()
}

// AddonDriversPresentError is returned wrapped in a type that implements [CompoundError]
// if addon drivers are detected to be running. These can be running either because they
// are loaded by BDS by the presence of Driver#### load options and the DriverOrder global
// variable, or because firmware finds a loadable PE image in the ROM area of a connected
// PCI device. They are included in a PCR policy when using [secboot_efi.WithDriversAndAppsProfile].
// These can be permitted by supplying the PermitAddonDrivers flag to [RunChecks], in
// which case, this error will be returned as a warning via [CheckResult].
//
// The check for addon drivers may not execute if a [DriversAndAppsPCRError] is returned,
// either as an error or as a warning.
type AddonDriversPresentError struct {
	Drivers []*LoadedImageInfo
}

func (e *AddonDriversPresentError) Error() string {
	var b strings.Builder
	io.WriteString(&b, "addon drivers were detected")

	if len(e.Drivers) > 0 {
		io.WriteString(&b, ":\n")
		for _, info := range e.Drivers {
			fmt.Fprintf(&b, "- %s\n", info)
		}
	}

	return b.String()
}

// Errors related to drivers and apps config PCR checks

// DriversAndAppsConfigPCRError may be returned if the PCR 3 value is inconsistent
// with the value reconstructed from the TCG log.
//
// This error will currently always be returned as a warning in [CheckResult] if
// the PermitNoDriversAndAppsConfigProfileSupport flag is supplied to
// [RunChecks], because there is currently no support in
// [github.com/snapcore/secboot/efi] for generating profiles for PCR 3.
//
// This error will be returned wrapped in [NoSuitablePCRAlgorithmError] if the
// PermitNoDriversAndAppsConfigProfileSupport flag is not supplied to [RunChecks]
// and the PCR 3 value is inconsistent with the value recorded from the TCG log.
//
// This error will otherwise currently always be returned wrapped in a type that
// implements [CompoundError] if the PermitNoDriversAndAppsConfigProfileSupport flag
// is not supplied to [RunChecks] because there is currently no support in
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
//   - The presence of system preparation apps when the firmware indicates they are
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
// the PermitNoBootManagerCodeProfileSupport flag is supplied to [RunChecks],
// to indicate that [github.com/snapcore/secboot/efi.WithBootManagerCodeProfile]
// cannot be used to generate profiles for PCR 4.
//
// This error will be returned wrapped in [NoSuitablePCRAlgorithmError] if the
// PermitNoBootManagerCodeProfileSupport flag is not supplied to [RunChecks] and the
// PCR 4 value is inconsistent with the value recorded from the TCG log.
//
// If any other error occurs and the PermitNoBootManagerCodeProfileSupport flag is
// not supplied to [RunChecks], this error will be returned wrapped in a type that
// implements [CompoundError].
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
	// ErrAbsoluteComputraceActive is returned wrapped in a type that implements CompoundError
	// if Absolute was detected to be active. Absolute is an endpoint management component. As
	// it is a component of the firmware, it increases fragility of profiles that include
	// efi.WithBootManagerCodeProfile, which includes the measurement of Absolute. Therefore,
	// it is advised that this is disabled if possible.
	// This can be permitted by supplying the PermitAbsoluteComputrace flag to RunChecks,
	// in which case, this error is returned as a warning via CheckResult.
	//
	// The check for Absolute may not execute if a BootManagerCodePCRError error is returned,
	// either as an error or as a warning.
	ErrAbsoluteComputraceActive = errors.New("Absolute was detected to be active and it is advised that this is disabled")
)

// SysPrepApplicationsPresentError is returned wrapped in a type that implements [CompoundError]
// if system preparation applications were detected to be running. These are loaded by BDS as part
// of the pre-OS environment because there are SysPrep#### load options and a SysPrepOrder global
// variable defined. As these aren't under the control of the OS, these can increase fragility of
// profiles that include [secboot_efi.WithBootManagerCodeProfile], which includes the measurements
// of these applications. These can be permitted by supplying the PermitSysPrepApplications flag
// to [RunChecks], in which case, the error is returned as a warning via [CheckResult].
//
// The check for system preparation applications may not execute if a [BootManagerCodePCRError]
// is returned, either as an error or as a warning.
type SysPrepApplicationsPresentError struct {
	Apps []*LoadedImageInfo
}

func (e *SysPrepApplicationsPresentError) Error() string {
	var b strings.Builder
	io.WriteString(&b, "system preparation applications were detected")

	if len(e.Apps) > 0 {
		io.WriteString(&b, ":\n")
		for _, info := range e.Apps {
			fmt.Fprintf(&b, "- %s\n", info)
		}
	}

	return b.String()
}

// Errors related to boot manager config PCR checks

// BootManagerConfigPCRError may be returned if the PCR 5 value is inconsistent
// with the value reconstructed from the TCG log.
//
// This error will currently always be returned as a warning in [CheckResult] if
// the PermitNoBootManagerConfigProfileSupport flag is supplied to [RunChecks],
// because there is currently no support in [github.com/snapcore/secboot/efi]
// for generating profiles for PCR 5.
//
// This error will be returned wrapped in [NoSuitablePCRAlgorithmError] if the
// PermitNoBootManagerConfigProfileSupport flag is not supplied to [RunChecks] and
// the PCR 5 value is inconsistent with the value recorded from the TCG log.
//
// This error will otherwise currently always be returned wrapped in a type that
// implements [CompoundError] if the PermitNoBootManagerConfigProfileSupport flag
// is not supplied to [RunChecks] because there is currently no support in
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
// the PermitNoSecureBootPolicyProfileSupport flag is supplied to [RunChecks],
// to indicate that [github.com/snapcore/secboot/efi.WithSecureBootPolicyProfile]
// cannot be used to generate profiles for PCR 7.
//
// This error will be returned wrapped in [NoSuitablePCRAlgorithmError] if the
// PermitNoSecureBootPolicyProfileSupport flag is not supplied to [RunChecks] and
// the PCR 7 value is inconsistent with the value recorded from the TCG log.
//
// If any other error occurs and the PermitNoSecureBootPolicyProfileSupport flag is
// not supplied to [RunChecks], this error will be returned wrapped in a type that
// implements [CompoundError].
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

	// ErrWeakSecureBootAlgorithmDetected is returned wrapped in a type that implements CompoundError and
	// indicates that weak algorithms were detected during secure boot verification, such as authenticating
	// a binary with SHA-1, or a CA with a 1024-bit RSA public key, or the signer of the initial boot
	// loader having a 1024-bit RSA public key. This does have some limitations because the TCG log doesn't
	// indicate the properties of the actual signing certificates or the algorithms used to sign each
	// binary, so it's not possible to determine whether signing certificates for non-OS components are
	// strong enough.
	// This can be bypassed by supplying the PermitWeakSecureBootAlgorithms flag to RunChecks, in which case,
	// the error is returned as a warning via CheckResult.
	//
	// The check for weak secure boot algorithms may not execute if a SecureBootPolicyPCRError error is
	// returned, either as an error or as a warning.
	ErrWeakSecureBootAlgorithmDetected = errors.New("a weak cryptographic algorithm was detected during secure boot verification")

	// ErrPreOSVerificationUsingDigests is returned wrapped in a type that implements CompoundError and
	// indicates that pre-OS components were authenticated using Authenticode digests rather than a
	// X.509 certificate. This makes PCR7 inherently fragile with regards to firmware updates because db
	// has to be changed accordingly each time.
	// This can be bypassed by supplying the PermitPreOSVerificationUsingDigests flag to RunChecks, in
	// which case, the error is returned as a warning via CheckResult.
	//
	// The check for pre-OS components authenticated using a digest may not execute if a
	// SecureBootPolicyPCRError error is returned, either as an error or as a warning.
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

// UnsupportedRequiredPCRsError is returned from methods of [PCRProfileAutoEnablePCRsOption]
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

// WithKindAndActionsError is an error type that can be serialized to JSON, represented by
// an error kind, associated argument map and a set of potential remedial actions.
type WithKindAndActionsError struct {
	Kind    ErrorKind                  `json:"kind"`    // The error kind
	Args    map[string]json.RawMessage `json:"args"`    // A map of arguments associated with the error. See the documentation for the ErrorKind for the meaning of these.
	Actions []Action                   `json:"actions"` // Potential remedial actions. This may be empty. Note that not all actions can be supplied to RunChecksContext.Run.

	err error `json:"-"` // The original error. This is not serialized to JSON.
}

// NewWithKindAndActionsError returns a new WithKindAndActionsError for the specified
// error kind, arguments, actions and error. The arguments must be any value that can
// be serialized to a JSON map. If an argument cannot be serialized to a JSON map, this
// will panic with an error that explains why.
func NewWithKindAndActionsError(kind ErrorKind, args any, actions []Action, err error) *WithKindAndActionsError {
	// Serialize the supplied arguments to JSON.
	jsonArgs, jsonErr := json.Marshal(args)
	if jsonErr != nil {
		panic(fmt.Errorf("cannot serialize arguments to JSON: %w", jsonErr))
	}

	// Unserialize the serialized arguments to a JSON map, which
	// is how it will be stored.
	var jsonArgsMap map[string]json.RawMessage
	if jsonErr := json.Unmarshal(jsonArgs, &jsonArgsMap); jsonErr != nil {
		panic(fmt.Errorf("cannot deserialize arguments JSON to map: %w", jsonErr))
	}

	return &WithKindAndActionsError{
		Kind:    kind,
		Args:    jsonArgsMap,
		Actions: actions,
		err:     err,
	}
}

// GetArgByName returns the value of the argument with the specified name from the map
// of arguments. An error will be returned if the argument does not exist or is
// not valid JSON.
func (e *WithKindAndActionsError) GetArgByName(name string) (arg any, err error) {
	argJson, exists := e.Args[name]
	if !exists {
		return nil, fmt.Errorf("argument %q does not exist", name)
	}
	if err := json.Unmarshal(argJson, &arg); err != nil {
		return nil, fmt.Errorf("cannot deserialize argument %q from JSON: %w", name, err)
	}
	return arg, nil
}

// GetArgMap returns the arguments for this error as a map of any. An error will be
// returned if any of the arguments are not valid JSON.
func (e *WithKindAndActionsError) GetArgMap() (args map[string]any, err error) {
	args = make(map[string]any)
	for k, v := range e.Args {
		var arg any
		if err := json.Unmarshal(v, &arg); err != nil {
			return nil, fmt.Errorf("cannot deserialize argument %q from JSON: %w", k, err)
		}
		args[k] = arg
	}
	return args, nil
}

func (e *WithKindAndActionsError) Error() string {
	if e.err == nil {
		return "<nil>"
	}
	return e.err.Error()
}

func (e *WithKindAndActionsError) Unwrap() error {
	return e.err
}

// GetWithKindAndActionsErrorArg returns the argument map for a [WithKindAndActionsError]
// as the specified type. If any values in the argument map cannot be serialized or the
// serialized argument map cannot be unserialized to the specified type, an error will be
// returned. This is a global function due to go's restriction of not allowing methods of
// types to have arbitrary type parameters.
func GetWithKindAndActionsErrorArg[T any](e *WithKindAndActionsError) (T, error) {
	return GetValueFromJSONMap[T](e.Args)
}
