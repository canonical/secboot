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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/canonical/go-tpm2"
	secboot_efi "github.com/snapcore/secboot/efi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

var errorKindToActions map[ErrorKind][]Action

func init() {
	errorKindToActions = map[ErrorKind][]Action{
		ErrorKindShutdownRequired: []Action{
			ActionShutdown,
		},
		ErrorKindRebootRequired: []Action{
			ActionReboot,
		},
		ErrorKindRunningInVM: []Action{
			// TODO: Add action to add PermitVirtualMachine to CheckFlags
		},
		ErrorKindTPMDeviceFailure: []Action{
			ActionReboot,
			ActionContactOEM,
		},
		ErrorKindTPMDeviceDisabled: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to enable the TPM
			// TODO: Add actions to enable the TPM via the PPI
		},
		ErrorKindTPMHierarchiesOwned: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to clear the TPM
			// TODO: Add actions to clear the TPM, either directly if possible or via the PPI
			// TODO: Add action to clear the authorization values / policies
		},
		ErrorKindTPMDeviceLockout: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to clear the TPM
			// TODO: Add actions to clear the TPM, either directly if possible or via the PPI
			// TODO: Add action to clear the lockout.
		},
		ErrorKindInsufficientTPMCounters: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to clear the TPM
			// TODO: Add actions to clear the TPM, either directly if possible or via the PPI
		},
		ErrorKindNoSuitablePCRBank: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to enable other PCR banks
			ActionContactOEM,         // suggest contacting the OEM because of a firmware bug
			// TODO: Add an action to reconfigure PCR banks via the PPI.
		},
		ErrorKindPCRUnusable: []Action{
			ActionContactOEM, // suggest contacting the OEM because of a firmware bug
		},
		ErrorKindEmptyPCRBanks: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to disable the empty PCR bank
			ActionContactOEM,         // suggest contacting the OEM because of a firmware bug
			// TODO: Add an action to reconfigure PCR banks via the PPI
			// TODO: Add an action to add PermitEmptyPCRBanks to CheckFlags if the user is ok with accepting this.
		},
		ErrorKindTCGLog: []Action{
			ActionContactOEM, // suggest contacting the OEM because of a firmware bug
		},
		ErrorKindNoKernelIOMMU: []Action{
			ActionContactOSVendor, // suggest contacting the OS vendor to supply a kernel with this feature enabled.
		},
		ErrorKindPlatformFirmwareInsufficientProtection: []Action{
			ActionContactOEM, // suggest contacting the OEM because the platform firmware protections are not configured correctly.
		},
		ErrorKindVARSuppliedDriversPresent: []Action{
			// TODO: Add action to add PermitVARSuppliedDrivers to CheckFlags if they're necessary - this gives the
			// user the chance to be aware of their existence.
			// TODO: If the drivers are being loaded from BDS using DriverOrder and DriverXXXX variables, add action to delete these
		},
		ErrorKindSysPrepApplicationsPresent: []Action{
			// TODO: Add action to add PermitSysPrepApplications to CheckFlags if the user wants to keep them -
			// this gives the user the chance to be aware of their existence.
			// TODO: Add an action to just disable these by erasing the SysPrepOrder and SysPrepXXXX variables
		},
		ErrorKindAbsolutePresent: []Action{
			ActionContactOEM,         // suggest contacting the OEM if there's no way to disable it.
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to disable it.
			// TODO: Add action to add PermitAbsoluteComputrace to CheckFlags if the user doesn't want to
			// or can't disable it. This gives the user the chance to be aware of their existence.
			// TODO: Add an action to just disable this automatically on supported platforms (eg, Dell via the WMI interface)
		},
		ErrorKindInvalidSecureBootMode: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to properly configure secure boot
			// TODO: Add action to add PCRProfileOptionPermitNoSecureBootPolicyProfile to the PCRProfileOptionsFlags,
			//  noting that this flag will need to be subsequently passed to WithAutoTCGPCRProfile.
		},
		ErrorKindWeakSecureBootAlgorithmsDetected: []Action{
			// TODO: Add action to add PermitWeakSecureBootAlgorithms to CheckFlags.
		},
		ErrorKindPreOSDigestVerificationDetected: []Action{
			// TODO: Add action to add PermitPreOSVerificationUsingDigests to CheckFlags.
		},
	}
}

// ErrorKindAndActions describes an error and a set of potential remedial actions.
type ErrorKindAndActions struct {
	ErrorKind ErrorKind       `json:"kind"`    // The error kind
	ErrorArgs json.RawMessage `json:"args"`    // The arguments associated with the error, as a slice. See the documentation for the ErrorKind for the meaning of these.
	Error     error           `json:"-"`       // The original error. This is not serialized to JSON.
	Actions   []Action        `json:"actions"` // Potential remedial actions. This may be empty. Note that not all actions can be supplied to RunChecksContext.Run.
}

func (e ErrorKindAndActions) String() string {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Sprintf("invalid ErrorKindAndActions: %v", err)
	}
	return fmt.Sprintf("%s (original error: %q)", string(data), e.Error)
}

// singleErrorKindAndActions turns a single error kind, its arguments and actions into a slice of error kinds,
// as this is what is returned from [RunChecksContext.Run].
func singleErrorKindAndActions(kind ErrorKind, args any, err error, actions ...Action) []*ErrorKindAndActions {
	jsonArgs, jsonErr := json.Marshal(args)
	if jsonErr != nil {
		return singleErrorKindAndActions(ErrorKindInternal, nil, err)
	}
	return []*ErrorKindAndActions{{ErrorKind: kind, ErrorArgs: jsonArgs, Error: err, Actions: actions}}
}

// unpackRunChecksErrors unpacks a [RunChecksErrors], as [RunChecks]
// may return multiple errors in a single invocation.
func unpackRunChecksErrors(err error) []error {
	var rce *RunChecksErrors
	if errors.As(err, &rce) {
		return rce.Errs
	}
	return []error{err}
}

// RunChecksContext maintains context for multiple invocations of [RunChecks] to permit the
// install process to iterate and resolve detected issues where possible. It also reduces
// the burden of selecting an initial set of [CheckFlags].
type RunChecksContext struct {
	env          internal_efi.HostEnvironment
	flags        CheckFlags
	loadedImages []secboot_efi.Image
	profileOpts  PCRProfileOptionsFlags

	errs    []error
	lastErr error
	result  *CheckResult

	availableActions map[Action]bool
	expectedActions  []Action
}

// NewRunChecksContext returns a new RunChecksContext instance with the initial flags for [RunChecks]
// and the supplied list of boot components for the current boot (see the documentation for [RunChecks].
// The supplied [PCRProfileOptionsFlags] represent the preferred flags for [WithAutoTCGPCRProfile] and
// should match the flags later passed to this function when creating a PCR profile. The PCRs that are
// determined to be required to build the profile using [WithAutoTCGPCRProfile] will be made mandatory
// automatically by this function by passing the relevant flags to [RunChecks].
//
// As [PCRProfileOptionsFlags] is intended to provide some limited amount of user customisation, this
// API [RunChecksContext] should be executed again with the new set of flags, should the user wish to
// change them. In this case, the caller should pass the PostInstallChecks flag as an initial flag.
//
// There is no need for the caller to supply any of these *SupportRequired flags as the initial flags,
// and this may have the effect of limiting the number of devices which pass the checks.
func NewRunChecksContext(initialFlags CheckFlags, loadedImages []secboot_efi.Image, profileOpts PCRProfileOptionsFlags) *RunChecksContext {
	return &RunChecksContext{
		env:          runChecksEnv,
		flags:        initialFlags,
		loadedImages: loadedImages,
		profileOpts:  profileOpts,
		// Populate actions that are always available or available by default
		// unless we discover that they aren't later on.
		availableActions: map[Action]bool{
			ActionNone:               true,
			ActionReboot:             true,
			ActionShutdown:           true,
			ActionRebootToFWSettings: true,
			ActionContactOEM:         true,
			ActionContactOSVendor:    true,
		},
		expectedActions: []Action{ActionNone},
	}
}

// testActionAvailable will perform some tests in order to determine whether
// the specified action is available.
func (c *RunChecksContext) testActionAvailable(action Action) error {
	available := false

	switch action {
	// TODO: Populate with actions to test as we add them later on.
	}

	c.availableActions[action] = available
	return nil
}

// filterUnavailableActions will filter out any actions in the supplied slice
// that are unavailable, and return a new slice containing only actions that
// are available.
func (c *RunChecksContext) filterUnavailableActions(actions []Action) (out []Action, err error) {
	for _, action := range actions {
		available, tested := c.availableActions[action]
		switch {
		case !tested:
			if err := c.testActionAvailable(action); err != nil {
				return nil, fmt.Errorf("cannot test whether action %q is available: %w", action, err)
			}
			if available := c.availableActions[action]; available {
				out = append(out, action)
			}
		case available:
			out = append(out, action)
		}
	}

	return out, nil
}

// isActionExpected determines if the supplied action is an expected
// response to the last call to [RunChecksContext.Run].
func (c *RunChecksContext) isActionExpected(action Action) bool {
	for _, expected := range c.expectedActions {
		if expected == action {
			return true
		}
	}
	return false
}

// classifyRunChecksError converts the supplied error which is returned from
// [RunChecks] into an [ErrorKind] and associated arguments where applicable
// (see the documentation for each error kind).
func (c *RunChecksContext) classifyRunChecksError(err error) (kind ErrorKind, args []any) {
	if errors.Is(err, ErrVirtualMachineDetected) {
		return ErrorKindRunningInVM, nil
	}
	if errors.Is(err, ErrNoTPM2Device) || errors.Is(err, ErrNoPCClientTPM) {
		return ErrorKindNoSuitableTPM2Device, nil
	}
	if errors.Is(err, ErrTPMFailure) {
		return ErrorKindTPMDeviceFailure, nil
	}
	if errors.Is(err, ErrTPMDisabled) {
		return ErrorKindTPMDeviceDisabled, nil
	}

	var ownershipErr *TPM2OwnedHierarchiesError
	if errors.As(err, &ownershipErr) {
		for _, hierarchy := range ownershipErr.WithAuthValue {
			args = append(args, TPMHierarchyOwnershipInfo{
				Hierarchy: hierarchy,
				Type:      TPMHierarchyOwnershipAuthValue,
			})
		}
		for _, hierarchy := range ownershipErr.WithAuthPolicy {
			args = append(args, TPMHierarchyOwnershipInfo{
				Hierarchy: hierarchy,
				Type:      TPMHierarchyOwnershipAuthPolicy,
			})
		}
		return ErrorKindTPMHierarchiesOwned, args
	}

	handleTpmCommandError := func(err error) (ErrorKind, []any) {
		tpmRsp, isTpmErr := errorAsTPMErrorResponse(err)
		switch {
		case isTpmErr:
			// TODO: Test this case
			return ErrorKindTPMCommandFailed, []any{tpmRsp}
		case isInvalidTPMResponse(err):
			// TODO: Test this case
			return ErrorKindInvalidTPMResponse, nil
		case isTPMCommunicationError(err):
			// TODO: Test this case
			return ErrorKindTPMCommunication, nil
		default:
			return ErrorKindInternal, nil
		}
	}

	if errors.Is(err, ErrTPMLockout) {
		var (
			lockoutCounter  uint32
			lockoutInterval uint32
		)
		dev, err := c.env.TPMDevice()
		if err != nil {
			// This shouldn't be possible - we just did some tests against a TPM device.
			return ErrorKindInternal, nil
		}
		tpm, err := tpm2.OpenTPMDevice(dev)
		if err != nil {
			// Likewise, this also shouldn't be possible, for the same reason.
			return ErrorKindInternal, nil
		}
		defer tpm.Close()

		var vals []uint32
		for _, prop := range []tpm2.Property{tpm2.PropertyLockoutCounter, tpm2.PropertyLockoutInterval} {
			val, err := tpm.GetCapabilityTPMProperty(prop)
			if err != nil {
				return handleTpmCommandError(err)
			}
			vals = append(vals, val)
		}
		lockoutCounter = vals[0]
		lockoutInterval = vals[1]
		return ErrorKindTPMDeviceLockout, []any{time.Duration(lockoutInterval) * time.Second, time.Duration(lockoutInterval) * time.Second * time.Duration(lockoutCounter)}
	}

	if errors.Is(err, ErrTPMInsufficientNVCounters) {
		return ErrorKindInsufficientTPMCounters, nil
	}

	var emptyPcrsErr *EmptyPCRBanksError
	if errors.As(err, &emptyPcrsErr) {
		return ErrorKindEmptyPCRBanks, []any{emptyPcrsErr.Algs}
	}

	// This has to become before TCGLogError because that error wraps this one.
	var pcrAlgErr *NoSuitablePCRAlgorithmError
	if errors.As(err, &pcrAlgErr) {
		// RunChecks indicates that there is no suitable PCR bank. The possibilities here:
		// - One or more ErrPCRBankMissingFromLog errors in the BankErrs field, for
		//   algorithms supported by this package that aren't present in the log
		//   (SHA-512, SHA-384, SHA-256, and maybe SHA1). If there is no good algorithm
		//   supported by this package present in the log, testing fails with this error
		//   in BankErrs.
		// - One or more TPM errors in the BankErrs field as a result of a failure to
		//   execute TPM2_PCR_Read for a specific PCR bank.
		// - One or more PCR specific errors in the PCRErrs field for a mandatory PCR,
		//   such as PCRValueMismatchError or some other arbitrary error as a result of
		//   testing the log. The PCRErrs field shouldn't contain any TPM errors in them.

		// First of all, search for TPM command errors and prioritize those.
		for _, err := range pcrAlgErr.BankErrs {
			if tpmErr, tpmErrArgs := handleTpmCommandError(err); tpmErr != ErrorKindInternal {
				// We encountered a TPM error response whilst executing a command to
				// test a bank - prioritize this in the return over any other error.
				return tpmErr, tpmErrArgs
			}
		}

		// We got through all of the errors in the BankErrs field without finding a
		// TPM error, so tell the caller that there is no suitable PCR bank.
		return ErrorKindNoSuitablePCRBank, nil
	}

	var logErr *TCGLogError
	if errors.As(err, &logErr) {
		return ErrorKindTCGLog, nil
	}

	var tpmErr *TPM2DeviceError
	if errors.As(err, &tpmErr) {
		return handleTpmCommandError(err)
	}

	if errors.Is(err, ErrNoKernelIOMMU) {
		// TODO: Test this case
		return ErrorKindNoKernelIOMMU, nil
	}

	var pfpErr *PlatformFirmwareProtectionError
	if errors.As(err, &pfpErr) {
		return ErrorKindPlatformFirmwareInsufficientProtection, nil
	}

	if errors.Is(err, ErrTPMStartupLocalityNotProtected) {
		// TODO: Test this case
		return ErrorKindTPMStartupLocalityNotProtected, nil
	}

	var pfPcrErr *PlatformFirmwarePCRError
	if errors.As(err, &pfPcrErr) {
		// XXX: It's currently impossible to hit this case
		return ErrorKindPCRUnusable, []any{internal_efi.PlatformFirmwarePCR}
	}

	var pcPcrErr *PlatformConfigPCRError
	if errors.As(err, &pcPcrErr) {
		return ErrorKindPCRUnsupported, []any{internal_efi.PlatformConfigPCR, "https://github.com/canonical/secboot/issues/322"}
	}

	if errors.Is(err, ErrVARSuppliedDriversPresent) {
		return ErrorKindVARSuppliedDriversPresent, nil
	}

	var daPcrErr *DriversAndAppsPCRError
	if errors.As(err, &daPcrErr) {
		// TODO: Test this case
		return ErrorKindPCRUnusable, []any{internal_efi.DriversAndAppsPCR}
	}

	var dacPcrErr *DriversAndAppsConfigPCRError
	if errors.As(err, &dacPcrErr) {
		return ErrorKindPCRUnsupported, []any{internal_efi.DriversAndAppsConfigPCR, "https://github.com/canonical/secboot/issues/341"}
	}

	if errors.Is(err, ErrSysPrepApplicationsPresent) {
		return ErrorKindSysPrepApplicationsPresent, nil
	}
	if errors.Is(err, ErrAbsoluteComputraceActive) {
		return ErrorKindAbsolutePresent, nil
	}

	var bmcPcrErr *BootManagerCodePCRError
	if errors.As(err, &bmcPcrErr) {
		// TODO: Test this case
		return ErrorKindPCRUnusable, []any{internal_efi.BootManagerCodePCR}
	}

	var bmccPcrErr *BootManagerConfigPCRError
	if errors.As(err, &bmccPcrErr) {
		return ErrorKindPCRUnsupported, []any{internal_efi.BootManagerConfigPCR, "https://github.com/canonical/secboot/issues/323"}
	}

	if errors.Is(err, ErrNoSecureBoot) || errors.Is(err, ErrNoDeployedMode) {
		return ErrorKindInvalidSecureBootMode, nil
	}
	if errors.Is(err, ErrWeakSecureBootAlgorithmDetected) {
		return ErrorKindWeakSecureBootAlgorithmsDetected, nil
	}
	if errors.Is(err, ErrPreOSVerificationUsingDigests) {
		return ErrorKindPreOSDigestVerificationDetected, nil
	}

	var sbPcrErr *SecureBootPolicyPCRError
	if errors.As(err, &sbPcrErr) {
		// TODO: Test this case
		return ErrorKindPCRUnusable, []any{internal_efi.SecureBootPolicyPCR}
	}

	return ErrorKindInternal, nil
}

func (c *RunChecksContext) runAction(action Action, args ...any) []*ErrorKindAndActions {
	if action.IsPseudoAction() {
		return singleErrorKindAndActions(ErrorKindUnexpectedAction, nil, errors.New("specified action is not implemented directly by this package"))
	}

	switch action {
	case ActionNone:
		// ok, do nothing
		return nil
	default:
		return singleErrorKindAndActions(ErrorKindUnexpectedAction, nil, errors.New("specified action is invalid"))
	}
}

// LastError returns the error from the last [RunChecks] invocation. If it completed
// successfully, this will return nil.
func (c *RunChecksContext) LastError() error {
	return c.lastErr
}

// Errors returns all errors from every [RunChecks] invocation.
func (c *RunChecksContext) Errors() []error {
	return c.errs
}

// Result returns the result from a successful invocation of [RunChecks]. This will
// be nil if it hasn't completed successfully yet.
func (c *RunChecksContext) Result() *CheckResult {
	return c.result
}

// Run will run the specified action, and if that completes successfully will run another
// iteration of [RunChecks] and test the result against the preferred [WithAutoTCGPCRProfile]
// configuration. On success, this will return the CheckResult. On failure, this will return
// one or more ErrorKindAndActions. If there are any actions associated with an error, the
// install environment may try one or more of them in order to try to resolve the issue that
// caused the error. In some cases, it may be appropriate to ask permission from the user to
// perform an action.
func (c *RunChecksContext) Run(ctx context.Context, action Action, args ...any) (*CheckResult, []*ErrorKindAndActions) {
	if !c.isActionExpected(action) {
		return nil, singleErrorKindAndActions(ErrorKindUnexpectedAction, nil, nil)
	}

	errKinds := c.runAction(action, args...)
	if len(errKinds) > 0 {
		return nil, errKinds
	}

	c.expectedActions = []Action{ActionNone}
	var kinds []*ErrorKindAndActions
	for {
		result, err := RunChecks(ctx, c.flags, c.loadedImages)
		c.lastErr = err

		var profileErr error
		if err == nil {
			// If RunChecks succeeded, test the result against the profile options
			// to see if we can generate a PCR combination.
			profile := WithAutoTCGPCRProfile(result, c.profileOpts)
			_, profileErr = profile.PCRs()
		}
		if err == nil && profileErr == nil {
			// If neither step failed, break and return success.
			c.result = result
			break
		}

		if err != nil {
			// If RunChecks failed, save its error and return the appropriate error kinds.
			c.errs = append(c.errs, err)

			for _, unpackedErr := range unpackRunChecksErrors(err) {
				kind, args := c.classifyRunChecksError(unpackedErr)
				if args == nil {
					args = []any{}
				}
				jsonArgs, err := json.Marshal(args)
				if err != nil {
					return nil, singleErrorKindAndActions(ErrorKindInternal, nil, fmt.Errorf("cannot serialize error arguments: %w", err))
				}
				actions := errorKindToActions[kind]
				actions, err = c.filterUnavailableActions(actions)
				if err != nil {
					return nil, singleErrorKindAndActions(ErrorKindInternal, nil, fmt.Errorf("cannot filter unavailable actions: %w", err))
				}

				kinds = append(kinds, &ErrorKindAndActions{
					ErrorKind: kind,
					ErrorArgs: jsonArgs,
					Error:     unpackedErr,
					Actions:   actions,
				})
				c.expectedActions = append(c.expectedActions, actions...)
			}

			break
		}

		// RunChecks succeeded but there was a profile error with the
		// current PCRProfileOptionsFlags. Most errors should tell us which
		// PCRs we're lacking support for.
		var requiredPCRsErr *UnsupportedRequiredPCRsError
		if !errors.As(profileErr, &requiredPCRsErr) {
			return nil, singleErrorKindAndActions(ErrorKindInternal, nil, fmt.Errorf("cannot test whether a PCR combination can be generated: %w", err))
		}

		// Make any PCRs we're lacking support for mandatory so that they end
		// up being returned in the RunChecks error on the next iteration,
		// which means we return a more appropriate set of error kinds.
		for _, pcr := range requiredPCRsErr.PCRs {
			switch pcr {
			case 0:
				c.flags |= PlatformFirmwareProfileSupportRequired
			case 1:
				c.flags |= PlatformConfigProfileSupportRequired
			case 2:
				c.flags |= DriversAndAppsProfileSupportRequired
			case 3:
				c.flags |= DriversAndAppsConfigProfileSupportRequired
			case 4:
				c.flags |= BootManagerCodeProfileSupportRequired
			case 5:
				c.flags |= BootManagerConfigProfileSupportRequired
			case 7:
				c.flags |= SecureBootPolicyProfileSupportRequired
			}
		}
	}

	if c.result != nil {
		return c.result, nil
	}
	return nil, kinds
}
