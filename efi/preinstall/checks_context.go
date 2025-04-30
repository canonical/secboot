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
		ErrorKindInsufficientTPMStorage: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to clear the TPM
			// TODO: Add actions to clear the TPM, either directly if possible or via the PPI
		},
		ErrorKindNoSuitablePCRBank: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to enable other PCR banks
			ActionContactOEM,         // suggest contacting the OEM because of a firmware bug
			// TODO: Add an action to reconfigure PCR banks via the PPI.
		},
		ErrorKindEmptyPCRBanks: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to disable the empty PCR bank
			ActionContactOEM,         // suggest contacting the OEM because of a firmware bug
			// TODO: Add an action to reconfigure PCR banks via the PPI
			// TODO: Add an action to add PermitEmptyPCRBanks to CheckFlags if the user is ok with accepting this.
		},
		ErrorKindUEFIDebuggingEnabled: []Action{
			ActionContactOEM, // suggest contacting the OEM because of a firmware bug
		},
		ErrorKindInsufficientDMAProtection: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to enable DMA protection.
		},
		ErrorKindNoKernelIOMMU: []Action{
			ActionContactOSVendor, // suggest contacting the OS vendor to supply a kernel with this feature enabled.
		},
		ErrorKindTPMStartupLocalityNotProtected: []Action{
			// TODO: Add an action to add PermitNoDiscreteTPMResetMitigation to CheckFlags
		},
		ErrorKindHostSecurity: []Action{
			ActionContactOEM, // suggest contacting the OEM because of a firmware bug or misconfigured root-of-trust
		},
		ErrorKindPCRUnusable: []Action{
			ActionContactOEM, // suggest contacting the OEM because of a firmware bug
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
func (c *RunChecksContext) classifyRunChecksError(err error) (ErrorKind, []any, error) {
	if errors.Is(err, ErrVirtualMachineDetected) {
		return ErrorKindRunningInVM, nil, nil
	}
	if errors.Is(err, ErrNoTPM2Device) || errors.Is(err, ErrNoPCClientTPM) {
		return ErrorKindNoSuitableTPM2Device, nil, nil
	}
	if errors.Is(err, ErrTPMFailure) {
		return ErrorKindTPMDeviceFailure, nil, nil
	}
	if errors.Is(err, ErrTPMDisabled) {
		return ErrorKindTPMDeviceDisabled, nil, nil
	}

	var ownershipErr *TPM2OwnedHierarchiesError
	if errors.As(err, &ownershipErr) {
		var args []any
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
		return ErrorKindTPMHierarchiesOwned, args, nil
	}

	if errors.Is(err, ErrTPMLockout) {
		var (
			lockoutCounter  uint32
			lockoutInterval uint32
		)
		dev, err := c.env.TPMDevice()
		if err != nil {
			// This shouldn't be possible - we just did some tests against a TPM device.
			return ErrorKindNone, nil, fmt.Errorf("cannot obtain TPM device: %w", err)
		}
		tpm, err := tpm2.OpenTPMDevice(dev)
		if err != nil {
			// Likewise, this also shouldn't be possible, for the same reason.
			return ErrorKindNone, nil, fmt.Errorf("cannot open TPM device: %w", err)
		}
		defer tpm.Close()

		var vals []uint32
		for _, prop := range []tpm2.Property{tpm2.PropertyLockoutCounter, tpm2.PropertyLockoutInterval} {
			val, err := tpm.GetCapabilityTPMProperty(prop)
			if err != nil {
				return ErrorKindNone, nil, fmt.Errorf("cannot read property %d: %w", prop, err)
			}
			vals = append(vals, val)
		}
		lockoutCounter = vals[0]
		lockoutInterval = vals[1]
		return ErrorKindTPMDeviceLockout, []any{time.Duration(lockoutInterval) * time.Second, time.Duration(lockoutInterval) * time.Second * time.Duration(lockoutCounter)}, nil
	}

	if errors.Is(err, ErrTPMInsufficientNVCounters) {
		return ErrorKindInsufficientTPMStorage, nil, nil
	}

	// This has to become before MeasuredBootError because that error wraps this one.
	var pcrAlgErr *NoSuitablePCRAlgorithmError
	if errors.As(err, &pcrAlgErr) {
		// RunChecks indicates that there is no suitable PCR bank. The possibilities here:
		// - One or more ErrPCRBankMissingFromLog errors for algorithms supported by this
		//   package that aren't present in the TCG log (SHA-512, SHA-384, SHA-256, and maybe
		//   SHA1).
		// - One or more PCR specific errors for mandatory PCRs, such as PCRValueMismatchError.
		return ErrorKindNoSuitablePCRBank, nil, nil
	}

	var mbErr *MeasuredBootError
	if errors.As(err, &mbErr) {
		return ErrorKindMeasuredBoot, nil, nil
	}

	var tpmErr *TPM2DeviceError
	if errors.As(err, &tpmErr) {
		tpmRsp, isTpmErr := errorAsTPMErrorResponse(err)
		switch {
		case isTpmErr:
			// TODO: Test this case
			return ErrorKindTPMCommandFailed, []any{tpmRsp}, nil
		case isInvalidTPMResponse(err):
			// TODO: Test this case
			return ErrorKindInvalidTPMResponse, nil, nil
		case isTPMCommunicationError(err):
			// TODO: Test this case
			return ErrorKindTPMCommunication, nil, nil
		}
	}

	var emptyPcrsErr *EmptyPCRBanksError
	if errors.As(err, &emptyPcrsErr) {
		var args []any
		for _, alg := range emptyPcrsErr.Algs {
			args = append(args, alg)
		}
		return ErrorKindEmptyPCRBanks, args, nil
	}

	var upErr *UnsupportedPlatformError
	if errors.As(err, &upErr) {
		// TODO: Add a test for this. To trigger this, we need to move
		// the TPM discreteness check to after the host security check, as
		// setting the CPU to an unknown type triggers an error there
		// instead. This will land in a follow-up PR.
		return ErrorKindUnsupportedPlatform, nil, nil
	}

	if errors.Is(err, ErrUEFIDebuggingEnabled) {
		return ErrorKindUEFIDebuggingEnabled, nil, nil
	}

	if errors.Is(err, ErrInsufficientDMAProtection) {
		return ErrorKindInsufficientDMAProtection, nil, nil
	}

	if errors.Is(err, ErrNoKernelIOMMU) {
		return ErrorKindNoKernelIOMMU, nil, nil
	}

	if errors.Is(err, ErrTPMStartupLocalityNotProtected) {
		return ErrorKindTPMStartupLocalityNotProtected, nil, nil
	}

	var hsErr *HostSecurityError
	if errors.As(err, &hsErr) {
		return ErrorKindHostSecurity, nil, nil
	}

	var pfPcrErr *PlatformFirmwarePCRError
	if errors.As(err, &pfPcrErr) {
		// XXX: It's currently impossible to hit this case
		return ErrorKindPCRUnusable, []any{internal_efi.PlatformFirmwarePCR}, nil
	}

	var pcPcrErr *PlatformConfigPCRError
	if errors.As(err, &pcPcrErr) {
		return ErrorKindPCRUnsupported, []any{internal_efi.PlatformConfigPCR, "https://github.com/canonical/secboot/issues/322"}, nil
	}

	if errors.Is(err, ErrVARSuppliedDriversPresent) {
		return ErrorKindVARSuppliedDriversPresent, nil, nil
	}

	var daPcrErr *DriversAndAppsPCRError
	if errors.As(err, &daPcrErr) {
		// XXX: It's currently impossible to hit this case
		return ErrorKindPCRUnusable, []any{internal_efi.DriversAndAppsPCR}, nil
	}

	var dacPcrErr *DriversAndAppsConfigPCRError
	if errors.As(err, &dacPcrErr) {
		return ErrorKindPCRUnsupported, []any{internal_efi.DriversAndAppsConfigPCR, "https://github.com/canonical/secboot/issues/341"}, nil
	}

	if errors.Is(err, ErrSysPrepApplicationsPresent) {
		return ErrorKindSysPrepApplicationsPresent, nil, nil
	}
	if errors.Is(err, ErrAbsoluteComputraceActive) {
		return ErrorKindAbsolutePresent, nil, nil
	}

	var bmcPcrErr *BootManagerCodePCRError
	if errors.As(err, &bmcPcrErr) {
		return ErrorKindPCRUnusable, []any{internal_efi.BootManagerCodePCR}, nil
	}

	var bmccPcrErr *BootManagerConfigPCRError
	if errors.As(err, &bmccPcrErr) {
		return ErrorKindPCRUnsupported, []any{internal_efi.BootManagerConfigPCR, "https://github.com/canonical/secboot/issues/323"}, nil
	}

	if errors.Is(err, ErrNoSecureBoot) || errors.Is(err, ErrNoDeployedMode) {
		return ErrorKindInvalidSecureBootMode, nil, nil
	}
	if errors.Is(err, ErrWeakSecureBootAlgorithmDetected) {
		return ErrorKindWeakSecureBootAlgorithmsDetected, nil, nil
	}
	if errors.Is(err, ErrPreOSVerificationUsingDigests) {
		return ErrorKindPreOSDigestVerificationDetected, nil, nil
	}

	var sbPcrErr *SecureBootPolicyPCRError
	if errors.As(err, &sbPcrErr) {
		return ErrorKindPCRUnusable, []any{internal_efi.SecureBootPolicyPCR}, nil
	}

	return ErrorKindInternal, nil, nil
}

func (c *RunChecksContext) runAction(action Action, args ...any) error {
	if !c.isActionExpected(action) {
		return &WithKindAndActionsError{
			Kind: ErrorKindUnexpectedAction,
			err:  errors.New("specified action is not expected"),
		}
	}

	if action.IsExternalAction() {
		return &WithKindAndActionsError{
			Kind: ErrorKindUnexpectedAction,
			err:  errors.New("specified action is not implemented directly by this package"),
		}
	}

	switch action {
	case ActionNone:
		// ok, do nothing
		return nil
	default:
		return &WithKindAndActionsError{
			Kind: ErrorKindUnexpectedAction,
			err:  errors.New("specified action is invalid"),
		}
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
// an error which will either be a single WithKindAndActionsError, or multiple WithKindAndActionsError
// wrapped by an error type that implements the [CompoundError] interface. If there are any
// actions associated with an error, the install environment may try one or more of them in
// order to try to resolve the issue that caused the error. In some cases, it may be appropriate
// to ask permission from the user to perform an action.
func (c *RunChecksContext) Run(ctx context.Context, action Action, args ...any) (*CheckResult, error) {
	if err := c.runAction(action, args...); err != nil {
		return nil, err
	}

	c.expectedActions = []Action{ActionNone}
	var errs []error
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

			// Reset the list of expected actions
			c.expectedActions = nil

			// Convert each error into WithKindAndActionsError
			for _, e := range unwrapCompoundError(err) {
				kind, args, err := c.classifyRunChecksError(e)
				if err != nil {
					return nil, &WithKindAndActionsError{
						Kind: ErrorKindInternal,
						err:  fmt.Errorf("cannot classify error %v: %w", e, err),
					}
				}
				jsonArgs, err := json.Marshal(args)
				if err != nil {
					return nil, &WithKindAndActionsError{
						Kind: ErrorKindInternal,
						err:  fmt.Errorf("cannot serialize error arguments: %w", err),
					}
				}
				actions := errorKindToActions[kind]
				actions, err = c.filterUnavailableActions(actions)
				if err != nil {
					return nil, &WithKindAndActionsError{
						Kind: ErrorKindInternal,
						err:  fmt.Errorf("cannot filter unavailable actions: %w", err),
					}
				}

				errs = append(errs, &WithKindAndActionsError{
					Kind:    kind,
					Args:    jsonArgs,
					Actions: actions,
					err:     e,
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
			return nil, &WithKindAndActionsError{
				Kind: ErrorKindInternal,
				err:  fmt.Errorf("cannot test whether a PCR combination can be generated: %w", err),
			}
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

	return nil, joinErrors(errs...)
}
