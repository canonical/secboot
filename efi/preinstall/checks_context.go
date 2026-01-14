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
	"github.com/canonical/go-tpm2/ppi"
	secboot_efi "github.com/snapcore/secboot/efi"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// errorKindToActions maps an error kind to one or more possible actions. The
// slice of actions is an OR in the sense that any one of these actions can
// be executed to attempt to resolve the associated error kind.
//
// The order of actions is significant as it represents the recommended order
// in which users should attempt to resolve issues. Actions should generally be
// ordered using the following rules in order of priority:
//  1. Fix error before ignoring error before giving up e.g.
//     [ActionRebootToFWSettings] to attempt to resolve the error before
//     [ActionProceed] (dynamically added) that ignores error before
//     [ActionContactOEM] that gives up.
//  2. Automatic actions before manual actions e.g. automatic PPI-based actions
//     and direct TPM commands are listed before manual actions that require
//     rebooting to firmware settings e.g. [ActionClearTPMViaFirmware] and
//     [ActionClearTPM] before [ActionRebootToFWSettings].
//  4. More reliable actions before less reliable actions e.g. [ActionClearTPMViaFirmware]
//     that is PPI-based before [ActionClearTPM] that uses TPM2_Clear which is more likely
//     to fail.
//  5. Less destructive actions before more destructive actions e.g.
//     [ActionEnableTPMViaFirmware] that only enables TPM before
//     [ActionEnableAndClearTPMViaFirmware] that also clears the TPM.
//  6. Simplest actions first e.g. [ActionClearTPMSimple] before
//     [ActionClearTPM].
var errorKindToActions map[ErrorKind][]Action

// errorKindToProceedFlag maps an error kind to a flag that can be set
// to ignore the error. Not all errors can be ignored in this way.
var errorKindToProceedFlag map[ErrorKind]CheckFlags

// unsupportedPcrs are the PCRs that are currently unsupported.
var unsupportedPcrs tpm2.HandleList

func init() {
	errorKindToActions = map[ErrorKind][]Action{
		ErrorKindShutdownRequired: []Action{
			ActionShutdown,
		},
		ErrorKindRebootRequired: []Action{
			ActionReboot,
		},
		ErrorKindEFIVariableAccess: []Action{
			ActionContactOEM,
		},
		ErrorKindTPMDeviceFailure: []Action{
			ActionReboot, // suggest rebooting to see if it clears the failure
			ActionContactOEM,
		},
		ErrorKindTPMDeviceDisabled: []Action{
			ActionEnableTPMViaFirmware,         // suggest enabling the TPM via the PPI
			ActionEnableAndClearTPMViaFirmware, // suggest enabling and clearing the TPM via the PPI
			ActionRebootToFWSettings,           // suggest rebooting to the firmware settings UI to enable the TPM
		},
		ErrorKindTPMHierarchiesOwned: []Action{
			ActionClearTPMViaFirmware,          // suggest clearing the TPM via the PPI
			ActionEnableAndClearTPMViaFirmware, // suggest enabling and clearing the TPM via the PPI
			ActionClearTPMSimple,               // suggest clearing the TPM using TPM2_Clear
			ActionClearTPM,                     // suggest clearing the TPM using TPM2_Clear
			ActionRebootToFWSettings,           // suggest rebooting to the firmware settings UI to clear the TPM
			// TODO: Add action to clear the authorization values / policies
		},
		ErrorKindTPMDeviceLockoutLockedOut: []Action{
			ActionClearTPMViaFirmware,          // suggest clearing the TPM via the PPI
			ActionEnableAndClearTPMViaFirmware, // suggest enabling and clearing the TPM via the PPI
			ActionRebootToFWSettings,           // suggest rebooting to the firmware settings UI to clear the TPM
			// There will be no option to clear the lockout as there isn't a mechanism to do this.
		},
		ErrorKindInsufficientTPMStorage: []Action{
			ActionClearTPMViaFirmware,          // suggest clearing the TPM via the PPI
			ActionEnableAndClearTPMViaFirmware, // suggest enabling and clearing the TPM via the PPI
			ActionClearTPMSimple,               // suggest clearing the TPM using TPM2_Clear
			ActionClearTPM,                     // suggest clearing the TPM using TPM2_Clear
			ActionRebootToFWSettings,           // suggest rebooting to the firmware settings UI to clear the TPM
		},
		ErrorKindNoSuitablePCRBank: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to enable other PCR banks
			ActionContactOEM,         // suggest contacting the OEM because of a firmware bug
			// TODO: Add an action to reconfigure PCR banks via the PPI.
		},
		ErrorKindInsufficientDMAProtection: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to enable DMA protection.
			ActionContactOEM,         // suggest contacting the OEM because of a firmware bug.
		},
		ErrorKindNoKernelIOMMU: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to enable DMA protection.
			ActionContactOSVendor,    // suggest contacting the OS vendor to supply a kernel with this feature enabled.
		},
		ErrorKindHostSecurity: []Action{
			ActionContactOEM, // suggest contacting the OEM because of a firmware bug or misconfigured root-of-trust
		},
		ErrorKindPCRUnusable: []Action{
			ActionContactOEM, // suggest contacting the OEM because of a firmware bug
		},
		ErrorKindAddonDriversPresent: []Action{
			// TODO: If the drivers are being loaded from BDS using DriverOrder and DriverXXXX variables, add action to delete these
		},
		ErrorKindSysPrepApplicationsPresent: []Action{
			// TODO: Add an action to just disable these by erasing the SysPrepOrder and SysPrepXXXX variables
		},
		ErrorKindAbsolutePresent: []Action{
			ActionRebootToFWSettings, // suggest rebooting to the firmware settings UI to disable it.
			ActionContactOEM,         // suggest contacting the OEM if there's no way to disable it.
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
		ErrorKindPreOSSecureBootAuthByEnrolledDigests: []Action{
			// TODO: Add action to add PermitPreOSSecureBootAuthByEnrolledDigests to CheckFlags.
		},
	}

	errorKindToProceedFlag = map[ErrorKind]CheckFlags{
		ErrorKindRunningInVM:                          PermitVirtualMachine,
		ErrorKindInsufficientDMAProtection:            PermitInsufficientDMAProtection,
		ErrorKindNoKernelIOMMU:                        PermitInsufficientDMAProtection,
		ErrorKindAddonDriversPresent:                  PermitAddonDrivers,
		ErrorKindSysPrepApplicationsPresent:           PermitSysPrepApplications,
		ErrorKindAbsolutePresent:                      PermitAbsoluteComputrace,
		ErrorKindWeakSecureBootAlgorithmsDetected:     PermitWeakSecureBootAlgorithms,
		ErrorKindPreOSSecureBootAuthByEnrolledDigests: PermitPreOSSecureBootAuthByEnrolledDigests,
	}

	unsupportedPcrs = tpm2.HandleList{
		internal_efi.PlatformConfigPCR,
		internal_efi.DriversAndAppsConfigPCR,
		internal_efi.BootManagerConfigPCR,
	}
}

type errorInfo struct {
	kind ErrorKind
	args any
	err  error
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

	// availableActions stores one of 3 states:
	// - untested (a lack of value), meaning that a test of availability needs to be performed.
	// - unavailable (a value of false).
	// - available (a value of true).
	availableActions map[Action]bool

	// expectedActions contains a slice of actions that are expected on a subsequent call
	// to Run. Trying to execute an action that is not in here will result in an error
	// being returned.
	expectedActions []Action

	// proceedFlags indicates the CheckFlags that can be enabled if Run is called
	// with ActionProceed.
	proceedFlags CheckFlags
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
// There is no need for the caller to specify any of the PermitNo*ProfileSupport flags as the initial
// flags, and they will be ignored anyway.
func NewRunChecksContext(initialFlags CheckFlags, loadedImages []secboot_efi.Image, profileOpts PCRProfileOptionsFlags) *RunChecksContext {
	defaultFlags := PermitNoPlatformFirmwareProfileSupport |
		PermitNoPlatformConfigProfileSupport |
		PermitNoDriversAndAppsProfileSupport |
		PermitNoDriversAndAppsConfigProfileSupport |
		PermitNoBootManagerCodeProfileSupport |
		PermitNoBootManagerConfigProfileSupport |
		PermitNoSecureBootPolicyProfileSupport
	return &RunChecksContext{
		env:          runChecksEnv,
		flags:        initialFlags | defaultFlags,
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
			ActionProceed:            true,
		},
	}
}

// testActionAvailable will perform some tests in order to determine whether
// the specified action is available.
func (c *RunChecksContext) testActionAvailable(action Action) error {
	available := false

	switch action {
	case ActionEnableTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMViaFirmware:
		var err error
		available, err = isPPIActionAvailable(c.env, action)
		if err != nil {
			return err
		}
	case ActionClearTPMSimple:
		tpm, err := openTPMDevice(c.env)
		if err != nil {
			return fmt.Errorf("cannot open TPM device: %w", err)
		}
		defer tpm.Close()

		clearDisabled, err := isOwnerClearDisabled(tpm)
		if err != nil {
			return fmt.Errorf("cannot determine if TPM owner clear is enabled: %w", err)
		}
		available = !clearDisabled

		if available {
			requireAuthValue, err := isLockoutHierarchyAuthValueSet(tpm)
			if err != nil {
				return fmt.Errorf("cannot determine if TPM lockout hierarchy authorization value is set: %w", err)
			}
			available = !requireAuthValue
		}
	case ActionClearTPM:
		tpm, err := openTPMDevice(c.env)
		if err != nil {
			return fmt.Errorf("cannot open TPM device: %w", err)
		}
		defer tpm.Close()

		clearDisabled, err := isOwnerClearDisabled(tpm)
		if err != nil {
			return fmt.Errorf("cannot determine if TPM owner clear is enabled: %w", err)
		}
		available = !clearDisabled
	}

	c.availableActions[action] = available
	return nil
}

// disableActionsOnLockoutHierarchyUnavailable marks actions that require the
// use of the TPMs lockout hierarchy as unavailable if the lockout hierarchy
// becomes unavailable.
func (c *RunChecksContext) disableActionsOnLockoutHierarchyUnavailable() {
	c.availableActions[ActionClearTPMSimple] = false
	c.availableActions[ActionClearTPM] = false
}

// filterUnavailableActions will filter out any actions in the supplied slice
// that are unavailable, and return a new slice containing only actions that
// are available.
func (c *RunChecksContext) filterUnavailableActions(info errorInfo, actions []Action) (out []Action, err error) {
	for _, action := range actions {
		if info.kind == ErrorKindPCRUnusable {
			var dropAction bool
			pcr := tpm2.Handle(info.args.(PCRUnusableArg))
			for _, unsupported := range unsupportedPcrs {
				if pcr == unsupported {
					// Drop actions for a PCR that we don't yet support.
					// The only assigned action is ActionContactOEM, but that's
					// not appropriate in this scenario.
					dropAction = true
					break
				}
			}
			if dropAction {
				continue
			}
		}

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
	if action == ActionNone {
		// ActionNone is always expected.
		return true
	}
	for _, expected := range c.expectedActions {
		if expected == action {
			return true
		}
	}
	return false
}

// insertActionProceed inserts [ActionProceed] into the actions slice.
// It inserts before [ActionContactOEM] or [ActionContactOSVendor] if present,
// otherwise appends to the end. This ensures [ActionProceed] (which ignores
// the error) appears before "give up" actions per Rule 1.
func insertActionProceed(actions []Action) []Action {
	for i, action := range actions {
		if action == ActionContactOEM || action == ActionContactOSVendor {
			// Create new slice with capacity for the additional action.
			result := make([]Action, len(actions)+1)
			copy(result, actions[:i])
			result[i] = ActionProceed
			copy(result[i+1:], actions[i:])
			return result
		}
	}
	return append(actions, ActionProceed)
}

// classifyRunChecksError converts the supplied error which is returned from
// [RunChecks] into an [ErrorKind] and associated arguments where applicable
// (see the documentation for each error kind).
//
// Note that certain errors can make some actions become unavailable.
func (c *RunChecksContext) classifyRunChecksError(err error) (info errorInfo, outErr error) {
	defer func() {
		if outErr != nil {
			return
		}

		// Ensure the returned errorInfo carries the original error
		info.err = err
	}()

	var me MissingKernelModuleError
	if errors.As(err, &me) {
		// A missing kernel module is an internal error because it's an
		// error with the way that the caller is using the API, and not
		// something that should be directly exposed to some UI.
		return errorInfo{kind: ErrorKindInternal}, nil
	}

	if errors.Is(err, ErrVirtualMachineDetected) {
		return errorInfo{kind: ErrorKindRunningInVM}, nil
	}
	if errors.Is(err, ErrSystemNotEFI) {
		return errorInfo{kind: ErrorKindSystemNotEFI}, nil
	}
	var efiErr *EFIVariableAccessError
	if errors.As(err, &efiErr) {
		arg := MakeEFIVariableAccessErrorArg(efiErr)
		return errorInfo{
			kind: ErrorKindEFIVariableAccess,
			args: arg,
		}, nil
	}
	if errors.Is(err, ErrNoTPM2Device) || errors.Is(err, ErrNoPCClientTPM) {
		return errorInfo{kind: ErrorKindNoSuitableTPM2Device}, nil
	}
	if errors.Is(err, ErrTPMFailure) {
		return errorInfo{kind: ErrorKindTPMDeviceFailure}, nil
	}
	if errors.Is(err, ErrTPMDisabled) {
		return errorInfo{kind: ErrorKindTPMDeviceDisabled}, nil
	}

	var ownershipErr *TPM2OwnedHierarchiesError
	if errors.As(err, &ownershipErr) {
		return errorInfo{
			kind: ErrorKindTPMHierarchiesOwned,
			args: ownershipErr,
		}, nil
	}

	if errors.Is(err, ErrTPMLockoutLockedOut) {
		// Actions that require the use of the lockout hierarchy are not available.
		c.disableActionsOnLockoutHierarchyUnavailable()

		tpm, err := openTPMDevice(c.env)
		if err != nil {
			// This shouldn't be possible - we just did some tests against a TPM device.
			return errorInfo{}, fmt.Errorf("cannot open TPM device: %w", err)
		}
		defer tpm.Close()

		val, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyLockoutRecovery)
		if err != nil {
			return errorInfo{}, fmt.Errorf("cannot read property %v: %w", tpm2.PropertyLockoutRecovery, err)
		}

		return errorInfo{
			kind: ErrorKindTPMDeviceLockoutLockedOut,
			args: TPMDeviceLockoutRecoveryArg(time.Duration(val) * time.Second),
		}, nil
	}

	if errors.Is(err, ErrTPMInsufficientNVCounters) {
		return errorInfo{kind: ErrorKindInsufficientTPMStorage}, nil
	}

	// This has to come before MeasuredBootError because that error wraps this one.
	var pcrAlgErr *NoSuitablePCRAlgorithmError
	if errors.As(err, &pcrAlgErr) {
		// RunChecks indicates that there is no suitable PCR bank. The possibilities here:
		// - One or more ErrPCRBankMissingFromLog errors for algorithms supported by this
		//   package that aren't present in the TCG log (SHA-512, SHA-384, SHA-256, and maybe
		//   SHA1).
		// - One or more PCR specific errors for mandatory PCRs, such as PCRValueMismatchError.
		return errorInfo{kind: ErrorKindNoSuitablePCRBank}, nil
	}

	var mbErr *MeasuredBootError
	if errors.As(err, &mbErr) {
		return errorInfo{kind: ErrorKindMeasuredBoot}, nil
	}

	var tpmErr *TPM2DeviceError
	if errors.As(err, &tpmErr) {
		tpmRsp, isTpmErr := errorAsTPMErrorResponse(err)
		switch {
		case isTpmErr:
			// TODO: Test this case
			return errorInfo{
				kind: ErrorKindTPMCommandFailed,
				args: tpmRsp,
			}, nil
		case isInvalidTPMResponse(err):
			// TODO: Test this case
			return errorInfo{kind: ErrorKindInvalidTPMResponse}, nil
		case isTPMCommunicationError(err):
			// TODO: Test this case
			return errorInfo{kind: ErrorKindTPMCommunication}, nil
		}
	}

	var upErr *UnsupportedPlatformError
	if errors.As(err, &upErr) {
		// TODO: Add a test for this. To trigger this, we need to move
		// the TPM discreteness check to after the host security check, as
		// setting the CPU to an unknown type triggers an error there
		// instead. This will land in a follow-up PR.
		return errorInfo{kind: ErrorKindUnsupportedPlatform}, nil
	}

	if errors.Is(err, ErrInsufficientDMAProtection) {
		return errorInfo{kind: ErrorKindInsufficientDMAProtection}, nil
	}

	if errors.Is(err, ErrNoKernelIOMMU) {
		return errorInfo{kind: ErrorKindNoKernelIOMMU}, nil
	}

	var hsErr *HostSecurityError
	if errors.As(err, &hsErr) {
		return errorInfo{kind: ErrorKindHostSecurity}, nil
	}

	var pfPcrErr *PlatformFirmwarePCRError
	if errors.As(err, &pfPcrErr) {
		// XXX: It's currently impossible to hit this case
		return errorInfo{
			kind: ErrorKindPCRUnusable,
			args: PCRUnusableArg(internal_efi.PlatformFirmwarePCR),
		}, nil
	}

	var pcPcrErr *PlatformConfigPCRError
	if errors.As(err, &pcPcrErr) {
		return errorInfo{
			kind: ErrorKindPCRUnusable,
			args: PCRUnusableArg(internal_efi.PlatformConfigPCR),
		}, nil
	}

	var adpErr *AddonDriversPresentError
	if errors.As(err, &adpErr) {
		return errorInfo{
			kind: ErrorKindAddonDriversPresent,
			args: LoadedImagesInfoArg(adpErr.Drivers),
		}, nil
	}

	var daPcrErr *DriversAndAppsPCRError
	if errors.As(err, &daPcrErr) {
		// XXX: It's currently impossible to hit this case
		return errorInfo{
			kind: ErrorKindPCRUnusable,
			args: PCRUnusableArg(internal_efi.DriversAndAppsPCR),
		}, nil
	}

	var dacPcrErr *DriversAndAppsConfigPCRError
	if errors.As(err, &dacPcrErr) {
		return errorInfo{
			kind: ErrorKindPCRUnusable,
			args: PCRUnusableArg(internal_efi.DriversAndAppsConfigPCR),
		}, nil
	}

	var spapErr *SysPrepApplicationsPresentError
	if errors.As(err, &spapErr) {
		return errorInfo{
			kind: ErrorKindSysPrepApplicationsPresent,
			args: LoadedImagesInfoArg(spapErr.Apps),
		}, nil
	}
	if errors.Is(err, ErrAbsoluteComputraceActive) {
		return errorInfo{kind: ErrorKindAbsolutePresent}, nil
	}

	var bmcPcrErr *BootManagerCodePCRError
	if errors.As(err, &bmcPcrErr) {
		return errorInfo{
			kind: ErrorKindPCRUnusable,
			args: PCRUnusableArg(internal_efi.BootManagerCodePCR),
		}, nil
	}

	var bmccPcrErr *BootManagerConfigPCRError
	if errors.As(err, &bmccPcrErr) {
		return errorInfo{
			kind: ErrorKindPCRUnusable,
			args: PCRUnusableArg(internal_efi.BootManagerConfigPCR),
		}, nil
	}

	if errors.Is(err, ErrNoSecureBoot) || errors.Is(err, ErrNoDeployedMode) {
		return errorInfo{kind: ErrorKindInvalidSecureBootMode}, nil
	}
	if errors.Is(err, ErrWeakSecureBootAlgorithmDetected) {
		return errorInfo{kind: ErrorKindWeakSecureBootAlgorithmsDetected}, nil
	}
	if errors.Is(err, ErrPreOSSecureBootAuthByEnrolledDigests) {
		return errorInfo{kind: ErrorKindPreOSSecureBootAuthByEnrolledDigests}, nil
	}

	var sbPcrErr *SecureBootPolicyPCRError
	if errors.As(err, &sbPcrErr) {
		return errorInfo{
			kind: ErrorKindPCRUnusable,
			args: PCRUnusableArg(internal_efi.SecureBootPolicyPCR),
		}, nil
	}

	return errorInfo{kind: ErrorKindInternal}, nil
}

func (c *RunChecksContext) runAction(action Action, args map[string]json.RawMessage) error {
	if !c.isActionExpected(action) {
		return NewWithKindAndActionsError(
			ErrorKindUnexpectedAction,
			nil, nil, // args, actions
			errors.New("specified action is not expected"),
		)
	}

	if action.IsExternalAction() {
		return NewWithKindAndActionsError(
			ErrorKindUnexpectedAction,
			nil, nil, // args, actions
			errors.New("specified action is not implemented directly by this package"),
		)
	}

	available, tested := c.availableActions[action]
	if !tested || !available {
		// This can happen if an action becomes unavailable after it
		// was returned and added to the list of expected actions.
		return NewWithKindAndActionsError(
			ErrorKindUnexpectedAction,
			nil, nil, // args, actions
			errors.New("specified action is no longer available"),
		)
	}

	switch action {
	case ActionNone:
		// ok, do nothing
		return nil
	case ActionEnableTPMViaFirmware, ActionEnableAndClearTPMViaFirmware, ActionClearTPMViaFirmware: // PPI actions
		result, err := runPPIAction(c.env, action)
		if err != nil {
			return NewWithKindAndActionsError(
				ErrorKindActionFailed,
				nil, nil, // args, actions
				err,
			)
		}

		// TODO: This uses an error to indicate partial success where a shutdown
		//  or reboot is required to complete the action. It needs a bit more
		//  thought because an error doesn't feel appropriate.
		var kind ErrorKind
		switch result {
		case ppi.StateTransitionShutdownRequired:
			kind = ErrorKindShutdownRequired
			err = errors.New("a shutdown is required to complete the action")
		case ppi.StateTransitionRebootRequired:
			kind = ErrorKindRebootRequired
			err = errors.New("a reboot is required to complete the action")
		}

		return NewWithKindAndActionsError(kind, nil, errorKindToActions[kind], err)
	case ActionClearTPMSimple:
		err := clearTPM(c.env, nil)
		switch {
		case errors.Is(err, errInvalidLockoutAuthValueSupplied):
			// This can happen if something sets the TPM's lockout hierarchy
			// authorization value after returning an error that permits this
			// action.
			return NewWithKindAndActionsError(
				ErrorKindUnexpectedAction,
				nil, nil, // args, actions
				fmt.Errorf("specified action is no longer available because the TPM's lockout hierarchy now has a non-empty auth value: use %q action instead", ActionClearTPM),
			)
			// TODO: In a future PR, maybe convert TPM response errors into
			// ErrorKindTPMCommandFailed, ErrorKindInvalidTPMResponse, or
			// ErrorKindTPMCommunication, wrapped in ErrorKindActionFailed?
		case err != nil:
			return NewWithKindAndActionsError(
				ErrorKindActionFailed,
				nil, nil, // args, actions
				err,
			)
		}
	case ActionClearTPM:
		const fieldName = "auth-value"

		var authValue TPMAuthValueArg
		if args != nil {
			var err error
			authValue, err = GetValueFromJSONMap[TPMAuthValueArg](args)
			if err != nil {
				return NewWithKindAndActionsError(
					ErrorKindInvalidArgument,
					InvalidActionArgumentDetails{
						// XXX: We assume that the field is "auth-value" in this case, but
						// we don't really know for sure. Try to address this later.
						Field:  fieldName,
						Reason: InvalidActionArgumentReasonType,
					},
					nil, // actions
					err,
				)
			}
		}

		err := clearTPM(c.env, authValue)
		switch {
		case errors.Is(err, errInvalidLockoutAuthValueSupplied):
			return NewWithKindAndActionsError(
				ErrorKindInvalidArgument,
				InvalidActionArgumentDetails{
					Field:  fieldName,
					Reason: InvalidActionArgumentReasonValue,
				},
				nil, // actions
				err,
			)
		case tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandClear, 1):
			// Actions that require the use of the lockout hierarchy are no longer available.
			c.disableActionsOnLockoutHierarchyUnavailable()

			return NewWithKindAndActionsError(
				ErrorKindInvalidArgument,
				InvalidActionArgumentDetails{
					Field:  fieldName,
					Reason: InvalidActionArgumentReasonValue,
				},
				nil, // actions
				err,
			)
			// TODO: In a future PR, maybe convert TPM response errors into
			// ErrorKindTPMCommandFailed, ErrorKindInvalidTPMResponse, or
			// ErrorKindTPMCommunication, wrapped in ErrorKindActionFailed?
		case err != nil:
			return NewWithKindAndActionsError(
				ErrorKindActionFailed,
				nil, nil, // args, actions
				err,
			)
		}
	case ActionProceed:
		var proceedFlags CheckFlags
		if args != nil {
			const fieldName = "error-kinds"

			kinds, err := GetValueFromJSONMap[ActionProceedArgs](args)
			if err != nil {
				return NewWithKindAndActionsError(
					ErrorKindInvalidArgument,
					InvalidActionArgumentDetails{
						// XXX: We assume that the field is "error-kinds" in this case, but
						// we don't really know for sure. Try to address this later.
						Field:  fieldName,
						Reason: InvalidActionArgumentReasonType,
					},
					nil, // actions
					err,
				)
			}

			for i, kind := range kinds {
				flag, ok := errorKindToProceedFlag[kind]
				if !ok {
					return NewWithKindAndActionsError(
						ErrorKindInvalidArgument,
						InvalidActionArgumentDetails{
							Field:  fieldName,
							Reason: InvalidActionArgumentReasonValue,
						},
						nil, // actions
						fmt.Errorf("invalid value for argument %q at index %d: %q does not support the %q action", fieldName, i, kind, ActionProceed),
					)
				}

				if c.proceedFlags&flag == 0 {
					return NewWithKindAndActionsError(
						ErrorKindInvalidArgument,
						InvalidActionArgumentDetails{
							Field:  fieldName,
							Reason: InvalidActionArgumentReasonValue,
						},
						nil, // actions
						fmt.Errorf("invalid value for argument %q at index %d: %q is not expected", fieldName, i, kind),
					)
				}

				proceedFlags |= flag
				c.proceedFlags &^= flag
			}
		}

		if proceedFlags == CheckFlags(0) {
			// Handle the case where no argument is supplied or
			// an empty []ErrorKind slice is supplied
			proceedFlags = c.proceedFlags
			c.proceedFlags = 0
		}

		c.flags |= proceedFlags
	default:
		return NewWithKindAndActionsError(
			ErrorKindUnexpectedAction,
			nil, nil, // args, actions
			errors.New("specified action is invalid"),
		)
	}

	return nil
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

// ProfileOpts returns the [PCRProfileOptionsFlags] that were specified when this
// context was created with [NewRunChecksContext].
func (c *RunChecksContext) ProfileOpts() PCRProfileOptionsFlags {
	return c.profileOpts
}

// Run will run the specified action, and if that completes successfully will run another
// iteration of [RunChecks] and test the result against the preferred [WithAutoTCGPCRProfile]
// configuration. On success, this will return the CheckResult. On failure, this will return
// an error which will either be a single WithKindAndActionsError, or multiple WithKindAndActionsError
// wrapped by an error type that implements the [CompoundError] interface. If there are any
// actions associated with an error, the install environment may try one or more of them in
// order to try to resolve the issue that caused the error. In some cases, it may be appropriate
// to ask permission from the user to perform an action.
func (c *RunChecksContext) Run(ctx context.Context, action Action, args map[string]json.RawMessage) (*CheckResult, error) {
	if err := c.runAction(action, args); err != nil {
		c.lastErr = err
		c.errs = append(c.errs, err)
		return nil, err
	}

	c.expectedActions = nil
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

			// Reset the list of expected actions.
			c.expectedActions = nil

			// Reset the flags that would be enabled if ActionProceed is used.
			c.proceedFlags = 0

			// errInfo contains the error kind and arguments for each error.
			var errInfo []errorInfo

			// Classify each error into an error kind and associated arguments and
			// save this information. We do this separate pass before creating
			// the WithKindAndActionsError because some errors encountered here
			// may change the available actions.
			for _, e := range unwrapCompoundError(err) {
				info, err := c.classifyRunChecksError(e)
				if err != nil {
					return nil, NewWithKindAndActionsError(
						ErrorKindInternal,
						nil, nil, // args, actions
						fmt.Errorf("cannot classify error %v: %w", e, err),
					)
				}

				errInfo = append(errInfo, info)
			}

			// Track whether ActionProceed can be added as an action to error
			// kinds that support this. Is true until we encounter an error kind
			// that doesn't permit it.
			permitActionProceed := true

			// Intermediate error slice so we can do a second pass over errors
			// that support ActionProceed, adding this action if possible and
			// ordering these errors to appear after all other errors.
			var errsProceed []*WithKindAndActionsError

			// Iterate over the error info, creating a WithKindAndActionsError
			// for each one with associated actions.
			for _, info := range errInfo {
				actions := errorKindToActions[info.kind]
				actions, err = c.filterUnavailableActions(info, actions)
				if err != nil {
					return nil, NewWithKindAndActionsError(
						ErrorKindInternal,
						nil, nil, // args, actions
						fmt.Errorf("cannot filter unavailable actions: %w", err),
					)
				}

				if _, canProceed := errorKindToProceedFlag[info.kind]; !canProceed {
					// This error kind doesn't support ActionProceed. Don't
					// permit it at all for now, waiting until all of the errors
					// we return support it.
					permitActionProceed = false
					errs = append(errs, NewWithKindAndActionsError(info.kind, info.args, actions, info.err))
				} else {
					errsProceed = append(errsProceed, NewWithKindAndActionsError(info.kind, info.args, actions, info.err))
				}

				c.expectedActions = append(c.expectedActions, actions...)
			}

			// Add ActionProceed to any error kinds that support it if it is allowed
			// right now, and append these errors to the list of errors we return.
			for _, e := range errsProceed {
				if permitActionProceed {
					flag := errorKindToProceedFlag[e.Kind]
					c.proceedFlags |= flag
					e.Actions = insertActionProceed(e.Actions)
				}
				errs = append(errs, e)
			}

			if c.proceedFlags != 0 {
				// We are returning errors with ActionProceed enabled.
				c.expectedActions = append(c.expectedActions, ActionProceed)
			}

			break
		}

		// RunChecks succeeded but there was a profile error with the
		// current PCRProfileOptionsFlags. Most errors should tell us which
		// PCRs we're lacking support for.
		var requiredPCRsErr *UnsupportedRequiredPCRsError
		if !errors.As(profileErr, &requiredPCRsErr) {
			return nil, NewWithKindAndActionsError(
				ErrorKindInternal,
				nil, nil, // args, actions
				fmt.Errorf("cannot test whether a PCR combination can be generated: %w", err),
			)
		}

		// Make any PCRs we're lacking support for mandatory so that they end
		// up being returned in the RunChecks error on the next iteration,
		// which means we return a more appropriate set of error kinds.
		for _, pcr := range requiredPCRsErr.PCRs {
			switch pcr {
			case 0:
				c.flags &^= PermitNoPlatformFirmwareProfileSupport
			case 1:
				c.flags &^= PermitNoPlatformConfigProfileSupport
			case 2:
				c.flags &^= PermitNoDriversAndAppsProfileSupport
			case 3:
				c.flags &^= PermitNoDriversAndAppsConfigProfileSupport
			case 4:
				c.flags &^= PermitNoBootManagerCodeProfileSupport
			case 5:
				c.flags &^= PermitNoBootManagerConfigProfileSupport
			case 7:
				c.flags &^= PermitNoSecureBootPolicyProfileSupport
			}
		}
	}

	if c.result != nil {
		return c.result, nil
	}

	return nil, joinErrors(errs...)
}
