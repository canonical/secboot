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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
)

// ErrorKind describes an error detected during preinstall checks when
// using the [RunChecksContext] API.
type ErrorKind string

const (
	// ErrorKindNone indicates that no error occurred.
	ErrorKindNone ErrorKind = ""

	// ErrorKindInternal indicates that some kind of unexpected internal error
	// occurred that doesn't have a more appropriate error kind.
	ErrorKindInternal ErrorKind = "internal-error"

	// ErrorKindShutdownRequired indicates that a shutdown is required, and
	// is returned in response to some actions.
	ErrorKindShutdownRequired ErrorKind = "shutdown-required"

	// ErrorKindRebootRequired indicates that a reboot is required, and is
	// returned in response to some actions.
	ErrorKindRebootRequired ErrorKind = "reboot-required"

	// ErrorKindUnexpectedAction indicates that an action was supplied that
	// is unexpected because it isn't a remedial action associated with the
	// previously returned errors, or because the action is not supported.
	ErrorKindUnexpectedAction ErrorKind = "unexpected-action"

	// ErrorKindMissingArgument is returned if an action was supplied
	// that requires one or more arguments, but not enough arguments
	// are supplied.
	ErrorKindMissingArgument ErrorKind = "missing-argument"

	// ErrorKindInvalidArgument is returned if an action was supplied
	// that requires one or more arguments, but one or more of the
	// supplied arguments are of an invalid type of are an invalid value.
	// This will be accompanied with an argument of the type
	// InvalidActionArgumentDetails.
	ErrorKindInvalidArgument ErrorKind = "invalid-argument"

	// ErrorKindActionFailed indicates that the supplied action did not
	// succeed for some reason.
	ErrorKindActionFailed ErrorKind = "action-failed"

	// ErrorKindRunningInVM indicates that the current environment is a
	// virtal machine.
	ErrorKindRunningInVM ErrorKind = "running-in-vm"

	// ErrorKindSystemNotEFI indicates that the current host system is not
	// an EFI system.
	ErrorKindSystemNotEFI ErrorKind = "system-not-efi"

	// ErrorKindEFIVariableAccess indicates that an error occurred when accessing
	// an EFI variable. This will be supplied with a EFIVariableAccessErrorArg
	// as the argument, which details exactly what access error occurred. The
	// EFIVariableAccessErrorArg type describes the JSON format of the argument.
	ErrorKindEFIVariableAccess ErrorKind = "efi-variable-access"

	// ErrorKindNoSuitableTPM2Device indicates that the device has no
	// suitable TPM2 device. This is a fatal error. This error means that
	// full-disk encryption is not supported on this device.
	ErrorKindNoSuitableTPM2Device ErrorKind = "no-suitable-tpm2-device"

	// ErrorKindTPMDeviceFailure indicates that the TPM device has failed
	// an internal self check.
	ErrorKindTPMDeviceFailure ErrorKind = "tpm-device-failure"

	// ErrorKindTPMDeviceDisabled indicates that there is a TPM device
	// but it is currently disabled. Note that after enabling it, it may
	// still fail further checks which mean it is unsuitable.
	ErrorKindTPMDeviceDisabled ErrorKind = "tpm-device-disabled"

	// ErrorKindTPMHierarchiesOwned indicates that one or more TPM hierarchy
	// is currently owned, either because it has an authorization value or policy
	// set. This will be supplied with a TPM2OwnedHierarchiesError as the argument,
	// detailing which hierarchies are owned and whether they are owned with an
	// authorization value or an authorization policy. The TPM2OwnedHierarchiesError
	// type describes the JSON format of the argument.
	ErrorKindTPMHierarchiesOwned ErrorKind = "tpm-hierarchies-owned"

	// ErrorKindTPMDeviceLockoutLockedOut indicates that the TPM's lockout hierarchy
	// is currently unavailable because it is locked out. This is not the same as
	// ErrorKindTPMDeviceLockout. As there is no way to test for this other than
	// by performing an operation that requires authorizing the lockout hierarchy,
	// the test for this is only performed once verifying that the lockout hierarchy
	// has no authorization value set, and then an attempt is made to use the lockout
	// hierarchy with an empty authorization value. This will be accompanied with an
	// argument of the type TPMDeviceLockoutRecoveryArg. The TPMDeviceLockoutRecoveryArg
	// type describes the JSON format of the argument.
	ErrorKindTPMDeviceLockoutLockedOut ErrorKind = "tpm-device-lockout-locked-out"

	// ErrorKindInsufficientTPMStorage indicates that there isn't sufficient
	// storage space available to support FDE along with reprovisioning in
	// the future.
	ErrorKindInsufficientTPMStorage ErrorKind = "insufficient-tpm-storage"

	// ErrorKindNoSuitablePCRBank indicates that it was not possible to select
	// a suitable PCR bank. This could be because some mandatory PCR values are
	// inconsistent with the TCG log.
	// TODO: Expose some information about the error as arguments
	ErrorKindNoSuitablePCRBank ErrorKind = "no-suitable-pcr-bank"

	// ErrorKindMeasuredBoot indicates that there was an error with the TCG log
	// or some other error detected from the TCG log that isn't represented by
	// a more specific error kind.
	ErrorKindMeasuredBoot ErrorKind = "measured-boot"

	// ErrorKindEmptyPCRBanks indicates that one or more PCR banks thar are not
	// present in the TCG log are enabled but have unused PCRs in the TCG defined
	// space (ie, any of PCRs 0-7 are at their reset value). Whilst this isn't an
	// issue for the FDE use case because we can just select a good bank, it does
	// break remote attestation from this device, permitting an adversary to spoof
	// arbitrary trusted platforms by replaying PCR extends from software. This
	// will be accompanied with an argument of the type EmptyPCRBanksError. The
	// EmptyPCRBanksError type describes the JSON format of the arguments.
	ErrorKindEmptyPCRBanks ErrorKind = "empty-pcr-banks"

	// ErrorKindTPMCommandFailed indicates that an error occurred whilst
	// executing a TPM command. It will be accompanied with an argument of the
	// type TPMErrorResponse. The TPMErrorResponse type describes the JSON format
	// of the arguments.
	ErrorKindTPMCommandFailed ErrorKind = "tpm-command-failed"

	// ErrorKindInvalidTPMResponse indicates that the response from the TPM is
	// invalid, which makes it impossible to obtain a response code. This could
	// be because the response packet cannot be decoded, or one or more sessions
	// failed the response HMAC check.
	ErrorKindInvalidTPMResponse ErrorKind = "invalid-tpm-response"

	// ErrorKindTPMCommunication indicates that an error occurred at the transport
	// layer when executing a TPM command.
	ErrorKindTPMCommunication ErrorKind = "tpm-communication"

	// ErrorKindUnsupportedPlatform indicates that the current host platform is
	// not compatible with FDE. This generally occurs because the checks lack
	// the support for testing properties of the current platform, eg, whether
	// there is a correctly configured hardware RTM.
	ErrorKindUnsupportedPlatform ErrorKind = "unsupported-platform"

	// ErrorKindUEFIDebuggingEnabled indicates that the platform firmware currently
	// has a debugging endpoint enabled.
	ErrorKindUEFIDebuggingEnabled ErrorKind = "uefi-debugging-enabled"

	// ErrorKindInsufficientDMAProtection indicates that I/O DMA remapping was
	// disabled during the current boot cycle.
	ErrorKindInsufficientDMAProtection ErrorKind = "insufficient-dma-protection"

	// ErrorKindNoKernelIOMMU indicates that the OS kernel was not built with DMA
	// remapping support, or some configuration has resulted in it being disabled.
	ErrorKindNoKernelIOMMU ErrorKind = "no-kernel-iommu"

	// ErrorKindHostSecurity indicates that there is some problem with the system
	// security that isn't represented by a more specific error kind.
	ErrorKindHostSecurity ErrorKind = "host-security"

	// ErrorKindPCRUnusable indicates an error in the way that the platform
	// firmware performs measurements such that the PCR becomes unusable.
	// This will be accompanied by a PCRUnusableArg argument to indicate which PCR
	// is unusable. The implementation of PCRUnusableArg describes the JSON format
	// of the argument.
	ErrorKindPCRUnusable ErrorKind = "tpm-pcr-unusable"

	// ErrorKindPCRUnsupported indicates that a required PCR is currently unsupported
	// by the efi sub-package. This will be accompanied by a PCRUnsupportedArgs argument to
	// indicate the unsupported PCR and which contains a URL to a github issue. The
	// PCRUnsupportedArgs type describes the JSON format of the arguments.
	ErrorKindPCRUnsupported ErrorKind = "tpm-pcr-unsupported"

	// ErrorKindVARSuppliedDriversPresent indicates that drivers running from value-added-retailer
	// components were detected. Whilst these should generally be authenticated as part of the
	// secure boot chain and the digsts of the executed code measured to the TPM, the presence of
	// these does increase PCR fragility, and a user may choose not to trust this code (in which
	// case, they will need to disable it somehow).
	// TODO: it might be worth including the device paths from the launch events in PCR2 as an
	// argument.
	ErrorKindVARSuppliedDriversPresent ErrorKind = "var-supplied-drivers-present"

	// ErrorKindSysPrepApplicationsPresent indicates that system preparation applications were
	// detected to be running before the operating system. The OS does not use these and they
	// increase the fragility of PCR4 because they are beyond the control of the operating system.
	// In general, it is recommended that these are disabled.
	// TODO: it might be worth including the device paths from the launch events in PCR4 as an
	// argument.
	ErrorKindSysPrepApplicationsPresent ErrorKind = "sys-prep-applications-present"

	// ErrorKindAbsolutePresent indicates that Absolute was detected to be executing before the
	// initial OS loader. This is an endpoint management agent that is shipped with the platform
	// firmware. As it requires an OS component, it is generally recommended that this is disabled
	// via the firmware settings UI. Leaving it enabled does increase fragility of PCR4 because it
	// exposes it to changes via firmware updates.
	ErrorKindAbsolutePresent ErrorKind = "absolute-present"

	// ErrorKindInvalidSecureBootMode indicates that the secure boot mode is invalid. Either secure
	// boot is disabled or deployed mode is not enabled.
	ErrorKindInvalidSecureBootMode ErrorKind = "invalid-secure-boot-mode"

	// ErrorKindWeakSecureBootAlgorithmsDetected indicates that either pre-OS components were
	// authenticated with weak Authenticode digests, or CAs with weak public keys were used to
	// authenticate components. This check does have some limitations - for components other than
	// OS components, it is not possible to determine the properties of the signing key for signed
	// components - it is only possible to determine the properties of the trust anchor (the
	// certificate that is stored in db).
	ErrorKindWeakSecureBootAlgorithmsDetected ErrorKind = "weak-secure-boot-algorithms-detected"

	// ErrorKindPreOSDigestVerificationDetected indicates that pre-OS components were authenticated
	// by matching their Authenticode digest to an entry in db. This means that db has to change with
	// every firmware update, increasing the fragility of PCR7.
	// TODO: it might be worth attempting to match the verification with a corresponding
	// launch event from PCR2 or PCR4 to grab the device path and include it as an argument.
	ErrorKindPreOSDigestVerificationDetected ErrorKind = "pre-os-digest-verification-detected"
)

// PCRUnusableArg represents an unusable PCR handle that can be
// serialized to JSON.
type PCRUnusableArg tpm2.Handle

// MarshalJSON implements [json.Marshaler].
func (a PCRUnusableArg) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]tpm2.Handle{"pcr": tpm2.Handle(a)})
}

// UnmarshalJSON implements [json.Unmarshaler].
func (a *PCRUnusableArg) UnmarshalJSON(data []byte) error {
	var arg map[string]tpm2.Handle
	if err := json.Unmarshal(data, &arg); err != nil {
		return err
	}
	pcr, exists := arg["pcr"]
	if !exists {
		return errors.New("no \"pcr\" field")
	}
	*a = PCRUnusableArg(pcr)
	return nil
}

// PCR returns this argument as a PCR handle.
func (a PCRUnusableArg) PCR() tpm2.Handle {
	return tpm2.Handle(a)
}

// PCRUnsupportedArgs represents an unsupported PCR handle that can be
// serialized to JSON.
type PCRUnsupportedArgs struct {
	PCR tpm2.Handle `json:"pcr"` // The unsupported PCR.
	URL string      `json:"url"` // A URL to a github issue.
}

// InvalidActionArgumentReason specifies why an argument supplied with an
// action is invalid.
type InvalidActionArgumentReason string

const (
	InvalidActionArgumentReasonType  InvalidActionArgumentReason = "type"  // An argument type is invalid.
	InvalidActionArgumentReasonValue InvalidActionArgumentReason = "value" // An argument value is invalid.
)

// InvalidActionArgumentDetails provides information about an invalid
// argument supplied with an action.
type InvalidActionArgumentDetails struct {
	Field  string                      `json:"field"`  // The full name of the argument field, may be empty.
	Reason InvalidActionArgumentReason `json:"reason"` // Why the argument is invalid.
}

// String implements [fmt.Stringer].
func (a *InvalidActionArgumentDetails) String() string {
	return fmt.Sprintf("invalid action argument %q: invalid %s", a.Field, a.Reason)
}
