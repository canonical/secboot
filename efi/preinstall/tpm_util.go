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
	"time"

	"github.com/canonical/go-tpm2"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// TPMErrorResponse represents a TPM response that can be serialized to JSON.
type TPMErrorResponse struct {
	CommandCode  tpm2.CommandCode  `json:"command-code"`
	ResponseCode tpm2.ResponseCode `json:"response-code"`
}

// errorAsTPMErrorResponse determines whether the supplied error is an
// error associated with a TPM command, and returns a TPMErrorResponse
// and true if it is, else it returns (nil, false).
func errorAsTPMErrorResponse(err error) (*TPMErrorResponse, bool) {
	tpmErr := tpm2.AsTPMError(err, tpm2.AnyErrorCode, tpm2.AnyCommandCode)
	if tpmErr != nil {
		return &TPMErrorResponse{tpmErr.CommandCode(), tpmErr.ResponseCode()}, true
	}
	tpmWarn := tpm2.AsTPMWarning(err, tpm2.AnyWarningCode, tpm2.AnyCommandCode)
	if tpmWarn != nil {
		return &TPMErrorResponse{tpmWarn.CommandCode(), tpmWarn.ResponseCode()}, true
	}
	vendorErr := tpm2.AsTPMVendorError(err, tpm2.AnyVendorResponseCode, tpm2.AnyCommandCode)
	if vendorErr != nil {
		return &TPMErrorResponse{vendorErr.CommandCode(), vendorErr.ResponseCode()}, true
	}

	return nil, false
}

// isInvalidTPMResponse determines whether the supplied error is an
// error associated with a TPM response which prevents a response code
// from being obtained.
func isInvalidTPMResponse(err error) (yes bool) {
	var e *tpm2.InvalidResponseError
	return errors.As(err, &e)
}

// isTPMCommunicationError determines whether the supplied error is
// associated with a failure to communicate with the TPM.
func isTPMCommunicationError(err error) (yes bool) {
	var e *tpm2.TransportError
	return errors.As(err, &e)
}

// TPMDeviceLockoutRecoveryArg is the argument associated with errors with an [ErrorKind]
// of ErrorKindTPMDeviceLockoutLockedOut.
type TPMDeviceLockoutRecoveryArg time.Duration

// MarshalJSON implements [json.Marshaler].
func (r TPMDeviceLockoutRecoveryArg) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]time.Duration{"duration": time.Duration(r)})
}

// UnmarshalJSON implements [json.Unmarshaler].
func (r *TPMDeviceLockoutRecoveryArg) UnmarshalJSON(data []byte) error {
	var arg map[string]time.Duration
	if err := json.Unmarshal(data, &arg); err != nil {
		return err
	}
	duration, exists := arg["duration"]
	if !exists {
		return errors.New("no \"duration\" field")
	}
	*r = TPMDeviceLockoutRecoveryArg(duration)
	return nil
}

// Duration returns the maximum recovery duration for the lockout hierarchy
// to become available again. If it is zero, then it will become available
// after the next TPM reset or restart.
func (r TPMDeviceLockoutRecoveryArg) Duration() time.Duration {
	return time.Duration(r)
}

// LockoutClearsOnTPMStartupClear returns true if the lockout clears on the next
// TPM reset or restart, after which the lockout hierarchy will become available
// again. This is true if the lockout recovery duration is set to zero.
func (r TPMDeviceLockoutRecoveryArg) LockoutClearsOnTPMStartupClear() bool {
	return r.Duration() == time.Duration(0)
}

// IsValid indicates whether this argument is valid. In order to be valid,
// it must be a modulus of 1 second and not negative.
func (r TPMDeviceLockoutRecoveryArg) IsValid() bool {
	return time.Duration(r)%time.Second == 0 && r >= 0
}

func openTPMDevice(env internal_efi.HostEnvironment) (*tpm2.TPMContext, error) {
	device, err := env.TPMDevice()
	if err != nil {
		return nil, fmt.Errorf("cannot obtain TPM device: %w", err)
	}

	return tpm2.OpenTPMDevice(device)
}

func isLockoutHierarchyAuthValueSet(tpm *tpm2.TPMContext) (bool, error) {
	val, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	if err != nil {
		return false, err
	}

	return tpm2.PermanentAttributes(val)&tpm2.AttrLockoutAuthSet > 0, nil
}

func isOwnerClearDisabled(tpm *tpm2.TPMContext) (bool, error) {
	val, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	if err != nil {
		return false, err
	}

	return tpm2.PermanentAttributes(val)&tpm2.AttrDisableClear > 0, nil
}

// TPMAuthValueArg represents a TPM authorization value.
type TPMAuthValueArg []byte

// MarshalJSON implements [json.Marshaler].
func (v TPMAuthValueArg) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string][]byte{"auth-value": []byte(v)})
}

// UnmarshalJSON implements [json.Unmarshaler].
func (v *TPMAuthValueArg) UnmarshalJSON(data []byte) error {
	var m map[string][]byte
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	*v = TPMAuthValueArg(m["auth-value"])
	return nil
}

var errInvalidLockoutAuthValueSupplied = errors.New("supplied TPM lockout hierarchy authorization value is inconsistent with the value of the TPM_PT_PERMANENT lockoutAuthSet attribute")

func clearTPM(env internal_efi.HostEnvironment, lockoutAuthValue []byte) error {
	tpm, err := openTPMDevice(env)
	if err != nil {
		return fmt.Errorf("cannot open TPM device: %w", err)
	}
	defer tpm.Close()

	// Avoid tripping the lockout for the lockout hierarchy in some cases (if an empty auth
	// value is supplied but the lockout hierarchy has a non-empty value or if a non-empty
	// value is supplied but the lockout hierarchy has an empty value. We obviously can't
	// protect against the case where the lockout hierarchy has a non-empty value but an
	// incorrect non-empty value is supplied).
	requireAuthValue, err := isLockoutHierarchyAuthValueSet(tpm)
	if err != nil {
		return fmt.Errorf("cannot determine if TPM lockout hierarchy authorization value is set: %w", err)
	}
	switch requireAuthValue {
	case false:
		// The lockout hierarchy has an empty auth value, so we expect
		// to have been supplied with an empty value.
		if len(lockoutAuthValue) > 0 {
			return errInvalidLockoutAuthValueSupplied
		}
	case true:
		// The lockout hierarchy has a non-empty auth value, so we expect
		// to have been supplied with a non empty value.
		if len(lockoutAuthValue) == 0 {
			return errInvalidLockoutAuthValueSupplied
		}
	}

	tpm.LockoutHandleContext().SetAuthValue(lockoutAuthValue)

	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return fmt.Errorf("cannot start TPM session: %w", err)
	}
	defer tpm.FlushContext(session)

	if err := tpm.Clear(tpm.LockoutHandleContext(), session); err != nil {
		return fmt.Errorf("cannot clear TPM: %w", err)
	}

	return nil
}
