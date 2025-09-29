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
	"time"

	"github.com/canonical/go-tpm2"
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
