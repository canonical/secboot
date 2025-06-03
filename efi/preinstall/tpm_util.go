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

// TPMDeviceLockoutArgs are the arguments associated with errors with an [ErrorKind]
// of ErrorKindTPMDeviceLockout.
type TPMDeviceLockoutArgs struct {
	// IntervalDuration is the maximum amount of time it will
	// take for the lockout counter to reduce by one so that the lockout
	// clears, although it will only take a single authorization failure
	// to trigger the lockout again.
	IntervalDuration time.Duration `json:"interval-duration"`

	// TotalDuration is the maximum amount of time it will
	// take for the lockout counter to reduce to zero.
	TotalDuration time.Duration `json:"total-duration"`
}
