// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
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

package secboot

import (
	"encoding/json"
	"errors"
)

// ActivationStatus describes the activation status for a storage container.
type ActivationStatus string

const (
	activationIncomplete ActivationStatus = ""

	ActivationFailed                   ActivationStatus = "failed"       // The container could not be unlocked
	ActivationSucceededWithPlatformKey ActivationStatus = "platform-key" // The container was unlocked with a normal platform key
	ActivationSucceededWithRecoveryKey ActivationStatus = "recovery-key" // The container was unlocked with a recovery key
	ActivationDeactivated              ActivationStatus = "deactivated"  // The container was subsequently deactivated.
)

// DeactivationReason permits the user of the [ActivateContext] API
// to define and supply reasons for calling [ActivateContext.DeactivatePath]
// on a successfully unlocked storage container. This is intended to
// be used like an enum, with the user of the [ActivateContext] API
// defining the values.
type DeactivationReason string

// KeyslotErrorType describes the reason a keyslot failed when it was attempted.
type KeyslotErrorType string

func errorToKeyslotError(err error) KeyslotErrorType {
	if errors.Is(err, errInvalidPrimaryKey) {
		return KeyslotErrorInvalidPrimaryKey
	}

	var ikdErr *InvalidKeyDataError
	if errors.As(err, &ikdErr) {
		return KeyslotErrorInvalidKeyData
	}

	var ikdrErr *IncompatibleKeyDataRoleError
	if errors.As(err, &ikdrErr) {
		return KeyslotErrorIncompatibleRole
	}

	if errors.Is(err, ErrInvalidPassphrase) || errors.Is(err, ErrInvalidPIN) || errors.Is(err, errInvalidRecoveryKey) {
		return KeyslotErrorIncorrectUserAuth
	}

	var (
		puErr  *PlatformUninitializedError
		pduErr *PlatformDeviceUnavailableError
	)
	if errors.As(err, &puErr) || errors.As(err, &pduErr) {
		return KeyslotErrorPlatformFailure
	}

	return KeyslotErrorUnknown
}

const (
	KeyslotErrorIncompatibleRole  KeyslotErrorType = "incompatible-role"
	KeyslotErrorInvalidKeyData    KeyslotErrorType = "invalid-key-data"
	KeyslotErrorInvalidPrimaryKey KeyslotErrorType = "invalid-primary-key"
	KeyslotErrorIncorrectUserAuth KeyslotErrorType = "incorrect-user-auth"
	KeyslotErrorPlatformFailure   KeyslotErrorType = "platform-failure"
	KeyslotErrorUnknown           KeyslotErrorType = "unknown"
)

type ContainerActivateState struct {
	Status           ActivationStatus            `json:"status"`                      // The overall activation status for this storage container.
	Keyslot          string                      `json:"keyslot,omitempty"`           // If the container was activated, the name of the keyslot used.
	DeactivateReason DeactivationReason          `json:"deactivate-reason,omitempty"` // An argument supplied to ActivateContext.DeactivatePath.
	KeyslotErrors    map[string]KeyslotErrorType `json:"keyslot-errors"`              // A map of errors for tried keyslots, keyed by name.

	// CustomData provides a way for the user of the [ActivateContext] API
	// to save arbitrary custom JSON data, using the
	// [WithCustomActivateStateData] option.
	CustomData json.RawMessage `json:"custom-data,omitempty"`
}

type ActivateState struct {
	PrimaryKeyID int                               `json:"primary-key-id"` // Used to propagate the key between ActivateContexts, without storing it in the state.
	Activations  map[string]ContainerActivateState `json:"activations"`    // A map of activation state, keyed by container path
}
