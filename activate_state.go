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
// to define and supply reasons for calling [ActivateContext.DeactivateContainer]
// on a successfully unlocked storage container. This is intended to
// be used like an enum, with the user of the [ActivateContext] API
// defining the values.
type DeactivationReason string

// KeyslotErrorType describes the reason a keyslot failed when it was attempted.
type KeyslotErrorType string

const (
	KeyslotErrorNone                   KeyslotErrorType = ""
	KeyslotErrorIncompatibleRoleParams KeyslotErrorType = "incompatible-role-params" // The role parameters for the keyslot are not compatible with the current boot configuration.
	KeyslotErrorInvalidKeyData         KeyslotErrorType = "invalid-key-data"         // The keyslot metadata is invalid.
	KeyslotErrorInvalidPrimaryKey      KeyslotErrorType = "invalid-primary-key"      // The keyslot's primary key failed the primary key crosscheck.
	KeyslotErrorIncorrectUserAuth      KeyslotErrorType = "incorrect-user-auth"      // An incorrect user authorization was provided.
	KeyslotErrorPlatformFailure        KeyslotErrorType = "platform-failure"         // There was an error with the platform device.
	KeyslotErrorUnknown                KeyslotErrorType = "unknown"
)

func errorToKeyslotError(err error) KeyslotErrorType {
	if err == nil {
		return KeyslotErrorNone
	}

	if errors.Is(err, errInvalidPrimaryKey) {
		return KeyslotErrorInvalidPrimaryKey
	}

	var ikdErr *InvalidKeyDataError
	if errors.As(err, &ikdErr) {
		return KeyslotErrorInvalidKeyData
	}

	var ikdrErr *IncompatibleKeyDataRoleParamsError
	if errors.As(err, &ikdrErr) {
		return KeyslotErrorIncompatibleRoleParams
	}

	// XXX: Add the incorrect PIN error here as well.
	if errors.Is(err, ErrInvalidPassphrase) || errors.Is(err, errInvalidRecoveryKey) {
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

// ContainerActivateState contains the activation state for a single
// [StorageContainer].
type ContainerActivateState struct {
	Status             ActivationStatus            `json:"status"`                      // The overall activation status for this storage container.
	Keyslot            string                      `json:"keyslot,omitempty"`           // If the container was activated, the name of the keyslot used.
	DeactivateReason   DeactivationReason          `json:"deactivate-reason,omitempty"` // An argument supplied to ActivateContext.DeactivateContainer.
	KeyslotErrors      map[string]KeyslotErrorType `json:"keyslot-errors"`              // A map of errors for tried keyslots, keyed by name.
	KeyslotErrorsOrder []string                    `json:"keyslot-errors-order"`        // A list of keyslot names in order of failure.

	// CustomData provides a way for the user of the ActivateContext API
	// to save arbitrary custom JSON data, using the
	// WithCustomActivateStateData option.
	CustomData json.RawMessage `json:"custom-data,omitempty"`
}

// ActivateState contains the global activation state.
type ActivateState struct {
	// PrimaryKeyID is used to allow the primary key to be shared between
	// different ActivateContexts without storing the key in the state.
	PrimaryKeyID int32 `json:"primary-key-id"`

	// Activations contains state for each StorageContainer, keyed by
	// the credential name of the container.
	Activations map[string]*ContainerActivateState `json:"activations"`
}

// TotalActivatedContainers returns the total number of activated storage
// containers.
func (s *ActivateState) TotalActivatedContainers() (n int) {
	for _, state := range s.Activations {
		switch state.Status {
		case ActivationSucceededWithPlatformKey, ActivationSucceededWithRecoveryKey:
			n += 1
		}
	}

	return n
}

// NumActivatedContainersWithPlatformKey returns the number of storage
// containers activated with a platform key.
func (s *ActivateState) NumActivatedContainersWithPlatformKey() (n int) {
	for _, state := range s.Activations {
		switch state.Status {
		case ActivationSucceededWithPlatformKey:
			n += 1
		}
	}

	return n
}

// NumActivatedContainersWithPlatformKey returns the number of storage
// containers activated with a recovery key.
func (s *ActivateState) NumActivatedContainersWithRecoveryKey() (n int) {
	for _, state := range s.Activations {
		switch state.Status {
		case ActivationSucceededWithRecoveryKey:
			n += 1
		}
	}

	return n
}
