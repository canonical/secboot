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

// ActivationStatus describes the activation status for a storage container.
type ActivationStatus string

const (
	ActivationIncomplete               ActivationStatus = ""
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
//
// XXX: This will eventually be part of the serialized [ActivateState].
type DeactivationReason string

// ContainerActivateState contains the activation state for a single
// [StorageContainer].
type ContainerActivateState struct {
	Status ActivationStatus `json:"status"`
}

// ActivateState contains the global activation state.
type ActivateState struct {
	PrimaryKeyID int32 `json:"primary-key-id"`

	// Activations contains state for each StorageContainer, keyed by
	// credential name.
	Activations map[string]*ContainerActivateState `json:"activations"`
}

// TotalActivatedContainers returns the total number of activated storage
// containers.
func (s *ActivateState) TotalActivatedContainers() (n int) {
	if s.Activations == nil {
		return 0
	}

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
	if s.Activations == nil {
		return 0
	}

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
	if s.Activations == nil {
		return 0
	}

	for _, state := range s.Activations {
		switch state.Status {
		case ActivationSucceededWithRecoveryKey:
			n += 1
		}
	}

	return n
}
