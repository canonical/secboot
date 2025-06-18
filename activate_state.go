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

type ActivateState struct {
}
