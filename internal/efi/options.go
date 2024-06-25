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

package efi

import (
	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
)

type InitialVariablesModifier func(VariableSet) error

type PCRProfileOptionVisitor interface {
	// AddPCRs adds the supplied PCRs to the profile.
	AddPCRs(pcrs ...tpm2.Handle)

	// SetEnvironment overrides the host environment to the supplied environment.
	SetEnvironment(env HostEnvironmentEFI)

	// AddInitialVariablesModifier adds a function that will be called to allow
	// the initial variable set for profile generation to be modified.
	AddInitialVariablesModifier(fn InitialVariablesModifier)
}

// VariableSet corresponds to a set of EFI variables.
type VariableSet interface {
	// ReadVar reads the specified EFI variable for this set.
	ReadVar(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error)

	// WriteVar updates the specified EFI variable for this set, for
	// boot components that update variables. Each individual write
	// creates a new intitial set of variables for which a profile will be
	// generated against to accommodate interrupted sequences of writes.
	WriteVar(name string, guid efi.GUID, attrs efi.VariableAttributes, data []byte) error

	// Clone creates a copy of this variable set to make it possible to create
	// branches by setting variables to different values in each returned set.
	Clone() VariableSet
}
