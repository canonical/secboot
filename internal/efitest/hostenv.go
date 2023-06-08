// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package efitest

import (
	"errors"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
)

// MockHostEnvironment provides a mock EFI host environment.
type MockHostEnvironment struct {
	Vars MockVars
	Log  *tcglog.Log
}

// NewMockHostEnvironment returns a new MockHostEnvironment.
func NewMockHostEnvironment(vars MockVars, log *tcglog.Log) *MockHostEnvironment {
	return &MockHostEnvironment{
		Vars: vars,
		Log:  log}
}

// ReadVar implements [github.com/snapcore/secboot/efi.HostEnvironment.ReadVar].
func (e *MockHostEnvironment) ReadVar(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error) {
	if e.Vars == nil {
		return nil, 0, efi.ErrVarNotExist
	}
	entry, found := e.Vars[efi.VariableDescriptor{Name: name, GUID: guid}]
	if !found {
		return nil, 0, efi.ErrVarNotExist
	}
	return entry.Payload, entry.Attrs, nil
}

// ReadEventLog implements [github.com/snapcore/secboot/efi.HostEnvironment.ReadEventLog].
func (e *MockHostEnvironment) ReadEventLog() (*tcglog.Log, error) {
	if e.Log == nil {
		return nil, errors.New("nil log")
	}
	return e.Log, nil
}
