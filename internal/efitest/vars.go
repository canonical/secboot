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
	"bytes"
	_ "crypto/sha256"
	"errors"
	"io"

	efi "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"
)

// VarEntry describes the contents of a mock EFI variable.
type VarEntry struct {
	Attrs   efi.VariableAttributes
	Payload []byte
}

type VarPayloadWriter interface {
	Write(w io.Writer) error
}

// MakeVarPayload returns a byte slice from the supplied VarPayloadWriter.
func MakeVarPayload(c *C, w VarPayloadWriter) []byte {
	buf := new(bytes.Buffer)
	c.Assert(w.Write(buf), IsNil)
	return buf.Bytes()
}

// MockVars is a collection of mock EFI variables.
type MockVars map[efi.VariableDescriptor]*VarEntry

// MakeMockVars creates a new MockVars.
func MakeMockVars() MockVars {
	return make(MockVars)
}

// Get implements [efi.VarsBackend.Get].
func (v MockVars) Get(name string, guid efi.GUID) (efi.VariableAttributes, []byte, error) {
	entry, found := v[efi.VariableDescriptor{Name: name, GUID: guid}]
	if !found {
		return 0, nil, efi.ErrVarNotExist
	}
	return entry.Attrs, entry.Payload, nil
}

// Set implements [efi.VarsBackend.Set].
func (v MockVars) Set(name string, guid efi.GUID, attrs efi.VariableAttributes, data []byte) error {
	return errors.New("not implemented")
}

// List implements [efi.VarsBackend.List].
func (v MockVars) List() ([]efi.VariableDescriptor, error) {
	return nil, errors.New("not implemented")
}

// AddVar adds the specified mock variable. If the attributes indicate that the variable is authenticated,
// the data should not include the authentication header.
func (v MockVars) AddVar(name string, guid efi.GUID, attrs efi.VariableAttributes, data []byte) MockVars {
	v[efi.VariableDescriptor{Name: name, GUID: guid}] = &VarEntry{Attrs: attrs, Payload: data}
	return v
}

// AppendVar appends data to the specified mock variable. If the attributes indicate that the variable is
// authenticated, the data should not include the authentication header.
func (v MockVars) AppendVar(name string, guid efi.GUID, attrs efi.VariableAttributes, data []byte) MockVars {
	desc := efi.VariableDescriptor{Name: name, GUID: guid}
	entry, exists := v[desc]
	if !exists {
		entry = &VarEntry{Attrs: attrs}
		v[desc] = entry
	}
	entry.Payload = append(entry.Payload, data...)
	return v
}

// SetSecureBoot sets the status of the SecureBoot global variable.
func (v MockVars) SetSecureBoot(enabled bool) MockVars {
	var sbVal byte
	if enabled {
		sbVal = 0x01
	}
	return v.AddVar("SecureBoot", efi.GlobalVariable, efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess, []byte{sbVal})
}

// SetPK sets the PK global variable.
func (v MockVars) SetPK(c *C, pk *efi.SignatureList) MockVars {
	return v.AddVar("PK", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess, MakeVarPayload(c, pk))
}

// SetKEK sets the KEK global variable.
func (v MockVars) SetKEK(c *C, kek efi.SignatureDatabase) MockVars {
	return v.AddVar("KEK", efi.GlobalVariable, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess, MakeVarPayload(c, kek))
}

// SetDb sets the db image authentication variable.
func (v MockVars) SetDb(c *C, db efi.SignatureDatabase) MockVars {
	return v.AddVar("db", efi.ImageSecurityDatabaseGuid, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess, MakeVarPayload(c, db))
}

// AppendDb appends to the db image authentication variable. Note that this just appends
// bytes - it does no de-duplication of signatures.
func (v MockVars) AppendDb(c *C, db efi.SignatureDatabase) MockVars {
	return v.AppendVar("db", efi.ImageSecurityDatabaseGuid, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess, MakeVarPayload(c, db))
}

// SetDbx sets the dbx image authentication variable.
func (v MockVars) SetDbx(c *C, dbx efi.SignatureDatabase) MockVars {
	return v.AddVar("dbx", efi.ImageSecurityDatabaseGuid, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess, MakeVarPayload(c, dbx))
}

// AppendDbx appends to the dbx image authentication variable. Note that this just appends
// bytes - it does no de-duplication of signatures.
func (v MockVars) AppendDbx(c *C, dbx efi.SignatureDatabase) MockVars {
	return v.AppendVar("dbx", efi.ImageSecurityDatabaseGuid, efi.AttributeNonVolatile|efi.AttributeBootserviceAccess|efi.AttributeRuntimeAccess|efi.AttributeTimeBasedAuthenticatedWriteAccess, MakeVarPayload(c, dbx))
}
