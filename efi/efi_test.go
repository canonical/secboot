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

package efi_test

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type mockEFIVar struct {
	data  []byte
	attrs efi.VariableAttributes
}

type mockEFIEnvironment struct {
	vars map[efi.VariableDescriptor]*mockEFIVar
	log  []byte
}

func newMockEFIEnvironment(vars map[efi.VariableDescriptor]*mockEFIVar, log []byte) *mockEFIEnvironment {
	return &mockEFIEnvironment{vars: vars, log: log}
}

func newMockEFIEnvironmentFromFiles(c *C, efivars, log string) *mockEFIEnvironment {
	vars := make(map[efi.VariableDescriptor]*mockEFIVar)
	var logData []byte

	if efivars != "" {
		dir, err := os.Open(efivars)
		c.Assert(err, IsNil)
		defer dir.Close()

		entries, err := dir.Readdir(-1)
		c.Assert(err, IsNil)

		r := regexp.MustCompile(`^([[:alnum:]]+)-([[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12})$`)

		for _, entry := range entries {
			m := r.FindStringSubmatch(entry.Name())
			if len(m) == 0 {
				continue
			}

			name := m[1]
			guid, err := efi.DecodeGUIDString(m[2])
			c.Assert(err, IsNil)

			data, err := ioutil.ReadFile(filepath.Join(efivars, entry.Name()))
			c.Assert(err, IsNil)
			if len(data) < 4 {
				c.Fatal(entry.Name(), "contents too short")
			}

			vars[efi.VariableDescriptor{Name: name, GUID: guid}] = &mockEFIVar{
				data:  data[4:],
				attrs: efi.VariableAttributes(binary.LittleEndian.Uint32(data))}
		}
	}

	if log != "" {
		var err error
		logData, err = ioutil.ReadFile(log)
		c.Assert(err, IsNil)
	}
	return newMockEFIEnvironment(vars, logData)
}

func (e *mockEFIEnvironment) ReadVar(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error) {
	if e.vars == nil {
		return nil, 0, efi.ErrVarNotExist
	}
	v, found := e.vars[efi.VariableDescriptor{Name: name, GUID: guid}]
	if !found {
		return nil, 0, efi.ErrVarNotExist
	}
	return v.data, v.attrs, nil
}

func (e *mockEFIEnvironment) ReadEventLog() (*tcglog.Log, error) {
	return tcglog.ReadLog(bytes.NewReader(e.log), &tcglog.LogOptions{})
}
