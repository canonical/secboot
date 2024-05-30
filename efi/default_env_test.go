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
	"errors"
	"io"
	"os"
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"

	. "gopkg.in/check.v1"
)

// TODO: make efitest.MockVars implement efi.VarsBackend in a future PR.
type mockVarsBackend struct {
	vars efitest.MockVars
}

func (v *mockVarsBackend) Get(name string, guid efi.GUID) (efi.VariableAttributes, []byte, error) {
	entry, exists := v.vars[efi.VariableDescriptor{Name: name, GUID: guid}]
	if !exists {
		return 0, nil, efi.ErrVarNotExist
	}
	return entry.Attrs, entry.Payload, nil
}

func (v *mockVarsBackend) Set(name string, guid efi.GUID, attrs efi.VariableAttributes, data []byte) error {
	return errors.New("not implemented")
}

func (v *mockVarsBackend) List() ([]efi.VariableDescriptor, error) {
	return nil, errors.New("not implemented")
}

type defaultEnvSuite struct{}

var _ = Suite(&defaultEnvSuite{})

type testReadVarData struct {
	name string
	guid efi.GUID
}

func (s *defaultEnvSuite) testReadVar(c *C, data *testReadVarData) {
	vars := makeMockVars(c, withMsSecureBootConfig())
	restore := efi.MockVarsBackend(&mockVarsBackend{vars: vars})
	defer restore()

	payload, attrs, err := DefaultEnv.ReadVar(data.name, data.guid)

	entry, exists := vars[efi.VariableDescriptor{Name: data.name, GUID: data.guid}]
	if !exists {
		c.Check(err, Equals, efi.ErrVarNotExist)
	} else {
		c.Check(err, IsNil)
		c.Check(attrs, Equals, entry.Attrs)
		c.Check(payload, DeepEquals, entry.Payload)
	}
}

func (s *defaultEnvSuite) TestReadVar1(c *C) {
	s.testReadVar(c, &testReadVarData{
		name: "SecureBoot",
		guid: efi.GlobalVariable})
}

func (s *defaultEnvSuite) TestReadVar2(c *C) {
	s.testReadVar(c, &testReadVarData{
		name: "PK",
		guid: efi.GlobalVariable})
}

func (s *defaultEnvSuite) TestReadVar3(c *C) {
	s.testReadVar(c, &testReadVarData{
		name: "dbx",
		guid: efi.ImageSecurityDatabaseGuid})
}

func (s *defaultEnvSuite) TestReadVarNotExist(c *C) {
	s.testReadVar(c, &testReadVarData{
		name: "SecureBoot",
		guid: efi.ImageSecurityDatabaseGuid})
}

func (s *defaultEnvSuite) testReadEventLog(c *C, opts *efitest.LogOptions) {
	dir := c.MkDir()
	path := filepath.Join(dir, "log")

	log := efitest.NewLog(c, opts)

	logFile, err := os.Create(path)
	c.Assert(err, IsNil)
	defer logFile.Close()

	c.Check(log.Write(logFile), IsNil)

	restore := MockEventLogPath(path)
	defer restore()

	log, err = DefaultEnv.ReadEventLog()
	c.Assert(err, IsNil)

	_, err = logFile.Seek(0, io.SeekStart)
	c.Check(err, IsNil)
	expectedLog, err := tcglog.ReadLog(logFile, &tcglog.LogOptions{})
	c.Assert(err, IsNil)

	c.Check(log, DeepEquals, expectedLog)
}

func (s *defaultEnvSuite) TestReadEventLog1(c *C) {
	s.testReadEventLog(c, &efitest.LogOptions{Algorithms: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1}})
}

func (s *defaultEnvSuite) TestReadEventLog2(c *C) {
	s.testReadEventLog(c, &efitest.LogOptions{
		Algorithms:         []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		SecureBootDisabled: true,
	})
}
