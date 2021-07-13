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
	"os"

	"github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

type defaultEnvSuite struct{}

var _ = Suite(&defaultEnvSuite{})

type testReadVarData struct {
	name string
	guid efi.GUID
}

func (s *defaultEnvSuite) testReadVar(c *C, data *testReadVarData) {
	restore := MockReadVar("testdata/efivars_ms")
	defer restore()

	varData, attrs, err := DefaultEnv.ReadVar(data.name, data.guid)
	c.Check(err, IsNil)

	expectedVarData, expectedAttrs, err := testutil.EFIReadVar("testdata/efivars_ms", data.name, data.guid)
	c.Check(err, IsNil)

	c.Check(attrs, Equals, expectedAttrs)
	c.Check(varData, DeepEquals, expectedVarData)
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

func (s *defaultEnvSuite) testReadEventLog(c *C, path string) {
	restore := MockEventLogPath(path)
	defer restore()

	log, err := DefaultEnv.ReadEventLog()
	c.Assert(err, IsNil)

	f, err := os.Open(path)
	c.Assert(err, IsNil)
	defer f.Close()

	expectedLog, err := tcglog.ReadLog(f, &tcglog.LogOptions{})
	c.Assert(err, IsNil)

	c.Check(log, DeepEquals, expectedLog)
}

func (s *defaultEnvSuite) TestReadEventLog1(c *C) {
	s.testReadEventLog(c, "testdata/eventlog_sb.bin")
}

func (s *defaultEnvSuite) TestReadEventLog2(c *C) {
	s.testReadEventLog(c, "testdata/eventlog_no_sb.bin")
}
