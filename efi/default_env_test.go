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
	restore := MockReadVar("testdata/efivars6")
	defer restore()

	varData, attrs, err := DefaultEnv.ReadVar(data.name, data.guid)
	c.Check(err, IsNil)

	expectedVarData, expectedAttrs, err := testutil.EFIReadVar("testdata/efivars6", data.name, data.guid)
	c.Check(err, IsNil)

	c.Check(attrs, Equals, expectedAttrs)
	c.Check(varData, DeepEquals, expectedVarData)
}

func (s *defaultEnvSuite) TestReadVar1(c *C) {
	s.testReadVar(c, &testReadVarData{
		name: "foo",
		guid: efi.MakeGUID(0x4e448f45, 0x159f, 0x49f8, 0x8a7f, [6]uint8{0x45, 0xf3, 0xb2, 0x7c, 0xf8, 0x96})})
}

func (s *defaultEnvSuite) TestReadVar2(c *C) {
	s.testReadVar(c, &testReadVarData{
		name: "bar",
		guid: efi.MakeGUID(0x4e448f45, 0x159f, 0x49f8, 0x8a7f, [6]uint8{0x45, 0xf3, 0xb2, 0x7c, 0xf8, 0x96})})
}

func (s *defaultEnvSuite) TestReadVar3(c *C) {
	s.testReadVar(c, &testReadVarData{
		name: "foo",
		guid: efi.MakeGUID(0xf97cb67a, 0x0de5, 0x46b3, 0x882e, [6]uint8{0xcf, 0x35, 0x8b, 0x3f, 0xe8, 0x89})})
}

func (s *defaultEnvSuite) testReadEventLog(c *C, path string) {
	restore := MockEventLogPath(path)
	defer restore()

	log, err := DefaultEnv.ReadEventLog()
	c.Assert(err, IsNil)

	f, err := os.Open(path)
	c.Assert(err, IsNil)
	defer f.Close()

	expectedLog, err := tcglog.ParseLog(f, &tcglog.LogOptions{})
	c.Assert(err, IsNil)

	c.Check(log, DeepEquals, expectedLog)
}

func (s *defaultEnvSuite) TestReadEventLog1(c *C) {
	s.testReadEventLog(c, "testdata/eventlog1.bin")
}

func (s *defaultEnvSuite) TestReadEventLog2(c *C) {
	s.testReadEventLog(c, "testdata/eventlog2.bin")
}
