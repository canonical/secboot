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
	"context"
	_ "embed"
	"io"
	"os"
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"
	. "github.com/snapcore/secboot/internal/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"

	. "gopkg.in/check.v1"
)

type defaultEnvSuite struct{}

var _ = Suite(&defaultEnvSuite{})

type testKey struct{}

func (s *defaultEnvSuite) TestVarContext(c *C) {
	ctx := DefaultEnv.VarContext(context.WithValue(context.Background(), testKey{}, int64(10)))
	c.Assert(ctx, NotNil)

	expected := efi.WithDefaultVarsBackend(context.Background())
	c.Check(ctx.Value(efi.VarsBackendKey{}), Equals, expected.Value(efi.VarsBackendKey{}))

	// Make sure that the returned context has the right parent by testing the
	// value we attached to it.
	testVal := ctx.Value(testKey{})
	c.Assert(testVal, NotNil)
	testVali64, ok := testVal.(int64)
	c.Assert(ok, testutil.IsTrue)
	c.Check(testVali64, Equals, int64(10))
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
