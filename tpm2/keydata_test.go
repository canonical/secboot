// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package tpm2_test

import (
	"bytes"
	"errors"
	"io"

	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	. "github.com/snapcore/secboot/tpm2"
)

type mockKeyDataReader struct {
	io.Reader
}

func (mockKeyDataReader) ReadableName() string { return "" }

type mockKeyDataWriter struct {
	tmp   *bytes.Buffer
	final *bytes.Buffer
}

func (w *mockKeyDataWriter) Write(data []byte) (int, error) {
	if w.tmp == nil {
		return 0, errors.New("cancelled")
	}
	return w.tmp.Write(data)
}

func (w *mockKeyDataWriter) Commit() error {
	if w.tmp == nil {
		return errors.New("cancelled or already committed")
	}
	w.final = w.tmp
	w.tmp = nil
	return nil
}

func (w *mockKeyDataWriter) Reader() secboot.KeyDataReader {
	return &mockKeyDataReader{w.final}
}

func newMockKeyDataWriter() *mockKeyDataWriter {
	return &mockKeyDataWriter{tmp: new(bytes.Buffer)}
}

type keydataSuiteNoTPM struct{}

var _ = Suite(&keydataSuiteNoTPM{})

func (s *keydataSuiteNoTPM) TestNewKeyDataV0(c *C) {
	priv := tpm2.Private{1, 2, 3, 4}
	pub := new(tpm2.Public)
	policy := new(KeyDataPolicy_v0)

	_, err := NewKeyData(priv, pub, nil, policy)
	c.Check(err, ErrorMatches, "no support for creating v0 keys")
}

func (s *keydataSuiteNoTPM) TestNewKeyDataV2(c *C) {
	priv := tpm2.Private{1, 2, 3, 4}
	pub := new(tpm2.Public)
	importSymSeed := tpm2.EncryptedSecret{5, 6, 7, 8}
	policy := new(KeyDataPolicy_v2)

	data, err := NewKeyData(priv, pub, importSymSeed, policy)
	c.Assert(err, IsNil)

	_, ok := data.(*KeyData_v2)
	c.Check(ok, testutil.IsTrue)

	c.Check(data.Private(), DeepEquals, priv)
	c.Check(data.Public(), Equals, pub)
	c.Check(data.ImportSymSeed(), DeepEquals, importSymSeed)
	c.Check(data.Policy(), Equals, policy)
}

func (s *keydataSuiteNoTPM) TestNewKeyDataV3(c *C) {
	priv := tpm2.Private{1, 2, 3, 4}
	pub := new(tpm2.Public)
	importSymSeed := tpm2.EncryptedSecret{5, 6, 7, 8}
	policy := new(KeyDataPolicy_v3)

	data, err := NewKeyData(priv, pub, importSymSeed, policy)
	c.Assert(err, IsNil)

	_, ok := data.(*KeyData_v3)
	c.Check(ok, testutil.IsTrue)

	c.Check(data.Private(), DeepEquals, priv)
	c.Check(data.Public(), Equals, pub)
	c.Check(data.ImportSymSeed(), DeepEquals, importSymSeed)
	c.Check(data.Policy(), Equals, policy)
}
