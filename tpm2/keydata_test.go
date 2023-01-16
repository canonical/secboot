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
	"math/rand"
	"path/filepath"

	"github.com/canonical/go-tpm2"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type keydataSuiteNoTPM struct{}

var _ = Suite(&keydataSuiteNoTPM{})

func (s *keydataSuiteNoTPM) TestNewKeyDataV0(c *C) {
	priv := tpm2.Private{1, 2, 3, 4}
	pub := new(tpm2.Public)
	policy := new(KeyDataPolicy_v0)

	data, err := NewKeyData(priv, pub, nil, policy)
	c.Assert(err, IsNil)

	_, ok := data.(*KeyData_v0)
	c.Check(ok, testutil.IsTrue)

	c.Check(data.Private(), DeepEquals, priv)
	c.Check(data.Public(), Equals, pub)
	c.Check(data.ImportSymSeed(), IsNil)
	c.Check(data.Policy(), Equals, policy)
}

func (s *keydataSuiteNoTPM) TestNewKeyDataV0RejectsImportSymSeed(c *C) {
	priv := tpm2.Private{1, 2, 3, 4}
	pub := new(tpm2.Public)
	importSymSeed := tpm2.EncryptedSecret{5, 6, 7, 8}
	policy := new(KeyDataPolicy_v0)

	_, err := NewKeyData(priv, pub, importSymSeed, policy)
	c.Assert(err, ErrorMatches, "no importable key data support for v0")
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

type keydataSuite struct {
	tpm2test.TPMTest
}

func (s *keydataSuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeatureNV
}

var _ = Suite(&keydataSuite{})

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

func (w *mockKeyDataWriter) Reader() io.Reader {
	return w.final
}

func newMockKeyDataWriter() *mockKeyDataWriter {
	return &mockKeyDataWriter{tmp: new(bytes.Buffer)}
}

func (s *keydataSuite) TestFileReadAndWrite(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	keyFile := filepath.Join(c.MkDir(), "keydata")

	authPrivateKey, err := SealKeyToTPM(s.TPM(), key, keyFile, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)

	var st1 unix.Stat_t
	c.Check(unix.Stat(keyFile, &st1), IsNil)

	k, err := ReadSealedKeyObjectFromFile(keyFile)
	c.Assert(err, IsNil)
	c.Check(k.Validate(s.TPM().TPMContext, authPrivateKey, s.TPM().HmacSession()), IsNil)

	w := NewFileSealedKeyObjectWriter(keyFile)
	c.Check(k.WriteAtomic(w), IsNil)

	var st2 unix.Stat_t
	c.Check(unix.Stat(keyFile, &st2), IsNil)
	c.Check(st1.Ino, Not(Equals), st2.Ino)

	k, err = ReadSealedKeyObjectFromFile(keyFile)
	c.Assert(err, IsNil)
	c.Check(k.Validate(s.TPM().TPMContext, authPrivateKey, s.TPM().HmacSession()), IsNil)
}

func (s *keydataSuite) TestReadAndWrite(c *C) {
	key := make([]byte, 32)
	rand.Read(key)
	keyFile := filepath.Join(c.MkDir(), "keydata")

	authPrivateKey, err := SealKeyToTPM(s.TPM(), key, keyFile, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)

	k, err := ReadSealedKeyObjectFromFile(keyFile)
	c.Assert(err, IsNil)

	w := newMockKeyDataWriter()
	c.Check(k.WriteAtomic(w), IsNil)

	k, err = ReadSealedKeyObject(w.Reader())
	c.Assert(err, IsNil)
	c.Check(k.Validate(s.TPM().TPMContext, authPrivateKey, s.TPM().HmacSession()), IsNil)
}
