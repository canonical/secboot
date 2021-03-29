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

package secboot_test

import (
	"crypto"
	"os"
	"path/filepath"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

type keyDataFileSuite struct {
	snapModelTestBase
	keyDataTestBase
	dir string
}

func (s *keyDataFileSuite) SetUpTest(c *C) {
	s.keyDataTestBase.SetUpTest(c)
	s.dir = c.MkDir()
}

var _ = Suite(&keyDataFileSuite{})

func (s *keyDataFileSuite) TestWriter(c *C) {
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	w, err := NewKeyDataFileWriter(filepath.Join(s.dir, "key"))
	c.Assert(err, IsNil)

	c.Check(keyData.WriteAtomic(w), IsNil)

	f, err := os.Open(filepath.Join(s.dir, "key"))
	c.Assert(err, IsNil)
	defer f.Close()

	s.checkKeyDataJSON(c, f, protected, 0)
}

func (s *keyDataFileSuite) TestWriterIsAtomic(c *C) {
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	w, err := NewKeyDataFileWriter(filepath.Join(s.dir, "key"))
	c.Assert(err, IsNil)

	c.Check(keyData.WriteAtomic(w), IsNil)

	f, err := os.Open(filepath.Join(s.dir, "key"))
	c.Assert(err, IsNil)
	defer f.Close()

	w, err = NewKeyDataFileWriter(filepath.Join(s.dir, "key"))
	c.Assert(err, IsNil)

	c.Check(keyData.WriteAtomic(w), IsNil)

	var st1 unix.Stat_t
	c.Check(unix.Fstat(int(f.Fd()), &st1), IsNil)
	var st2 unix.Stat_t
	c.Check(unix.Stat(filepath.Join(s.dir, "key"), &st2), IsNil)
	c.Check(st1.Ino, Not(Equals), st2.Ino)
}

func (s *keyDataFileSuite) TestReader(c *C) {
	key, auxKey := s.newKeys(c, 32, 32)
	protected := s.mockProtectKeys(c, key, auxKey, crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	models := []SnapModel{
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	c.Check(keyData.SetAuthorizedSnapModels(auxKey, models...), IsNil)

	w, err := NewKeyDataFileWriter(filepath.Join(s.dir, "key"))
	c.Assert(err, IsNil)

	c.Check(keyData.WriteAtomic(w), IsNil)

	f, err := OpenKeyDataFile(filepath.Join(s.dir, "key"))
	c.Assert(err, IsNil)
	defer f.Close()
	c.Check(f.ID().Equals(&KeyID{Loader: "file", Path: filepath.Join(s.dir, "key")}), testutil.IsTrue)

	keyData, err = ReadKeyData(f)
	c.Assert(err, IsNil)

	recoveredKey, recoveredAuxKey, err := keyData.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(recoveredKey, DeepEquals, key)
	c.Check(recoveredAuxKey, DeepEquals, auxKey)

	authorized, err := keyData.IsSnapModelAuthorized(recoveredAuxKey, models[0])
	c.Check(err, IsNil)
	c.Check(authorized, testutil.IsTrue)
}
