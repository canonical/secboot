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
	"encoding/json"
	"os"
	"path/filepath"

	. "github.com/snapcore/secboot"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

type keyDataFileSuite struct {
	keyDataTestBase
	dir string
}

func (s *keyDataFileSuite) SetUpTest(c *C) {
	s.keyDataTestBase.SetUpTest(c)
	s.dir = c.MkDir()
}

var _ = Suite(&keyDataFileSuite{})

func (s *keyDataFileSuite) TestWriter(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeys(c, primaryKey, "foo", crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	w := NewFileKeyDataWriter(filepath.Join(s.dir, "key"))
	c.Assert(w, NotNil)
	c.Check(keyData.WriteAtomic(w), IsNil)

	f, err := os.Open(filepath.Join(s.dir, "key"))
	c.Assert(err, IsNil)
	defer f.Close()

	var j map[string]interface{}

	d := json.NewDecoder(f)
	c.Check(d.Decode(&j), IsNil)

	s.checkKeyDataJSONDecodedAuthModeNone(c, j, protected)
}

func (s *keyDataFileSuite) TestWriterIsAtomic(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, _ := s.mockProtectKeys(c, primaryKey, "foo", crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	w := NewFileKeyDataWriter(filepath.Join(s.dir, "key"))
	c.Check(keyData.WriteAtomic(w), IsNil)

	f, err := os.Open(filepath.Join(s.dir, "key"))
	c.Assert(err, IsNil)
	defer f.Close()

	w = NewFileKeyDataWriter(filepath.Join(s.dir, "key"))
	c.Check(keyData.WriteAtomic(w), IsNil)

	var st1 unix.Stat_t
	c.Check(unix.Fstat(int(f.Fd()), &st1), IsNil)
	var st2 unix.Stat_t
	c.Check(unix.Stat(filepath.Join(s.dir, "key"), &st2), IsNil)
	c.Check(st1.Ino, Not(Equals), st2.Ino)
}

func (s *keyDataFileSuite) TestReader(c *C) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeys(c, primaryKey, "foo", crypto.SHA256)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	expectedId, err := keyData.UniqueID()
	c.Check(err, IsNil)

	path := filepath.Join(s.dir, "key")

	w := NewFileKeyDataWriter(path)
	c.Check(keyData.WriteAtomic(w), IsNil)

	r, err := NewFileKeyDataReader(path)
	c.Assert(err, IsNil)
	c.Check(r.ReadableName(), Equals, path)

	keyData, err = ReadKeyData(r)
	c.Assert(err, IsNil)
	c.Check(keyData.ReadableName(), Equals, path)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)
	c.Check(id, DeepEquals, expectedId)

	c.Check(keyData.Role(), Equals, "foo")

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(recoveredUnlockKey, DeepEquals, unlockKey)
	c.Check(recoveredPrimaryKey, DeepEquals, primaryKey)
}
