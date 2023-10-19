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
	"fmt"

	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luks2/luks2test"
	"github.com/snapcore/secboot/internal/luksview"
	"github.com/snapcore/secboot/internal/testutil"
)

type keyDataLuksSuite struct {
	snapd_testutil.BaseTest
	keyDataTestBase

	luks2 *mockLUKS2
}

func (s *keyDataLuksSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	s.keyDataTestBase.SetUpTest(c)

	s.luks2 = &mockLUKS2{
		devices:   make(map[string]*mockLUKS2Container),
		activated: make(map[string]string)}
	s.AddCleanup(s.luks2.enableMocks())
}

var _ = Suite(&keyDataLuksSuite{})

func (s *keyDataLuksSuite) checkKeyDataJSONFromLUKSToken(c *C, path string, id int, keyslot int, name string, priority int, creationParams *KeyParams, nmodels int) {
	t, exists := s.luks2.devices[path].tokens[id]
	c.Assert(exists, testutil.IsTrue)

	data, err := json.Marshal(t)
	c.Check(err, IsNil)

	var token *luks2.GenericToken
	c.Check(json.Unmarshal(data, &token), IsNil)

	c.Check(token.Type(), Equals, luksview.KeyDataTokenType)
	c.Check(token.Keyslots(), DeepEquals, []int{keyslot})

	str, ok := token.Params["ubuntu_fde_name"].(string)
	c.Assert(ok, testutil.IsTrue)
	c.Check(str, Equals, name)

	n, ok := token.Params["ubuntu_fde_priority"].(float64)
	c.Assert(ok, testutil.IsTrue)
	c.Check(n, Equals, float64(priority))

	keyData, ok := token.Params["ubuntu_fde_data"].(map[string]interface{})
	c.Assert(ok, testutil.IsTrue)

	s.checkKeyDataJSONDecodedAuthModeNone(c, keyData, creationParams, nmodels)
}

type testKeyDataLuksWriterData struct {
	id           int
	path         string
	name         string
	slot         int
	initPriority int
	setPriority  int
}

func (s *keyDataLuksSuite) testWriter(c *C, data *testKeyDataLuksWriterData) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeys(c, primaryKey, crypto.SHA256)

	s.luks2.devices[data.path] = &mockLUKS2Container{
		tokens: map[int]luks2.Token{
			data.id: &luksview.KeyDataToken{
				TokenBase: luksview.TokenBase{
					TokenName:    data.name,
					TokenKeyslot: data.slot},
				Priority: data.initPriority},
		},
		keyslots: map[int][]byte{data.slot: unlockKey}}

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	w, err := NewLUKS2KeyDataWriter(data.path, data.name)
	c.Assert(err, IsNil)

	if data.initPriority != data.setPriority {
		w.SetPriority(data.setPriority)
	}
	c.Check(keyData.WriteAtomic(w), IsNil)

	c.Check(s.luks2.operations, DeepEquals, []string{
		"newLUKSView(" + data.path + ",0)",
		fmt.Sprint("ImportToken(", data.path, ",", &luks2.ImportTokenOptions{Id: data.id, Replace: true}, ")"),
	})

	s.checkKeyDataJSONFromLUKSToken(c, data.path, data.id, data.slot, data.name, data.setPriority, protected, 0)
}

func (s *keyDataLuksSuite) TestWriter(c *C) {
	s.testWriter(c, &testKeyDataLuksWriterData{
		id:           0,
		path:         "/dev/sda1",
		name:         "foo",
		slot:         0,
		initPriority: 1,
		setPriority:  1,
	})
}

func (s *keyDataLuksSuite) TestWriterDifferentId(c *C) {
	s.testWriter(c, &testKeyDataLuksWriterData{
		id:           2,
		path:         "/dev/sda1",
		name:         "foo",
		slot:         0,
		initPriority: 1,
		setPriority:  1,
	})
}

func (s *keyDataLuksSuite) TestWriterDifferentPath(c *C) {
	s.testWriter(c, &testKeyDataLuksWriterData{
		id:           0,
		path:         "/dev/nvme0n1p1",
		name:         "foo",
		slot:         0,
		initPriority: 1,
		setPriority:  1,
	})
}

func (s *keyDataLuksSuite) TestWriterDifferentName(c *C) {
	s.testWriter(c, &testKeyDataLuksWriterData{
		id:           0,
		path:         "/dev/sda1",
		name:         "bar",
		slot:         0,
		initPriority: 1,
		setPriority:  1,
	})
}

func (s *keyDataLuksSuite) TestWriterDifferentSlot(c *C) {
	s.testWriter(c, &testKeyDataLuksWriterData{
		id:           0,
		path:         "/dev/sda1",
		name:         "foo",
		slot:         6,
		initPriority: 1,
		setPriority:  1,
	})
}

func (s *keyDataLuksSuite) TestWriterDifferentPriority(c *C) {
	s.testWriter(c, &testKeyDataLuksWriterData{
		id:           0,
		path:         "/dev/sda1",
		name:         "foo",
		slot:         0,
		initPriority: 5,
		setPriority:  5,
	})
}

func (s *keyDataLuksSuite) TestWriterSetPriority(c *C) {
	s.testWriter(c, &testKeyDataLuksWriterData{
		id:          0,
		path:        "/dev/sda1",
		name:        "foo",
		slot:        0,
		setPriority: 5,
	})
}

func (s *keyDataLuksSuite) TestWriterTokenNotExist(c *C) {
	s.luks2.devices["/dev/sda1"] = &mockLUKS2Container{
		tokens:   make(map[int]luks2.Token),
		keyslots: map[int][]byte{0: nil}}
	w, err := NewLUKS2KeyDataWriter("/dev/sda1", "foo")
	c.Assert(w, IsNil)
	c.Check(err, ErrorMatches, "a keyslot with the specified name does not exist")
}

func (s *keyDataLuksSuite) TestWriterTokenWrongType(c *C) {
	s.luks2.devices["/dev/sda1"] = &mockLUKS2Container{
		tokens: map[int]luks2.Token{
			0: &luksview.RecoveryToken{
				TokenBase: luksview.TokenBase{
					TokenName:    "foo",
					TokenKeyslot: 0}},
		},
		keyslots: map[int][]byte{0: nil}}

	w, err := NewLUKS2KeyDataWriter("/dev/sda1", "foo")
	c.Assert(w, IsNil)
	c.Check(err, ErrorMatches, "named keyslot has the wrong type")
}

type testKeyDataLuksReaderData struct {
	id       int
	path     string
	name     string
	slot     int
	priority int
}

func (s *keyDataLuksSuite) testReader(c *C, data *testKeyDataLuksReaderData) {
	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeys(c, primaryKey, crypto.SHA256)

	s.luks2.devices[data.path] = &mockLUKS2Container{
		tokens: map[int]luks2.Token{
			data.id: &luksview.KeyDataToken{
				TokenBase: luksview.TokenBase{
					TokenKeyslot: data.slot,
					TokenName:    data.name},
				Priority: data.priority},
		},
		keyslots: map[int][]byte{data.slot: unlockKey}}

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	models := []SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}

	c.Check(keyData.SetAuthorizedSnapModels(primaryKey, models...), IsNil)

	expectedId, err := keyData.UniqueID()
	c.Check(err, IsNil)

	w, err := NewLUKS2KeyDataWriter(data.path, data.name)
	c.Check(keyData.WriteAtomic(w), IsNil)

	s.luks2.operations = nil

	r, err := NewLUKS2KeyDataReader(data.path, data.name)
	c.Assert(err, IsNil)

	c.Check(s.luks2.operations, DeepEquals, []string{"newLUKSView(" + data.path + ",0)"})

	c.Check(r.ReadableName(), Equals, data.path+":"+data.name)
	c.Check(r.KeyslotID(), Equals, data.slot)
	c.Check(r.Priority(), Equals, data.priority)

	keyData, err = ReadKeyData(r)
	c.Assert(err, IsNil)
	c.Check(keyData.ReadableName(), Equals, data.path+":"+data.name)

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)
	c.Check(id, DeepEquals, expectedId)

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(recoveredUnlockKey, DeepEquals, unlockKey)
	c.Check(recoveredPrimaryKey, DeepEquals, primaryKey)

	authorized, err := keyData.IsSnapModelAuthorized(recoveredPrimaryKey, models[0])
	c.Check(err, IsNil)
	c.Check(authorized, testutil.IsTrue)
}

func (s *keyDataLuksSuite) TestReader(c *C) {
	s.testReader(c, &testKeyDataLuksReaderData{
		id:       0,
		path:     "/dev/sda1",
		name:     "foo",
		slot:     0,
		priority: 1,
	})
}

func (s *keyDataLuksSuite) TestReaderDifferentPath(c *C) {
	s.testReader(c, &testKeyDataLuksReaderData{
		id:       0,
		path:     "/dev/vdc2",
		name:     "foo",
		slot:     0,
		priority: 1,
	})
}

func (s *keyDataLuksSuite) TestReaderDifferentName(c *C) {
	s.testReader(c, &testKeyDataLuksReaderData{
		id:       0,
		path:     "/dev/sda1",
		name:     "bar",
		slot:     0,
		priority: 1,
	})
}

func (s *keyDataLuksSuite) TestReaderDifferentSlot(c *C) {
	s.testReader(c, &testKeyDataLuksReaderData{
		id:       0,
		path:     "/dev/sda1",
		name:     "foo",
		slot:     5,
		priority: 1,
	})
}

func (s *keyDataLuksSuite) TestReaderDifferentPriority(c *C) {
	s.testReader(c, &testKeyDataLuksReaderData{
		id:       0,
		path:     "/dev/sda1",
		name:     "foo",
		slot:     0,
		priority: 10,
	})
}

func (s *keyDataLuksSuite) TestReaderDifferentTokenId(c *C) {
	s.testReader(c, &testKeyDataLuksReaderData{
		id:       4,
		path:     "/dev/sda1",
		name:     "foo",
		slot:     0,
		priority: 1,
	})
}

type keyDataLuksUnmockedSuite struct {
	keyDataTestBase
}

func (s *keyDataLuksUnmockedSuite) SetUpSuite(c *C) {
	if luks2.DetectCryptsetupFeatures()&(luks2.FeatureTokenImport|luks2.FeatureTokenReplace) != luks2.FeatureTokenImport|luks2.FeatureTokenReplace {
		c.Skip("cryptsetup doesn't support token import and replace")
	}
	s.keyDataTestBase.SetUpSuite(c)
}

var _ = Suite(&keyDataLuksUnmockedSuite{})

func (s *keyDataLuksUnmockedSuite) TestReaderAndWriter(c *C) {
	path := luks2test.CreateEmptyDiskImage(c, 20)

	primaryKey := s.newPrimaryKey(c, 32)
	protected, unlockKey := s.mockProtectKeys(c, primaryKey, crypto.SHA256)
	c.Check(InitializeLUKS2Container(path, "", unlockKey, nil), IsNil)

	keyData, err := NewKeyData(protected)
	c.Assert(err, IsNil)

	expectedId, err := keyData.UniqueID()
	c.Check(err, IsNil)

	w, err := NewLUKS2KeyDataWriter(path, "default")
	c.Assert(err, IsNil)
	w.SetPriority(1)
	c.Check(keyData.WriteAtomic(w), IsNil)

	r, err := NewLUKS2KeyDataReader(path, "default")
	c.Assert(err, IsNil)

	c.Check(r.ReadableName(), Equals, path+":default")
	c.Check(r.KeyslotID(), Equals, 0)
	c.Check(r.Priority(), Equals, 1)

	keyData, err = ReadKeyData(r)
	c.Assert(err, IsNil)
	c.Check(keyData.ReadableName(), Equals, path+":default")

	id, err := keyData.UniqueID()
	c.Check(err, IsNil)
	c.Check(id, DeepEquals, expectedId)

	recoveredUnlockKey, recoveredPrimaryKey, err := keyData.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(recoveredUnlockKey, DeepEquals, unlockKey)
	c.Check(recoveredPrimaryKey, DeepEquals, primaryKey)
}
