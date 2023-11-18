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

package luksview_test

import (
	"encoding/json"
	"strconv"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luks2/luks2test"
	. "github.com/snapcore/secboot/internal/luksview"
	"github.com/snapcore/secboot/internal/testutil"
)

type tokenSuite struct{}

var _ = Suite(&tokenSuite{})

func (s *tokenSuite) checkTokenBaseJSON(c *C, j map[string]interface{}, token *TokenBase, typ luks2.TokenType) {
	t, ok := j["type"].(string)
	c.Check(ok, testutil.IsTrue)
	c.Check(t, Equals, string(typ))

	keyslots, ok := j["keyslots"].([]interface{})
	c.Check(ok, testutil.IsTrue)
	for i, v := range keyslots {
		slot, ok := v.(string)
		c.Check(ok, testutil.IsTrue)
		c.Check(slot, Equals, strconv.Itoa(token.Keyslots()[i]))
	}

	name, ok := j["ubuntu_fde_name"].(string)
	c.Check(ok, testutil.IsTrue)
	c.Check(name, Equals, token.Name())
}

func (s *tokenSuite) checkRecoveryTokenJSON(c *C, data []byte, token *RecoveryToken) {
	var j map[string]interface{}
	c.Assert(json.Unmarshal(data, &j), IsNil)

	s.checkTokenBaseJSON(c, j, &token.TokenBase, RecoveryTokenType)
}

func (s *tokenSuite) TestMarshalRecoveryToken1(c *C) {
	token := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:    "foo-recovery",
			TokenKeyslot: 1}}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	s.checkRecoveryTokenJSON(c, data, token)
}

func (s *tokenSuite) TestMarshalRecoveryToken2(c *C) {
	token := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:    "recovery-bar",
			TokenKeyslot: 7}}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	s.checkRecoveryTokenJSON(c, data, token)
}

func (s *tokenSuite) TestUnmarshalRecoveryToken1(c *C) {
	token := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:    "foo-recovery",
			TokenKeyslot: 1}}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	var token2 *RecoveryToken
	c.Check(json.Unmarshal(data, &token2), IsNil)
	c.Check(token2, DeepEquals, token)
}

func (s *tokenSuite) TestUnmarshalRecoveryToken2(c *C) {
	token := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:    "recovery-bar",
			TokenKeyslot: 7}}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	var token2 *RecoveryToken
	c.Check(json.Unmarshal(data, &token2), IsNil)
	c.Check(token2, DeepEquals, token)
}

func (s *tokenSuite) TestDecodeRecoveryToken(c *C) {
	if luks2.DetectCryptsetupFeatures()&luks2.FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	path := luks2test.CreateEmptyDiskImage(c, 20)

	options := luks2.FormatOptions{KDFOptions: luks2.KDFOptions{MemoryKiB: 32, ForceIterations: 4}}
	c.Check(luks2.Format(path, "", make([]byte, 32), &options), IsNil)

	createToken := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:    "recovery",
			TokenKeyslot: 0}}
	c.Check(luks2.ImportToken(path, createToken, nil), IsNil)

	header, err := luks2.ReadHeader(path, luks2.LockModeNonBlocking)
	c.Assert(err, IsNil)

	token, ok := header.Metadata.Tokens[0].(*RecoveryToken)
	c.Assert(ok, testutil.IsTrue)
	c.Check(token, DeepEquals, createToken)
}

func (s *tokenSuite) TestDecodeOrphanedRecoveryToken(c *C) {
	if luks2.DetectCryptsetupFeatures()&luks2.FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	path := luks2test.CreateEmptyDiskImage(c, 20)

	options := luks2.FormatOptions{KDFOptions: luks2.KDFOptions{MemoryKiB: 32, ForceIterations: 4}}
	c.Check(luks2.Format(path, "", make([]byte, 32), &options), IsNil)

	createToken := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:    "recovery",
			TokenKeyslot: 0}}
	c.Check(luks2.ImportToken(path, createToken, nil), IsNil)
	c.Check(luks2.KillSlot(path, 0), IsNil)

	header, err := luks2.ReadHeader(path, luks2.LockModeNonBlocking)
	c.Assert(err, IsNil)

	token, ok := header.Metadata.Tokens[0].(*OrphanedToken)
	c.Assert(ok, testutil.IsTrue)
	c.Check(token.Type(), Equals, RecoveryTokenType)
	c.Check(token.Keyslots(), DeepEquals, []int(nil))
	c.Check(token.Name(), Equals, "recovery")
}

func (s *tokenSuite) TestDecodeInvalidRecoveryToken(c *C) {
	if luks2.DetectCryptsetupFeatures()&luks2.FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	path := luks2test.CreateEmptyDiskImage(c, 20)

	options := luks2.FormatOptions{KDFOptions: luks2.KDFOptions{MemoryKiB: 32, ForceIterations: 4}}
	c.Check(luks2.Format(path, "", make([]byte, 32), &options), IsNil)

	createToken := &RecoveryToken{
		TokenBase: TokenBase{
			TokenKeyslot: 0}}
	c.Check(luks2.ImportToken(path, createToken, nil), IsNil)

	header, err := luks2.ReadHeader(path, luks2.LockModeNonBlocking)
	c.Assert(err, IsNil)

	token, ok := header.Metadata.Tokens[0].(*luks2.GenericToken)
	c.Assert(ok, testutil.IsTrue)
	c.Check(token, DeepEquals, &luks2.GenericToken{
		TokenType:     RecoveryTokenType,
		TokenKeyslots: []int{0},
		Params: map[string]interface{}{
			"ubuntu_fde_name": "",
		},
	})
}

func (s *tokenSuite) checkKeyDataTokenJSON(c *C, data []byte, token *KeyDataToken) {
	var j map[string]interface{}
	c.Assert(json.Unmarshal(data, &j), IsNil)

	s.checkTokenBaseJSON(c, j, &token.TokenBase, KeyDataTokenType)

	priority, ok := j["ubuntu_fde_priority"].(float64)
	c.Check(ok, testutil.IsTrue)
	c.Check(priority, Equals, float64(token.Priority))

	if len(token.Data) == 0 {
		c.Check(j, Not(testutil.HasKey), "ubuntu_fde_data")
	} else {
		var expectedData map[string]interface{}
		c.Assert(json.Unmarshal(token.Data, &expectedData), IsNil)

		d, ok := j["ubuntu_fde_data"]
		c.Check(ok, testutil.IsTrue)
		c.Check(d, DeepEquals, expectedData)
	}
}

func (s *tokenSuite) TestMarshalKeyDataToken1(c *C) {
	token := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:    "foo",
			TokenKeyslot: 0}}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	s.checkKeyDataTokenJSON(c, data, token)
}

func (s *tokenSuite) TestMarshalKeyDataToken2(c *C) {
	token := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:    "bar",
			TokenKeyslot: 3},
		Priority: 1,
		Data:     json.RawMessage(`{"key1":"foo","key2":542}`)}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	s.checkKeyDataTokenJSON(c, data, token)
}

func (s *tokenSuite) TestUnmarshalKeyDataToken1(c *C) {
	token := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:    "foo",
			TokenKeyslot: 0}}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	var token2 *KeyDataToken
	c.Check(json.Unmarshal(data, &token2), IsNil)
	c.Check(token2, DeepEquals, token)
}

func (s *tokenSuite) TestUnmarshalKeyDataToken2(c *C) {
	token := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:    "bar",
			TokenKeyslot: 3},
		Priority: 1,
		Data:     json.RawMessage(`{"key1":"foo","key2":542}`)}
	data, err := json.Marshal(token)
	c.Check(err, IsNil)

	var token2 *KeyDataToken
	c.Check(json.Unmarshal(data, &token2), IsNil)
	c.Check(token2, DeepEquals, token)
	c.Logf("%s\n", token2.Data)
}

func (s *tokenSuite) TestDecodeKeyDataToken(c *C) {
	if luks2.DetectCryptsetupFeatures()&luks2.FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	path := luks2test.CreateEmptyDiskImage(c, 20)

	options := luks2.FormatOptions{KDFOptions: luks2.KDFOptions{MemoryKiB: 32, ForceIterations: 4}}
	c.Check(luks2.Format(path, "", make([]byte, 32), &options), IsNil)

	createToken := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:    "bar",
			TokenKeyslot: 0},
		Priority: 1,
		Data:     json.RawMessage(`{"key1":"foo","key2":542}`)}
	c.Check(luks2.ImportToken(path, createToken, nil), IsNil)

	header, err := luks2.ReadHeader(path, luks2.LockModeNonBlocking)
	c.Assert(err, IsNil)

	token, ok := header.Metadata.Tokens[0].(*KeyDataToken)
	c.Assert(ok, testutil.IsTrue)
	c.Check(token, DeepEquals, createToken)
}

func (s *tokenSuite) TestDecodeOrphanedKeyDataToken(c *C) {
	if luks2.DetectCryptsetupFeatures()&luks2.FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	path := luks2test.CreateEmptyDiskImage(c, 20)

	options := luks2.FormatOptions{KDFOptions: luks2.KDFOptions{MemoryKiB: 32, ForceIterations: 4}}
	c.Check(luks2.Format(path, "", make([]byte, 32), &options), IsNil)

	createToken := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:    "bar",
			TokenKeyslot: 0}}
	c.Check(luks2.ImportToken(path, createToken, nil), IsNil)
	c.Check(luks2.KillSlot(path, 0), IsNil)

	header, err := luks2.ReadHeader(path, luks2.LockModeNonBlocking)
	c.Assert(err, IsNil)

	token, ok := header.Metadata.Tokens[0].(*OrphanedToken)
	c.Assert(ok, testutil.IsTrue)
	c.Check(token.Type(), Equals, KeyDataTokenType)
	c.Check(token.Keyslots(), DeepEquals, []int(nil))
	c.Check(token.Name(), Equals, "bar")
}

func (s *tokenSuite) TestDecodeInvalidKeyDataToken(c *C) {
	if luks2.DetectCryptsetupFeatures()&luks2.FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	path := luks2test.CreateEmptyDiskImage(c, 20)

	options := luks2.FormatOptions{KDFOptions: luks2.KDFOptions{MemoryKiB: 32, ForceIterations: 4}}
	c.Check(luks2.Format(path, "", make([]byte, 32), &options), IsNil)

	createToken := &KeyDataToken{
		TokenBase: TokenBase{
			TokenKeyslot: 0}}
	c.Check(luks2.ImportToken(path, createToken, nil), IsNil)

	header, err := luks2.ReadHeader(path, luks2.LockModeNonBlocking)
	c.Assert(err, IsNil)

	token, ok := header.Metadata.Tokens[0].(*luks2.GenericToken)
	c.Assert(ok, testutil.IsTrue)
	c.Check(token, DeepEquals, &luks2.GenericToken{
		TokenType:     KeyDataTokenType,
		TokenKeyslots: []int{0},
		Params: map[string]interface{}{
			"ubuntu_fde_name":     "",
			"ubuntu_fde_priority": float64(0),
		},
	})
}
