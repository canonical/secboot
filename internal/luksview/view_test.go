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
	snapd_testutil "github.com/snapcore/snapd/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/luks2"
	"github.com/snapcore/secboot/internal/luks2/luks2test"
	. "github.com/snapcore/secboot/internal/luksview"
	"github.com/snapcore/secboot/internal/paths/pathstest"
	"github.com/snapcore/secboot/internal/testutil"
)

type viewSuite struct {
	snapd_testutil.BaseTest
}

func (s *viewSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	s.AddCleanup(pathstest.MockRunDir(c.MkDir()))
	s.AddCleanup(luks2test.WrapCryptsetup(c))
}

var _ = Suite(&viewSuite{})

type mockHeaderSource luks2.HeaderInfo

func (s mockHeaderSource) ReadHeader() (*luks2.HeaderInfo, error) {
	return (*luks2.HeaderInfo)(&s), nil
}

var testHeader = mockHeaderSource(luks2.HeaderInfo{
	Metadata: luks2.Metadata{
		Keyslots: map[int]*luks2.Keyslot{
			0: new(luks2.Keyslot),
			1: new(luks2.Keyslot),
			2: new(luks2.Keyslot),
			3: new(luks2.Keyslot),
			4: new(luks2.Keyslot),
			5: new(luks2.Keyslot)},
		Tokens: map[int]luks2.Token{
			0: &KeyDataToken{
				TokenBase: TokenBase{
					TokenKeyslot: 0,
					TokenName:    "foo"},
				Priority: 1},
			1: &RecoveryToken{
				TokenBase: TokenBase{
					TokenKeyslot: 1,
					TokenName:    "recovery"}},
			2: &KeyDataToken{
				TokenBase: TokenBase{
					TokenKeyslot: 2,
					TokenName:    "bar"}},
			// Test that this token type is ignored.
			3: &luks2.GenericToken{
				TokenType:     "luks2-keyring",
				TokenKeyslots: []int{3}},
			// Add another token with the same priority as
			// an existing one to check that the behaviour of
			// TokensByPriority is well defined.
			4: &KeyDataToken{
				TokenBase: TokenBase{
					TokenKeyslot: 4,
					TokenName:    "abc"},
				Priority: 1},
			// Add a token with priority -1 to test that it
			// is omitted from TokensByPriority.
			5: &KeyDataToken{
				TokenBase: TokenBase{
					TokenKeyslot: 5,
					TokenName:    "xyz"},
				Priority: -1},
			// Add a token without a corresponding keyslot
			// to test OrphanedTokenIds, and to ensure that
			// it is omitted from TokenNames and TokenByName.
			6: MockOrphanedToken(KeyDataTokenType, "orphaned"),
			// Test that an orphaned token can't own a name used
			// by a valid token.
			7: MockOrphanedToken(KeyDataTokenType, "foo")}}})

func (s *viewSuite) TestViewTokenNames(c *C) {
	view, err := NewViewFromCustomHeaderSource(testHeader)
	c.Assert(err, IsNil)
	c.Check(view.TokenNames(), DeepEquals, []string{"abc", "bar", "foo", "recovery", "xyz"})
}

func (s *viewSuite) TestViewTokenByName1(c *C) {
	view, err := NewViewFromCustomHeaderSource(testHeader)
	c.Assert(err, IsNil)

	token, id, exists := view.TokenByName("foo")
	c.Check(exists, testutil.IsTrue)
	c.Check(token, DeepEquals, testHeader.Metadata.Tokens[0])
	c.Check(id, Equals, 0)
}

func (s *viewSuite) TestViewTokenByName2(c *C) {
	view, err := NewViewFromCustomHeaderSource(testHeader)
	c.Assert(err, IsNil)

	token, id, exists := view.TokenByName("bar")
	c.Check(exists, testutil.IsTrue)
	c.Check(token, DeepEquals, testHeader.Metadata.Tokens[2])
	c.Check(id, Equals, 2)
}

func (s *viewSuite) TestViewTokenByNameNonExistant(c *C) {
	view, err := NewViewFromCustomHeaderSource(testHeader)
	c.Assert(err, IsNil)

	token, _, exists := view.TokenByName("zzz")
	c.Check(exists, Not(testutil.IsTrue))
	c.Check(token, IsNil)
}

func (s *viewSuite) TestViewTokenByNameOrphaned(c *C) {
	view, err := NewViewFromCustomHeaderSource(testHeader)
	c.Assert(err, IsNil)

	token, _, exists := view.TokenByName("orphaned")
	c.Check(exists, Not(testutil.IsTrue))
	c.Check(token, IsNil)
}

func (s *viewSuite) TestViewKeyDataTokensByPriority(c *C) {
	view, err := NewViewFromCustomHeaderSource(testHeader)
	c.Assert(err, IsNil)

	tokens := view.KeyDataTokensByPriority()
	c.Assert(tokens, HasLen, 3)
	c.Check(tokens[0], DeepEquals, testHeader.Metadata.Tokens[4])
	c.Check(tokens[1], DeepEquals, testHeader.Metadata.Tokens[0])
	c.Check(tokens[2], DeepEquals, testHeader.Metadata.Tokens[2])
}

func (s *viewSuite) TestViewOrphanedTokenIds(c *C) {
	view, err := NewViewFromCustomHeaderSource(testHeader)
	c.Assert(err, IsNil)
	c.Check(view.OrphanedTokenIds(), DeepEquals, []int{6, 7})
}

func (s *viewSuite) TestViewUsedKeyslots(c *C) {
	view, err := NewViewFromCustomHeaderSource(testHeader)
	c.Assert(err, IsNil)
	c.Check(view.UsedKeyslots(), DeepEquals, []int{0, 1, 2, 3, 4, 5})
}

func (s *viewSuite) TestNewView(c *C) {
	if luks2.DetectCryptsetupFeatures()&luks2.FeatureTokenImport == 0 {
		c.Skip("cryptsetup doesn't support token import")
	}

	path := luks2test.CreateEmptyDiskImage(c, 20)

	options := luks2.FormatOptions{KDFOptions: luks2.KDFOptions{MemoryKiB: 32, ForceIterations: 4}}
	c.Check(luks2.Format(path, "", make([]byte, 32), &options), IsNil)

	token := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:    "default",
			TokenKeyslot: 0},
		Priority: 1}
	c.Check(luks2.ImportToken(path, token, nil), IsNil)

	recoveryToken := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:    "recovery",
			TokenKeyslot: 0}}
	c.Check(luks2.ImportToken(path, recoveryToken, nil), IsNil)

	view, err := NewView(path, luks2.LockModeNonBlocking)
	c.Assert(err, IsNil)

	c.Check(view.TokenNames(), DeepEquals, []string{"default", "recovery"})

	t, id, exists := view.TokenByName("default")
	c.Check(t, DeepEquals, token)
	c.Check(id, Equals, 0)
	c.Check(exists, testutil.IsTrue)

	t, id, exists = view.TokenByName("recovery")
	c.Check(t, DeepEquals, recoveryToken)
	c.Check(id, Equals, 1)
	c.Check(exists, testutil.IsTrue)

	c.Check(view.UsedKeyslots(), DeepEquals, []int{0})
}

func (s *viewSuite) TestViewReread(c *C) {
	if luks2.DetectCryptsetupFeatures()&(luks2.FeatureTokenImport|luks2.FeatureTokenReplace) != (luks2.FeatureTokenImport | luks2.FeatureTokenReplace) {
		c.Skip("cryptsetup doesn't support token import or replace")
	}

	path := luks2test.CreateEmptyDiskImage(c, 20)

	options := luks2.KDFOptions{MemoryKiB: 32, ForceIterations: 4}
	c.Check(luks2.Format(path, "", make([]byte, 32), &luks2.FormatOptions{KDFOptions: options}), IsNil)

	token := &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:    "default",
			TokenKeyslot: 0},
		Priority: 1}
	c.Check(luks2.ImportToken(path, token, nil), IsNil)

	view, err := NewView(path, luks2.LockModeNonBlocking)
	c.Assert(err, IsNil)

	c.Check(view.TokenNames(), DeepEquals, []string{"default"})

	token = &KeyDataToken{
		TokenBase: TokenBase{
			TokenName:    "default",
			TokenKeyslot: 0},
		Priority: 2}
	c.Check(luks2.ImportToken(path, token, &luks2.ImportTokenOptions{Replace: true, Id: 0}), IsNil)

	c.Check(luks2.AddKey(path, make([]byte, 32), make([]byte, 32), &luks2.AddKeyOptions{KDFOptions: options, Slot: luks2.AnySlot}), IsNil)
	recoveryToken := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:    "recovery",
			TokenKeyslot: 1}}
	c.Check(luks2.ImportToken(path, recoveryToken, nil), IsNil)

	c.Check(luks2.AddKey(path, make([]byte, 32), make([]byte, 32), &luks2.AddKeyOptions{KDFOptions: options, Slot: luks2.AnySlot}), IsNil)
	token2 := &RecoveryToken{
		TokenBase: TokenBase{
			TokenName:    "foo",
			TokenKeyslot: 2}}
	c.Check(luks2.ImportToken(path, token2, nil), IsNil)
	c.Check(luks2.KillSlot(path, 2), IsNil)

	c.Check(view.Reread(), IsNil)

	t, id, exists := view.TokenByName("default")
	c.Check(t, DeepEquals, token)
	c.Check(id, Equals, 0)
	c.Check(exists, testutil.IsTrue)

	t, id, exists = view.TokenByName("recovery")
	c.Check(t, DeepEquals, recoveryToken)
	c.Check(id, Equals, 1)
	c.Check(exists, testutil.IsTrue)

	t, id, exists = view.TokenByName("foo")
	c.Check(t, IsNil)
	c.Check(id, Equals, 0)
	c.Check(exists, Not(testutil.IsTrue))

	c.Check(view.UsedKeyslots(), DeepEquals, []int{0, 1})
	c.Check(view.OrphanedTokenIds(), DeepEquals, []int{2})
}
