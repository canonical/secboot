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
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/util"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type pcrProfileSuite struct{}

var _ = Suite(&pcrProfileSuite{})

type testPCRProtectionProfileData struct {
	alg     tpm2.HashAlgorithmId
	profile *PCRProtectionProfile
	pcrs    tpm2.PCRSelectionList
	values  []tpm2.PCRValues
}

func (s *pcrProfileSuite) testPCRProtectionProfile(c *C, data *testPCRProtectionProfileData) {
	expectedPcrs, err := data.values[0].SelectionList()
	c.Assert(err, IsNil)

	var expectedDigests tpm2.DigestList
	for _, v := range data.values {
		d, _ := util.ComputePCRDigest(data.alg, expectedPcrs, v)
		expectedDigests = append(expectedDigests, d)
	}

	pcrs, pcrDigests, err := data.profile.ComputePCRDigests(nil, data.alg)
	c.Assert(err, IsNil)
	c.Check(pcrs.Equal(expectedPcrs), testutil.IsTrue)
	c.Check(pcrDigests, DeepEquals, expectedDigests)

	if c.Failed() {
		c.Logf("Profile:\n%s", data.profile)
		c.Logf("Values:\n%s", tpm2test.FormatPCRValuesFromPCRProtectionProfile(data.profile, nil))
	}
}

func (s *pcrProfileSuite) TestLegacyAddPCRValues(c *C) {
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: NewPCRProtectionProfile().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestAddPCRValues(c *C) {
	// Verify that AddPCRValues works as expected
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: func() *PCRProtectionProfile {
			profile := NewPCRProtectionProfile()
			profile.RootBranch().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			return profile
		}(),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestAddPCRValuesOverwritesPrevious(c *C) {
	// Verify that AddPCRValues overwrites previous values
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: func() *PCRProtectionProfile {
			profile := NewPCRProtectionProfile()
			profile.RootBranch().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			return profile
		}(),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestLegacyAddProfileOR1(c *C) {
	// Verify that (A1 || A2) && (B1 || B2) produces 4 outcomes
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: NewPCRProtectionProfile().
			AddProfileOR(
				NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")),
				NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2"))).
			AddProfileOR(
				NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
				NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2"))),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestLegacyAddProfileOR2(c *C) {
	// Verify that (A1 && B1) || (A2 && B2) produces 2 outcomes
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: NewPCRProtectionProfile().AddProfileOR(
			NewPCRProtectionProfile().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
			NewPCRProtectionProfile().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2"))),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestLegacyExtendPCR(c *C) {
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: NewPCRProtectionProfile().
			ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
			ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event2")).
			ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event3")).
			ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event4")),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "event1", "event3"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "event2", "event4"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestExtendPCR(c *C) {
	// Verify that ExtendPCR without an initial value works as expected
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: func() *PCRProtectionProfile {
			p := NewPCRProtectionProfile()
			p.RootBranch().
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event2")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event3")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event4"))
			return p
		}(),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "event1", "event3"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "event2", "event4"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestExtendPCRAfterAddPCRValue(c *C) {
	// Verify that ExtendPCR after AddPCRValue works as expected
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: func() *PCRProtectionProfile {
			p := NewPCRProtectionProfile()
			p.RootBranch().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event2"))
			return p
		}(),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event1"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event2"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestLegacyAddProfileOR3(c *C) {
	// Verify that ExtendPCR inside ProfileOR with initial PCR values works as expected
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: NewPCRProtectionProfile().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
			AddProfileOR(
				NewPCRProtectionProfile().
					ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event2")),
				NewPCRProtectionProfile().
					ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event3")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event4"))).
			ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event5")).
			ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event6")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 4, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "xyz")),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "xyz"),
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event1", "event5"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event2", "event6"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "xyz"),
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event3", "event5"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event4", "event6"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestLegacyAddProfileOR4(c *C) {
	// Verify that AddPCRValue inside ProfileOR with initial PCR values works as expected
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: NewPCRProtectionProfile().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
			AddProfileOR(
				NewPCRProtectionProfile().
					ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
					AddPCRValue(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")),
				NewPCRProtectionProfile().
					AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
					ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event4"))),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event1"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event4"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestCompoundProfile(c *C) {
	// Verify that (A1 || A2) && (B1 || B2) produces 4 outcomes
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: func() *PCRProtectionProfile {
			p := NewPCRProtectionProfile()
			p.RootBranch().
				AddBranchPoint(). // Begin (A1 || A2)
				AddBranch().      // Begin A1
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				EndBranch(). // End A1
				AddBranch(). // Begin A2
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).
				EndBranch().      // End A2
				EndBranchPoint(). // End (A1 || A2)
				AddBranchPoint(). // Begin (B1 || B2)
				AddBranch().      // Begin B1
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
				EndBranch(). // End B1
				AddBranch(). // Begin B2
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).
				EndBranch().     // End B2
				EndBranchPoint() // End (B1 || B2)
			return p
		}(),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestCompoundProfile2(c *C) {
	// Verify that (A1 && B1) || (A2 && B2) produces 2 outcomes
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: func() *PCRProtectionProfile {
			p := NewPCRProtectionProfile()
			p.RootBranch().
				AddBranchPoint(). // Begin (A1 && B1) || (A2 && B2)
				AddBranch().      // Begin (A1 && B1)
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
				EndBranch(). // End (A1 && B1)
				AddBranch(). // Begin (A2 && B2)
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2")).
				EndBranch().     // End (A2 && B2)
				EndBranchPoint() // End (A1 && B1) || (A2 && B2)
			return p
		}(),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo2"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar2"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestCompoundProfile3(c *C) {
	// Verify that ExtendPCR inside subbranches with initial PCR values works as expected
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: func() *PCRProtectionProfile {
			p := NewPCRProtectionProfile()
			p.RootBranch().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
				AddBranchPoint().
				AddBranch().
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event2")).
				EndBranch().
				AddBranch().
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event3")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event4")).
				EndBranch().
				EndBranchPoint().
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event5")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event6")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 4, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "xyz"))
			return p
		}(),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					4:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "xyz"),
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event1", "event5"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event2", "event6"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					4:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "xyz"),
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event3", "event5"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event4", "event6"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestCompoundProfile4(c *C) {
	// Verify that AddPCRValue inside ProfileOR with initial PCR values works as expected
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: func() *PCRProtectionProfile {
			p := NewPCRProtectionProfile()
			p.RootBranch().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
				AddBranchPoint().
				AddBranch().
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				EndBranch().
				AddBranch().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event4")).
				EndBranch().
				EndBranchPoint()
			return p
		}(),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event1"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event4"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestSHA1PCRs(c *C) {
	// Verify that other PCR algorithms work
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: func() *PCRProtectionProfile {
			p := NewPCRProtectionProfile()
			p.RootBranch().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA1, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA1, "bar"))
			return p
		}(),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA1: {
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA1, "bar"),
				},
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestSHA1(c *C) {
	// Verify that other PCR digest algorithms work
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA1,
		profile: func() *PCRProtectionProfile {
			p := NewPCRProtectionProfile()
			p.RootBranch().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			return p
		}(),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestDeDuplicate(c *C) {
	// Verify that (A1 && B1) || (A1 && B1) is de-duplicated
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: func() *PCRProtectionProfile {
			p := NewPCRProtectionProfile()
			p.RootBranch().
				AddBranchPoint().
				AddBranch().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
				EndBranch().
				AddBranch().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
				EndBranch().
				EndBranchPoint()
			return p
		}(),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestEmptyProfileOR(c *C) {
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: func() *PCRProtectionProfile {
			p := NewPCRProtectionProfile()
			p.RootBranch().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddBranchPoint().
				EndBranchPoint().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"))
			return p
		}(),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					8: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestProfileString(c *C) {
	profile := NewPCRProtectionProfile()
	profile.RootBranch().
		AddPCRValue(tpm2.HashAlgorithmSHA256, 7, make([]byte, tpm2.HashAlgorithmSHA256.Size())).
		AddPCRValue(tpm2.HashAlgorithmSHA256, 8, make([]byte, tpm2.HashAlgorithmSHA256.Size())).
		AddBranchPoint().
		AddBranch().
		ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo1")).
		ExtendPCR(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar1")).
		EndBranch().
		AddBranch().
		ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar1")).
		ExtendPCR(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo1")).
		EndBranch().
		EndBranchPoint().
		ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "end")).
		AddPCRValueFromTPM(tpm2.HashAlgorithmSHA1, 0)

	expectedTpl := `
 AddPCRValue(TPM_ALG_SHA256, 7, %[1]x)
 AddPCRValue(TPM_ALG_SHA256, 8, %[1]x)
 BranchPoint(
   Branch 0 {
    ExtendPCR(TPM_ALG_SHA256, 7, %[2]x)
    ExtendPCR(TPM_ALG_SHA256, 8, %[3]x)
   }
   Branch 1 {
    ExtendPCR(TPM_ALG_SHA256, 7, %[3]x)
    ExtendPCR(TPM_ALG_SHA256, 8, %[2]x)
   }
 )
 ExtendPCR(TPM_ALG_SHA256, 7, %[4]x)
 AddPCRValueFromTPM(TPM_ALG_SHA1, 0)
`

	expected := fmt.Sprintf(expectedTpl,
		make([]byte, tpm2.HashAlgorithmSHA256.Size()),
		tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo1"),
		tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar1"),
		tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "end"))
	c.Check(profile.String(), Equals, expected)
}

func (s *pcrProfileSuite) TestModifyCompletedBranchPointFails1(c *C) {
	profile := NewPCRProtectionProfile()
	bp := profile.RootBranch().AddBranchPoint()
	c.Check(bp.AddBranch(), NotNil)
	c.Check(bp.EndBranchPoint(), Equals, profile.RootBranch())
	c.Check(bp.AddBranch(), NotNil)

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: cannot add a branch to a branch point that has already been terminated \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 BranchPoint(
   Branch 0 {
   }
 )
`)
}

func (s *pcrProfileSuite) TestModifyCompletedBranchPointFails2(c *C) {
	// Test that EndBranch terminates an in-progress branch point as well
	profile := NewPCRProtectionProfile()
	bp := profile.RootBranch().AddBranchPoint()
	b := bp.AddBranch()
	bp2 := b.AddBranchPoint()
	c.Check(b.EndBranch(), Equals, bp)
	c.Check(bp2.AddBranch(), NotNil)

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: cannot add a branch to a branch point that has already been terminated \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 BranchPoint(
   Branch 0 {
    BranchPoint(
    )
   }
 )
`)
}

func (s *pcrProfileSuite) TestModifyCompletedBranchPointFailsRecursiveMany(c *C) {
	profile := NewPCRProtectionProfile()
	bp := profile.RootBranch().AddBranchPoint()
	bp2 := bp.AddBranch().AddBranchPoint().AddBranch().AddBranchPoint().AddBranch().AddBranchPoint()
	c.Check(bp.EndBranchPoint(), Equals, profile.RootBranch())
	c.Check(bp2.AddBranch(), NotNil)

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: cannot add a branch to a branch point that has already been terminated \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 BranchPoint(
   Branch 0 {
    BranchPoint(
      Branch 0 {
       BranchPoint(
         Branch 0 {
          BranchPoint(
          )
         }
       )
      }
    )
   }
 )
`)
}

func (s *pcrProfileSuite) TestEndCompletedBranchPointFails(c *C) {
	profile := NewPCRProtectionProfile()
	bp := profile.RootBranch().AddBranchPoint()
	c.Check(bp.AddBranch(), NotNil)
	c.Check(bp.EndBranchPoint(), Equals, profile.RootBranch())
	c.Check(bp.EndBranchPoint(), Equals, profile.RootBranch())

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: cannot terminate a branch point more than once \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 BranchPoint(
   Branch 0 {
   }
 )
`)
}

func (s *pcrProfileSuite) TestModifyCompletedBranchFails1(c *C) {
	profile := NewPCRProtectionProfile()
	bp := profile.RootBranch().AddBranchPoint()
	b := bp.AddBranch()
	c.Check(b.EndBranch(), Equals, bp)
	c.Check(b.AddPCRValue(tpm2.HashAlgorithmSHA256, 0, make([]byte, 32)), Equals, b)

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: cannot modify branch that has already been terminated \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 BranchPoint(
   Branch 0 {
   }
 )
`)
}

func (s *pcrProfileSuite) TestModifyCompletedBranchFails2(c *C) {
	profile := NewPCRProtectionProfile()
	bp := profile.RootBranch().AddBranchPoint()
	b := bp.AddBranch()
	c.Check(b.EndBranch(), Equals, bp)
	c.Check(b.AddBranchPoint().AddBranch(), NotNil)

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: cannot modify branch that has already been terminated \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 BranchPoint(
   Branch 0 {
   }
 )
`)
}

func (s *pcrProfileSuite) TestModifyCompletedBranchFails3(c *C) {
	// Test that EndBranchPoint terminates sub-branches
	profile := NewPCRProtectionProfile()
	bp := profile.RootBranch().AddBranchPoint()
	b := bp.AddBranch()
	c.Check(bp.EndBranchPoint(), Equals, profile.RootBranch())
	c.Check(b.AddPCRValue(tpm2.HashAlgorithmSHA256, 0, make([]byte, 32)), Equals, b)

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: cannot modify branch that has already been terminated \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 BranchPoint(
   Branch 0 {
   }
 )
`)
}

func (s *pcrProfileSuite) TestModifyCompletedBranchFailsRecursiveMany(c *C) {
	profile := NewPCRProtectionProfile()
	bp := profile.RootBranch().AddBranchPoint()
	b := bp.AddBranch().AddBranchPoint().AddBranch().AddBranchPoint().AddBranch().AddBranchPoint().AddBranch()
	c.Check(bp.EndBranchPoint(), Equals, profile.RootBranch())
	c.Check(b.AddPCRValue(tpm2.HashAlgorithmSHA256, 0, make([]byte, 32)), Equals, b)

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: cannot modify branch that has already been terminated \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 BranchPoint(
   Branch 0 {
    BranchPoint(
      Branch 0 {
       BranchPoint(
         Branch 0 {
          BranchPoint(
            Branch 0 {
            }
          )
         }
       )
      }
    )
   }
 )
`)
}

func (s *pcrProfileSuite) TestInvalidAlg1(c *C) {
	profile := NewPCRProtectionProfile()
	c.Check(profile.RootBranch().AddPCRValue(tpm2.HashAlgorithmNull, 0, nil), Equals, profile.RootBranch())

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: invalid digest algorithm \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 AddPCRValue(TPM_ALG_NULL, 0, )
`)
}

func (s *pcrProfileSuite) TestInvalidAlg2(c *C) {
	profile := NewPCRProtectionProfile()
	c.Check(profile.RootBranch().ExtendPCR(tpm2.HashAlgorithmNull, 0, nil), Equals, profile.RootBranch())

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: invalid digest algorithm \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 ExtendPCR(TPM_ALG_NULL, 0, )
`)
}

func (s *pcrProfileSuite) TestInvalidPCR1(c *C) {
	profile := NewPCRProtectionProfile()
	c.Check(profile.RootBranch().AddPCRValue(tpm2.HashAlgorithmSHA256, -1, make([]byte, 32)), Equals, profile.RootBranch())

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: invalid PCR index \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 AddPCRValue(TPM_ALG_SHA256, -1, 0000000000000000000000000000000000000000000000000000000000000000)
`)
}

func (s *pcrProfileSuite) TestInvalidPCR2(c *C) {
	profile := NewPCRProtectionProfile()
	c.Check(profile.RootBranch().AddPCRValue(tpm2.HashAlgorithmSHA256, 2048, make([]byte, 32)), Equals, profile.RootBranch())

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: invalid PCR index \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 AddPCRValue(TPM_ALG_SHA256, 2048, 0000000000000000000000000000000000000000000000000000000000000000)
`)
}

func (s *pcrProfileSuite) TestInvalidDigest1(c *C) {
	profile := NewPCRProtectionProfile()
	c.Check(profile.RootBranch().AddPCRValue(tpm2.HashAlgorithmSHA256, 1, make([]byte, 20)), Equals, profile.RootBranch())

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: digest length is inconsistent with specified algorithm \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, "\n")
}

func (s *pcrProfileSuite) TestInvalidDigest2(c *C) {
	profile := NewPCRProtectionProfile()
	c.Check(profile.RootBranch().ExtendPCR(tpm2.HashAlgorithmSHA256, 1, make([]byte, 20)), Equals, profile.RootBranch())

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: digest length is inconsistent with specified algorithm \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, "\n")
}

func (s *pcrProfileSuite) TestTerminateRootBranchFails(c *C) {
	profile := NewPCRProtectionProfile()
	bp := profile.RootBranch().EndBranch()
	c.Check(bp, NotNil)
	c.Check(bp.EndBranchPoint(), NotNil)

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: cannot terminate the root branch \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
}

func (s *pcrProfileSuite) TestLegacyAddProfileORPropagatesErrors1(c *C) {
	profile := NewPCRProtectionProfile()
	subProfile := NewPCRProtectionProfile()
	c.Check(subProfile.RootBranch().EndBranch(), NotNil)
	c.Check(profile.AddProfileOR(subProfile), Equals, profile)

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: cannot terminate the root branch \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 BranchPoint(
 )
`)
}

func (s *pcrProfileSuite) TestLegacyAddProfileORPropagatesErrors2(c *C) {
	profile := NewPCRProtectionProfile()
	subProfile := NewPCRProtectionProfile()
	c.Check(profile.AddProfileOR(subProfile), Equals, profile)
	c.Check(subProfile.AddPCRValue(tpm2.HashAlgorithmSHA256, 0, make([]byte, 32)), Equals, subProfile)

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: cannot modify branch that has already been terminated \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 BranchPoint(
   Branch 0 {
   }
 )
`)
}

func (s *pcrProfileSuite) TestMultipleFailures(c *C) {
	profile := NewPCRProtectionProfile()
	c.Check(profile.RootBranch().AddPCRValue(tpm2.HashAlgorithmNull, 0, nil), Equals, profile.RootBranch())
	c.Check(profile.RootBranch().EndBranch(), NotNil)

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot compute PCR values because an error occurred when constructing the profile: invalid digest algorithm \(occurred at \/.*\/pcr_profile_test\.go:[[:digit:]]+\)`)
	c.Check(profile.String(), Equals, `
 AddPCRValue(TPM_ALG_NULL, 0, )
`)
}

func (s *pcrProfileSuite) TestUnbalancedBranchesFails(c *C) {
	profile := NewPCRProtectionProfile()
	c.Check(profile.RootBranch().
		AddBranchPoint().
		AddBranch().
		AddPCRValue(tpm2.HashAlgorithmSHA256, 0, make([]byte, 32)).
		EndBranch().
		AddBranch().
		AddPCRValue(tpm2.HashAlgorithmSHA256, 1, make([]byte, 32)).
		EndBranch().
		EndBranchPoint(), Equals, profile.RootBranch())

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `not all branches contain values for the same sets of PCRs`)
}

func (s *pcrProfileSuite) TestMarshalAndUnmarshal(c *C) {
	p := NewPCRProtectionProfile()
	p.RootBranch().
		AddBranchPoint(). // Begin (A1 || A2 || A3)
		AddBranch().      // Begin A1
		AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
		EndBranch(). // End A1
		AddBranch(). // Begin A2
		AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
		EndBranch(). // End A2
		AddBranch(). // Begin A3
		AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).
		EndBranch().      // End A3
		EndBranchPoint(). // End (A1 || A2 || A3)
		AddBranchPoint(). // Begin (B1 || B2 || B3)
		AddBranch().      // Begin B1
		AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
		EndBranch(). // End B1
		AddBranch(). // Begin B2
		AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
		EndBranch(). // End B2
		AddBranch(). // Begin B3
		AddPCRValue(tpm2.HashAlgorithmSHA256, 8, make([]byte, 32)).
		ExtendPCR(tpm2.HashAlgorithmSHA256, 8, make([]byte, 32)).
		EndBranch().     // End B3
		EndBranchPoint() // End (B1 || B2 || B3)
	b, err := mu.MarshalToBytes(p)
	c.Assert(err, IsNil)
	c.Check(b, DeepEquals, testutil.DecodeHexString(c, "00000003"+
		"0020424816d020cf3d793ac021da47379bdf608080a83eb9364a7fbe0bdfa87111d7"+
		"0020a98b1d896c9383603b7923fffe230c9e4df24218eb84c90c5c758e63ce62843c"+
		"00200000000000000000000000000000000000000000000000000000000000000000"+
		"00000019"+
		"01050102000b00000007070102000b00000807070103000b00070706050102000b00000808070102000b00000008070102000b0000100804000b00001008070607"))

	var p2 *PCRProtectionProfile
	_, err = mu.UnmarshalFromBytes(b, &p2)
	c.Assert(err, IsNil)
	c.Check(p2.String(), Equals, `
 BranchPoint(
   Branch 0 {
    AddPCRValue(TPM_ALG_SHA256, 7, 424816d020cf3d793ac021da47379bdf608080a83eb9364a7fbe0bdfa87111d7)
   }
   Branch 1 {
    AddPCRValue(TPM_ALG_SHA256, 7, a98b1d896c9383603b7923fffe230c9e4df24218eb84c90c5c758e63ce62843c)
   }
   Branch 2 {
    AddPCRValueFromTPM(TPM_ALG_SHA256, 7)
   }
 )
 BranchPoint(
   Branch 0 {
    AddPCRValue(TPM_ALG_SHA256, 8, a98b1d896c9383603b7923fffe230c9e4df24218eb84c90c5c758e63ce62843c)
   }
   Branch 1 {
    AddPCRValue(TPM_ALG_SHA256, 8, 424816d020cf3d793ac021da47379bdf608080a83eb9364a7fbe0bdfa87111d7)
   }
   Branch 2 {
    AddPCRValue(TPM_ALG_SHA256, 8, 0000000000000000000000000000000000000000000000000000000000000000)
    ExtendPCR(TPM_ALG_SHA256, 8, 0000000000000000000000000000000000000000000000000000000000000000)
   }
 )
`)
}

func (s *pcrProfileSuite) TestUnmarshalDigestIndexOutOfRange(c *C) {
	b := testutil.DecodeHexString(c, "00000000000000030102000b0000100707")

	var p *PCRProtectionProfile
	_, err := mu.UnmarshalFromBytes(b, &p)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type "+
		"tpm2.PCRProtectionProfile: digest index \\(2\\) out of range for instruction 1")
}

func (s *pcrProfileSuite) TestUnmarshalMissingEndBranch(c *C) {
	b := testutil.DecodeHexString(c, "000000010014a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5000000020102000400000007")

	var p *PCRProtectionProfile
	_, err := mu.UnmarshalFromBytes(b, &p)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type "+
		"tpm2.PCRProtectionProfile: missing EndBranch for root branch")
}

func (s *pcrProfileSuite) TestUnmarshalUnexpctedAddPCRValue(c *C) {
	b := testutil.DecodeHexString(c, "000000010014a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5000000020200040000000707")

	var p *PCRProtectionProfile
	_, err := mu.UnmarshalFromBytes(b, &p)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type "+
		"tpm2.PCRProtectionProfile: unexpected AddPCRValue at instruction 0")
}

func (s *pcrProfileSuite) TestUnmarshalUnexpctedAddPCRValueFromTPM(c *C) {
	b := testutil.DecodeHexString(c, "0000000000000002030004000707")

	var p *PCRProtectionProfile
	_, err := mu.UnmarshalFromBytes(b, &p)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type "+
		"tpm2.PCRProtectionProfile: unexpected AddPCRValueFromTPM at instruction 0")
}

func (s *pcrProfileSuite) TestUnmarshalUnexpctedExtendPCR(c *C) {
	b := testutil.DecodeHexString(c, "000000010014a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5000000020400040000000707")

	var p *PCRProtectionProfile
	_, err := mu.UnmarshalFromBytes(b, &p)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type "+
		"tpm2.PCRProtectionProfile: unexpected ExtendPCR at instruction 0")
}

func (s *pcrProfileSuite) TestUnmarshalUnexpctedBeginBranchPoint(c *C) {
	b := testutil.DecodeHexString(c, "00000000000000020507")

	var p *PCRProtectionProfile
	_, err := mu.UnmarshalFromBytes(b, &p)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type "+
		"tpm2.PCRProtectionProfile: unexpected BeginBranchPoint at instruction 0")
}

func (s *pcrProfileSuite) TestUnmarshalUnexpctedEndBranchPoint(c *C) {
	b := testutil.DecodeHexString(c, "0000000000000003010607")

	var p *PCRProtectionProfile
	_, err := mu.UnmarshalFromBytes(b, &p)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type "+
		"tpm2.PCRProtectionProfile: unexpected EndBranchPoint at instruction 1")
}

func (s *pcrProfileSuite) TestUnmarshalUnexpctedEndBranch1(c *C) {
	b := testutil.DecodeHexString(c, "000000000000000401070506")

	var p *PCRProtectionProfile
	_, err := mu.UnmarshalFromBytes(b, &p)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type "+
		"tpm2.PCRProtectionProfile: unexpected EndBranch for root branch at instruction 1")
}

func (s *pcrProfileSuite) TestUnmarshalUnexpctedEndBranch2(c *C) {
	b := testutil.DecodeHexString(c, "00000000000000050105070607")

	var p *PCRProtectionProfile
	_, err := mu.UnmarshalFromBytes(b, &p)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type "+
		"tpm2.PCRProtectionProfile: unexpected EndBranch at instruction 2")
}

func (s *pcrProfileSuite) TestAddPCRValueFromTPMFailsWithoutTPM(c *C) {
	profile := NewPCRProtectionProfile()
	c.Check(profile.RootBranch().
		AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 7).
		AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 8), Equals, profile.RootBranch())

	_, _, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot read current PCR values from TPM: no context`)
}

type pcrProfileTPMSuite struct {
	tpm2test.TPMTest
}

func (s *pcrProfileTPMSuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeaturePCR | tpm2test.TPMFeatureNV
}

var _ = Suite(&pcrProfileTPMSuite{})

func (s *pcrProfileTPMSuite) TestAddValueFromTPM(c *C) {
	_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	_, values, err := s.TPM().PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{23}}})
	c.Assert(err, IsNil)

	p := NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 23)
	pcrs, digests, err := p.ComputePCRDigests(s.TPM().TPMContext, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs.Equal(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{23}}}), testutil.IsTrue)
	c.Check(digests, HasLen, 1)

	expectedDigest, _ := util.ComputePCRDigest(tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{23}}}, values)
	c.Check(digests[0], DeepEquals, expectedDigest)
}

func (s *pcrProfileTPMSuite) TestAddValueFromTPMAddProfileORPropagatesSelection(c *C) {
	_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	_, values, err := s.TPM().PCRRead(tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA1, Select: []int{23}},
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{23}},
	})
	c.Assert(err, IsNil)

	p := NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 23)
	p2 := NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA1, 23)
	p.AddProfileOR(p2)

	pcrs, digests, err := p.ComputePCRDigests(s.TPM().TPMContext, tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(pcrs.Equal(tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA1, Select: []int{23}},
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{23}},
	}), testutil.IsTrue)
	c.Check(digests, HasLen, 1)

	expectedDigest, _ := util.ComputePCRDigest(tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA1, Select: []int{23}},
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{23}},
	}, values)
	c.Check(digests[0], DeepEquals, expectedDigest)
}

func (s *pcrProfileTPMSuite) TestAddValueFromTPMInvalidPCR(c *C) {
	p := NewPCRProtectionProfile()
	c.Check(p.RootBranch().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 100), Equals, p.RootBranch())

	_, _, err := p.ComputePCRDigests(s.TPM().TPMContext, tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot read current PCR values from TPM: TPM returned an error for parameter 1 whilst executing command TPM_CC_PCR_Read: TPM_RC_VALUE \(value is out of range or is not correct for the context\)`)
}
