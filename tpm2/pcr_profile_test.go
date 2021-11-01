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
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"

	. "gopkg.in/check.v1"

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
	expectedPcrs := data.values[0].SelectionList()
	var expectedDigests tpm2.DigestList
	for _, v := range data.values {
		d, _ := util.ComputePCRDigest(data.alg, expectedPcrs, v)
		expectedDigests = append(expectedDigests, d)
	}

	pcrs, pcrDigests, err := data.profile.ComputePCRDigests(nil, data.alg)
	c.Assert(err, IsNil)
	c.Check(pcrs.Equal(expectedPcrs), tpm2_testutil.IsTrue)
	c.Check(pcrDigests, DeepEquals, expectedDigests)

	if c.Failed() {
		c.Logf("Profile:\n%s", data.profile)
		c.Logf("Values:\n%s", tpm2test.FormatPCRValuesFromPCRProtectionProfile(data.profile, nil))
	}
}

func (s *pcrProfileSuite) TestAddValues1(c *C) {
	// Verify that AddPCRValues works as expected
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

func (s *pcrProfileSuite) TestAddValues2(c *C) {
	// Verify that AddPCRValues overwrites previous values
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: NewPCRProtectionProfile().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestOR1(c *C) {
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

func (s *pcrProfileSuite) TestOR2(c *C) {
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

func (s *pcrProfileSuite) TestExtend(c *C) {
	// Verify that ExtendPCR without an initial value works as expected
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

func (s *pcrProfileSuite) TestAddAndExtend(c *C) {
	// Verify that ExtendPCR after AddPCRValue works as expected
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: NewPCRProtectionProfile().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")).
			ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event1")).
			ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event2")),
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

func (s *pcrProfileSuite) TestOR3(c *C) {
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
					ExtendPCR(tpm2.HashAlgorithmSHA256, 12, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "event4"))),
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event1"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event2"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7:  tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "event3"),
					12: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "event4"),
				},
			},
		},
	})
}

func (s *pcrProfileSuite) TestOR4(c *C) {
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

func (s *pcrProfileSuite) TestSHA1PCRs(c *C) {
	// Verify that other PCR algorithms work
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: NewPCRProtectionProfile().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA1, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA1, "bar")),
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

func (s *pcrProfileSuite) TestDeDuplicate(c *C) {
	// Verify that (A1 && B1) || (A1 && B1) is de-duplicated
	s.testPCRProtectionProfile(c, &testPCRProtectionProfileData{
		alg: tpm2.HashAlgorithmSHA256,
		profile: NewPCRProtectionProfile().AddProfileOR(
			NewPCRProtectionProfile().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
			NewPCRProtectionProfile().
				AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
				AddPCRValue(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"))),
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
		profile: NewPCRProtectionProfile().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddProfileOR().
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

func (s *pcrProfileSuite) TestProfileString(c *C) {
	profile := NewPCRProtectionProfile().
		AddPCRValue(tpm2.HashAlgorithmSHA256, 7, make([]byte, tpm2.HashAlgorithmSHA256.Size())).
		AddPCRValue(tpm2.HashAlgorithmSHA256, 8, make([]byte, tpm2.HashAlgorithmSHA256.Size())).
		AddProfileOR(
			NewPCRProtectionProfile().
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo1")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar1")),
			NewPCRProtectionProfile().
				ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar1")).
				ExtendPCR(tpm2.HashAlgorithmSHA256, 8, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo1"))).
		ExtendPCR(tpm2.HashAlgorithmSHA256, 7, tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "end"))
	expectedTpl := `
 AddPCRValue(TPM_ALG_SHA256, 7, %[1]x)
 AddPCRValue(TPM_ALG_SHA256, 8, %[1]x)
 AddProfileOR(
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
`

	expected := fmt.Sprintf(expectedTpl,
		make([]byte, tpm2.HashAlgorithmSHA256.Size()),
		tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "foo1"),
		tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "bar1"),
		tpm2test.MakePCREventDigest(tpm2.HashAlgorithmSHA256, "end"))
	c.Check(profile.String(), Equals, expected)
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
	c.Check(pcrs.Equal(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{23}}}), tpm2_testutil.IsTrue)
	c.Check(digests, tpm2_testutil.LenEquals, 1)

	expectedDigest, _ := util.ComputePCRDigest(tpm2.HashAlgorithmSHA256, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{23}}}, values)
	c.Check(digests[0], DeepEquals, expectedDigest)
}
