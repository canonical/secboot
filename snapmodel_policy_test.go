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

package secboot_test

import (
	"encoding/base64"
	"time"

	"github.com/chrisccoulson/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"

	. "gopkg.in/check.v1"
)

type snapModelProfileTest struct{}

var _ = Suite(&snapModelProfileTest{})

type testAddSnapModelProfileData struct {
	profile *PCRProtectionProfile
	params  *SnapModelProfileParams
	values  []tpm2.PCRValues
}

func (s *snapModelProfileTest) testAddSnapModelProfile(c *C, data *testAddSnapModelProfileData) {
	profile := data.profile
	if profile == nil {
		profile = NewPCRProtectionProfile()
	}
	c.Check(AddSnapModelProfile(profile, data.params), IsNil)
	values, err := profile.ComputePCRValues(nil)
	c.Assert(err, IsNil)
	c.Check(values, DeepEquals, data.values)
	for i, v := range values {
		c.Logf("Value %d:", i)
		for alg := range v {
			for pcr := range v[alg] {
				c.Logf(" PCR%d,%v: %x", pcr, alg, v[alg][pcr])
			}
		}
	}
}

func (s *snapModelProfileTest) TestAddSnapModelProfile1(c *C) {
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []*asserts.Model{
				assertstest.FakeAssertion(map[string]interface{}{
					"type":         "model",
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"architecture": "amd64",
					"gadget":       "pc=20",
					"kernel":       "pc-kernel=20",
					"base":         "core20",
				}).(*asserts.Model),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "4d4e46741b272922844798df559dc511366f6239d9b987f856cbb7e8ef0f8131"),
				},
			},
		},
	})
}

func (s *snapModelProfileTest) TestAddSnapModelProfile2(c *C) {
	// Test that changing the signing key produces a new digest.
	model, err := asserts.Assemble(map[string]interface{}{
		"type":              "model",
		"authority-id":      "fake-brand",
		"series":            "20",
		"brand-id":          "fake-brand",
		"model":             "fake-model",
		"architecture":      "amd64",
		"gadget":            "pc=20",
		"kernel":            "pc-kernel=20",
		"base":              "core20",
		"timestamp":         time.Now().Format(time.RFC3339),
		"sign-key-sha3-384": base64.RawURLEncoding.EncodeToString(decodeHexString(c, "190d8045dc5875c1004e4dd31f13194eea25043cf9ffc40550cca30fdcae20f8d7eed05f3c94058b206329dbe8d2312e")),
	}, nil, nil, []byte("AXNpZw=="))
	c.Assert(err, IsNil)

	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models:       []*asserts.Model{model.(*asserts.Model)},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "df6f0c42b613de7d273822675a8dcc45446b05a8ac2286c462bb88c71a306bd1"),
				},
			},
		},
	})
}

func (s *snapModelProfileTest) TestAddSnapModelProfile3(c *C) {
	// Test that changing the brand-id produces a new digest.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []*asserts.Model{
				assertstest.FakeAssertion(map[string]interface{}{
					"type":         "model",
					"authority-id": "other-brand",
					"series":       "20",
					"brand-id":     "other-brand",
					"model":        "fake-model",
					"architecture": "amd64",
					"gadget":       "pc=20",
					"kernel":       "pc-kernel=20",
					"base":         "core20",
				}).(*asserts.Model),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "243420e1dc752a6ea5700040c7e55c9b5975ed5351f55732b56f0e8b5e89879b"),
				},
			},
		},
	})
}

func (s *snapModelProfileTest) TestAddSnapModelProfile4(c *C) {
	// Test that changing the model produces a new digest.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []*asserts.Model{
				assertstest.FakeAssertion(map[string]interface{}{
					"type":         "model",
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "other-model",
					"architecture": "amd64",
					"gadget":       "pc=20",
					"kernel":       "pc-kernel=20",
					"base":         "core20",
				}).(*asserts.Model),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "79010a11d00afb85a7c6798b37ea65e19d5c469fc04c28cce3139f205382e4f9"),
				},
			},
		},
	})
}

func (s *snapModelProfileTest) TestAddSnapModelProfile5(c *C) {
	// Test that changing the series produces a new digest.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []*asserts.Model{
				assertstest.FakeAssertion(map[string]interface{}{
					"type":         "model",
					"authority-id": "fake-brand",
					"series":       "18",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"architecture": "amd64",
					"gadget":       "pc=20",
					"kernel":       "pc-kernel=20",
					"base":         "core20",
				}).(*asserts.Model),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "80804cb20ed8ec6069b61cf37304c6c18f8b8785bb83736fa48dd3b3e6d59daf"),
				},
			},
		},
	})
}

func (s *snapModelProfileTest) TestAddSnapModelProfile6(c *C) {
	// Test with a different PCR alg.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA1,
			PCRIndex:     12,
			Models: []*asserts.Model{
				assertstest.FakeAssertion(map[string]interface{}{
					"type":         "model",
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"architecture": "amd64",
					"gadget":       "pc=20",
					"kernel":       "pc-kernel=20",
					"base":         "core20",
				}).(*asserts.Model),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA1: {
					12: decodeHexString(c, "e92abf598a159fad8e1cda1a408ba8b278295f0c"),
				},
			},
		},
	})
}

func (s *snapModelProfileTest) TestAddSnapModelProfile7(c *C) {
	// Test with a different PCR.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     14,
			Models: []*asserts.Model{
				assertstest.FakeAssertion(map[string]interface{}{
					"type":         "model",
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"architecture": "amd64",
					"gadget":       "pc=20",
					"kernel":       "pc-kernel=20",
					"base":         "core20",
				}).(*asserts.Model),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					14: decodeHexString(c, "4d4e46741b272922844798df559dc511366f6239d9b987f856cbb7e8ef0f8131"),
				},
			},
		},
	})
}

func (s *snapModelProfileTest) TestAddSnapModelProfile8(c *C) {
	// Test with more than one model.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []*asserts.Model{
				assertstest.FakeAssertion(map[string]interface{}{
					"type":         "model",
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"architecture": "amd64",
					"gadget":       "pc=20",
					"kernel":       "pc-kernel=20",
					"base":         "core20",
				}).(*asserts.Model),
				assertstest.FakeAssertion(map[string]interface{}{
					"type":         "model",
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "other-model",
					"architecture": "amd64",
					"gadget":       "pc=20",
					"kernel":       "pc-kernel=20",
					"base":         "core20",
				}).(*asserts.Model),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "4d4e46741b272922844798df559dc511366f6239d9b987f856cbb7e8ef0f8131"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "79010a11d00afb85a7c6798b37ea65e19d5c469fc04c28cce3139f205382e4f9"),
				},
			},
		},
	})
}

func (s *snapModelProfileTest) TestAddSnapModelProfile9(c *C) {
	// Test extending in to an initial profile.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		profile: NewPCRProtectionProfile().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 12, makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []*asserts.Model{
				assertstest.FakeAssertion(map[string]interface{}{
					"type":         "model",
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"architecture": "amd64",
					"gadget":       "pc=20",
					"kernel":       "pc-kernel=20",
					"base":         "core20",
				}).(*asserts.Model),
				assertstest.FakeAssertion(map[string]interface{}{
					"type":         "model",
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "other-model",
					"architecture": "amd64",
					"gadget":       "pc=20",
					"kernel":       "pc-kernel=20",
					"base":         "core20",
				}).(*asserts.Model),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7:  makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					12: decodeHexString(c, "2c3caf892570525d37d4729bfb260593f8a1ca607ae8e8b2ea573bb7e0bc3904"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7:  makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					12: decodeHexString(c, "566e37630ca8b0adcce77f7c77f193bffc98d307944503188b7aa46a5c7555ce"),
				},
			},
		},
	})
}

func (s *snapModelProfileTest) TestAddSnapModelProfile10(c *C) {
	// Test that there aren't contatenation issues with brand-id/model/series - ie, "fake-brand,fake-model,20" should
	// be different to "fake-bran,dfake-mode,l20".
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []*asserts.Model{
				assertstest.FakeAssertion(map[string]interface{}{
					"type":         "model",
					"authority-id": "fake-bran",
					"series":       "l20",
					"brand-id":     "fake-bran",
					"model":        "dfake-mode",
					"architecture": "amd64",
					"gadget":       "pc=20",
					"kernel":       "pc-kernel=20",
					"base":         "core20",
				}).(*asserts.Model),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "7c7b7f6062cf23af1b717b2980ceefc7404f30a4a9c37c43573e4bbbe53c4a5b"),
				},
			},
		},
	})
}
