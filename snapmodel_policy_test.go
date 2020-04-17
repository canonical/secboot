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
	"time"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/snapd/asserts"

	. "gopkg.in/check.v1"
)

type snapModelProfileTest struct{}

var _ = Suite(&snapModelProfileTest{})

func (s *snapModelProfileTest) makeMockCore20ModelAssertion(c *C, headers map[string]interface{}, signKeyHash string) *asserts.Model {
	template := map[string]interface{}{
		"type":              "model",
		"architecture":      "amd64",
		"base":              "core20",
		"timestamp":         time.Now().Format(time.RFC3339),
		"sign-key-sha3-384": signKeyHash,
		"snaps": []interface{}{
			map[string]interface{}{
				"name": "fake-linux",
				"id":   "fakelinuxidididididididididididi",
				"type": "kernel",
			},
			map[string]interface{}{
				"name": "fake-gadget",
				"id":   "fakegadgetididididididididididid",
				"type": "gadget",
			},
		},
	}
	for k, v := range headers {
		template[k] = v
	}

	assertion, err := asserts.Assemble(template, nil, nil, []byte("AXNpZw=="))
	c.Assert(err, IsNil)
	return assertion.(*asserts.Model)
}

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
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "c97cc440a039c990927565d6818f6f23734bbeed2951ed5d7bf1bd5ec5b04e8c"),
				},
			},
		},
	})
}

func (s *snapModelProfileTest) TestAddSnapModelProfile2(c *C) {
	// Test that changing the signing key produces a new digest.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []*asserts.Model{
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "GQ2ARdxYdcEATk3THxMZTuolBDz5_8QFUMyjD9yuIPjX7tBfPJQFiyBjKdvo0jEu"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "7712e7ef0dfff33588e0157d88c0400d5029e1293d05d4975ab88279f4ce6266"),
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
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "other-brand",
					"series":       "20",
					"brand-id":     "other-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "bdf8ad6741193f3e99cfb4cf0588d06f57a095746b7844a9245857c83829ab08"),
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
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "other-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "cd497d89f48ae1329f8a4b1fe7ddedaaf52f370c4f1dc8e631efd73be2663f41"),
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
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "18",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "6ab237c7d0855618765533137849477a759453e9a89c39f90ad23f5604aef601"),
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
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA1: {
					12: decodeHexString(c, "cbb043790386b031b5e40c3aa46b65479159f0a1"),
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
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					14: decodeHexString(c, "c97cc440a039c990927565d6818f6f23734bbeed2951ed5d7bf1bd5ec5b04e8c"),
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
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "other-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "c97cc440a039c990927565d6818f6f23734bbeed2951ed5d7bf1bd5ec5b04e8c"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "cd497d89f48ae1329f8a4b1fe7ddedaaf52f370c4f1dc8e631efd73be2663f41"),
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
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "other-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7:  makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					12: decodeHexString(c, "5d49397e8137997214ec3b32fb0632c207b76b30e8b2595aaca7006ddb49ab65"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7:  makePCRDigestFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					12: decodeHexString(c, "81723abe417d707e308dab720ecb00ae543931993175851d7356d46cecd46fef"),
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
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-bran",
					"series":       "l20",
					"brand-id":     "fake-bran",
					"model":        "dfake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "28f90b2f338afc3064cc5a06af4ebf61f6f6f2e181057a5ea4350b90b3f417bd"),
				},
			},
		},
	})
}

func (s *snapModelProfileTest) TestAddSnapModelProfile11(c *C) {
	// Test with a different grade.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []*asserts.Model{
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "20",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "dangerous",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: decodeHexString(c, "e644cdf6668fa8c675dddc21bdfdd0887381d9719faf1e44e882c3d34cc2bb5a"),
				},
			},
		},
	})
}
