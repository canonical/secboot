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
	"encoding/binary"
	"time"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/snapd/asserts"

	. "gopkg.in/check.v1"
)

type snapModelTestBase struct{}

func (tb *snapModelTestBase) makeMockCore20ModelAssertion(c *C, headers map[string]interface{}, signKeyHash string) SnapModel {
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
	return assertion.(SnapModel)
}

type snapModelProfileSuite struct {
	snapModelTestBase
}

var _ = Suite(&snapModelProfileSuite{})

type testAddSnapModelProfileData struct {
	profile *PCRProtectionProfile
	params  *SnapModelProfileParams
	values  []tpm2.PCRValues
}

func (s *snapModelProfileSuite) testAddSnapModelProfile(c *C, data *testAddSnapModelProfileData) {
	profile := data.profile
	if profile == nil {
		profile = NewPCRProtectionProfile()
	}
	expectedPcrs, _, _ := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	expectedPcrs = expectedPcrs.Merge(tpm2.PCRSelectionList{{Hash: data.params.PCRAlgorithm, Select: []int{data.params.PCRIndex}}})
	var expectedDigests tpm2.DigestList
	for _, v := range data.values {
		d, _ := tpm2.ComputePCRDigest(tpm2.HashAlgorithmSHA256, expectedPcrs, v)
		expectedDigests = append(expectedDigests, d)
	}

	c.Check(AddSnapModelProfile(profile, data.params), IsNil)
	pcrs, digests, err := profile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	c.Check(pcrs.Equal(expectedPcrs), Equals, true)
	c.Check(digests, DeepEquals, expectedDigests)
	if c.Failed() {
		c.Logf("Profile:\n%s", profile)
		c.Logf("Values:\n%s", profile.DumpValues(nil))
	}
}

func (s *snapModelProfileSuite) TestAddSnapModelProfile1(c *C) {
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []SnapModel{
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: testutil.DecodeHexString(c, "bd7851fd994a7f899364dbc96a95dffeaa250cd7ea33b4b6c313866169e779bc"),
				},
			},
		},
	})
}

func (s *snapModelProfileSuite) TestAddSnapModelProfile2(c *C) {
	// Test that changing the signing key produces a new digest.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []SnapModel{
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "GQ2ARdxYdcEATk3THxMZTuolBDz5_8QFUMyjD9yuIPjX7tBfPJQFiyBjKdvo0jEu"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: testutil.DecodeHexString(c, "df0c79fd31951f47b547a2914427159d52a870ed368a9dfd29fc08f28c341b6d"),
				},
			},
		},
	})
}

func (s *snapModelProfileSuite) TestAddSnapModelProfile3(c *C) {
	// Test that changing the brand-id produces a new digest.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []SnapModel{
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "other-brand",
					"series":       "16",
					"brand-id":     "other-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: testutil.DecodeHexString(c, "d2fd13d3097d7cf75c8f14f790f6a41e27e8925664b2324e73a749aa30971594"),
				},
			},
		},
	})
}

func (s *snapModelProfileSuite) TestAddSnapModelProfile4(c *C) {
	// Test that changing the model produces a new digest.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []SnapModel{
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "other-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: testutil.DecodeHexString(c, "7135fd41c92f097075cc21eefd6797498544fd329b3bf996654885ebf83bb2de"),
				},
			},
		},
	})
}

func (s *snapModelProfileSuite) TestAddSnapModelProfile5(c *C) {
	// Test that changing the series produces a new digest.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []SnapModel{
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "28",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: testutil.DecodeHexString(c, "62242d713e406f862ca35be37777b6932bfdcd8b766a99ce408c8c3bce68b2fe"),
				},
			},
		},
	})
}

func (s *snapModelProfileSuite) TestAddSnapModelProfile6(c *C) {
	// Test with a different PCR alg.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA1,
			PCRIndex:     12,
			Models: []SnapModel{
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA1: {
					12: testutil.DecodeHexString(c, "aa6839aca24500a572aea54bf5b23912abf8ed42"),
				},
			},
		},
	})
}

func (s *snapModelProfileSuite) TestAddSnapModelProfile7(c *C) {
	// Test with a different PCR.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     14,
			Models: []SnapModel{
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					14: testutil.DecodeHexString(c, "bd7851fd994a7f899364dbc96a95dffeaa250cd7ea33b4b6c313866169e779bc"),
				},
			},
		},
	})
}

func (s *snapModelProfileSuite) TestAddSnapModelProfile8(c *C) {
	// Test with more than one model.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []SnapModel{
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
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: testutil.DecodeHexString(c, "bd7851fd994a7f899364dbc96a95dffeaa250cd7ea33b4b6c313866169e779bc"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					12: testutil.DecodeHexString(c, "7135fd41c92f097075cc21eefd6797498544fd329b3bf996654885ebf83bb2de"),
				},
			},
		},
	})
}

func (s *snapModelProfileSuite) TestAddSnapModelProfile9(c *C) {
	// Test extending in to an initial profile.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		profile: NewPCRProtectionProfile().
			AddPCRValue(tpm2.HashAlgorithmSHA256, 7, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo")).
			AddPCRValue(tpm2.HashAlgorithmSHA256, 12, testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar")),
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []SnapModel{
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
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					12: testutil.DecodeHexString(c, "3089d679b1cda31c76fe57e6cf0c3eb35c221acde76a678c3c4771ee9b99a8c9"),
				},
			},
			{
				tpm2.HashAlgorithmSHA256: {
					7:  testutil.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"),
					12: testutil.DecodeHexString(c, "cb7a1cf1afbc73e0e4348f771cf7475e7ec278549af042e2617e717ca38d3416"),
				},
			},
		},
	})
}

func (s *snapModelProfileSuite) TestAddSnapModelProfile10(c *C) {
	// Test that there aren't contatenation issues with brand-id/model/series - ie, "fake-brand,fake-model,16" should
	// be different to "fake-bran,dfake-mode,l16".
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []SnapModel{
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-bran",
					"series":       "l16",
					"brand-id":     "fake-bran",
					"model":        "dfake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: testutil.DecodeHexString(c, "b6dfa17679ea768de6430c531da07e2f926320a1ec577c2edd97d4757dc6e45f"),
				},
			},
		},
	})
}

func (s *snapModelProfileSuite) TestAddSnapModelProfile11(c *C) {
	// Test with a different grade.
	s.testAddSnapModelProfile(c, &testAddSnapModelProfileData{
		params: &SnapModelProfileParams{
			PCRAlgorithm: tpm2.HashAlgorithmSHA256,
			PCRIndex:     12,
			Models: []SnapModel{
				s.makeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "dangerous",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
			},
		},
		values: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					12: testutil.DecodeHexString(c, "27db1fa15c2fd09361f6812bca72c3285e889dd20fcfbbe509e153b302046820"),
				},
			},
		},
	})
}

type snapModelMeasureSuite struct {
	testutil.TPMSimulatorTestBase
	snapModelTestBase
}

var _ = Suite(&snapModelMeasureSuite{})

func (s *snapModelMeasureSuite) SetUpTest(c *C) {
	s.TPMSimulatorTestBase.SetUpTest(c)
	s.ResetTPMSimulator(c)
}

type testMeasureSnapModelToTPMTestData struct {
	pcrIndex int
	model    SnapModel
}

func (s *snapModelMeasureSuite) testMeasureSnapModelToTPMTest(c *C, data *testMeasureSnapModelToTPMTestData) {
	pcrSelection, err := s.TPM.GetCapabilityPCRs()
	c.Assert(err, IsNil)

	var pcrs []int
	for i := 0; i < 24; i++ {
		pcrs = append(pcrs, i)
	}
	var readPcrSelection tpm2.PCRSelectionList
	for _, s := range pcrSelection {
		readPcrSelection = append(readPcrSelection, tpm2.PCRSelection{Hash: s.Hash, Select: pcrs})
	}

	_, origPcrValues, err := s.TPM.PCRRead(readPcrSelection)
	c.Assert(err, IsNil)

	c.Check(MeasureSnapModelToTPM(s.TPM, data.pcrIndex, data.model), IsNil)

	_, pcrValues, err := s.TPM.PCRRead(readPcrSelection)
	c.Assert(err, IsNil)

	for _, s := range pcrSelection {
		snapModelDigest, err := ComputeSnapModelDigest(s.Hash, data.model)
		c.Assert(err, IsNil)

		h := s.Hash.NewHash()
		h.Write(origPcrValues[s.Hash][data.pcrIndex])
		h.Write(snapModelDigest)

		c.Check(pcrValues[s.Hash][data.pcrIndex], DeepEquals, tpm2.Digest(h.Sum(nil)))

		for _, p := range pcrs {
			if p == data.pcrIndex {
				continue
			}
			c.Check(pcrValues[s.Hash][p], DeepEquals, origPcrValues[s.Hash][p])
		}
	}
}

func (s *snapModelMeasureSuite) TestMeasureSnapModelToTPMTest1(c *C) {
	s.testMeasureSnapModelToTPMTest(c, &testMeasureSnapModelToTPMTestData{
		pcrIndex: 12,
		model: s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
	})
}

func (s *snapModelMeasureSuite) TestMeasureSnapModelToTPMTest2(c *C) {
	// Test with a different signing key.
	s.testMeasureSnapModelToTPMTest(c, &testMeasureSnapModelToTPMTestData{
		pcrIndex: 12,
		model: s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "GQ2ARdxYdcEATk3THxMZTuolBDz5_8QFUMyjD9yuIPjX7tBfPJQFiyBjKdvo0jEu"),
	})
}

func (s *snapModelMeasureSuite) TestMeasureSnapModelToTPMTest3(c *C) {
	// Test with a different brand.
	s.testMeasureSnapModelToTPMTest(c, &testMeasureSnapModelToTPMTestData{
		pcrIndex: 12,
		model: s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "other-brand",
			"series":       "16",
			"brand-id":     "other-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
	})
}

func (s *snapModelMeasureSuite) TestMeasureSnapModelToTPMTest4(c *C) {
	// Test with a different model.
	s.testMeasureSnapModelToTPMTest(c, &testMeasureSnapModelToTPMTestData{
		pcrIndex: 12,
		model: s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
	})
}

func (s *snapModelMeasureSuite) TestMeasureSnapModelToTPMTest5(c *C) {
	s.testMeasureSnapModelToTPMTest(c, &testMeasureSnapModelToTPMTestData{
		pcrIndex: 12,
		model: s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "28",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
	})
}

func (s *snapModelMeasureSuite) TestMeasureSnapModelToTPMTest6(c *C) {
	// Test with a different PCR
	s.testMeasureSnapModelToTPMTest(c, &testMeasureSnapModelToTPMTestData{
		pcrIndex: 14,
		model: s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
	})
}

func (s *snapModelMeasureSuite) TestMeasureSnapModelToTPMTest7(c *C) {
	// Test with a different grade.
	s.testMeasureSnapModelToTPMTest(c, &testMeasureSnapModelToTPMTestData{
		pcrIndex: 12,
		model: s.makeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "dangerous",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
	})
}

func (s *snapModelMeasureSuite) testMeasureSnapSystemEpochToTPM(c *C, pcrIndex int) {
	pcrSelection, err := s.TPM.GetCapabilityPCRs()
	c.Assert(err, IsNil)

	var pcrs []int
	for i := 0; i < 24; i++ {
		pcrs = append(pcrs, i)
	}
	var readPcrSelection tpm2.PCRSelectionList
	for _, s := range pcrSelection {
		readPcrSelection = append(readPcrSelection, tpm2.PCRSelection{Hash: s.Hash, Select: pcrs})
	}

	_, origPcrValues, err := s.TPM.PCRRead(readPcrSelection)
	c.Assert(err, IsNil)

	c.Check(MeasureSnapSystemEpochToTPM(s.TPM, pcrIndex), IsNil)

	_, pcrValues, err := s.TPM.PCRRead(readPcrSelection)
	c.Assert(err, IsNil)

	for _, s := range pcrSelection {
		h := s.Hash.NewHash()
		binary.Write(h, binary.LittleEndian, uint32(0))
		digest := h.Sum(nil)

		h = s.Hash.NewHash()
		h.Write(origPcrValues[s.Hash][pcrIndex])
		h.Write(digest)

		c.Check(pcrValues[s.Hash][pcrIndex], DeepEquals, tpm2.Digest(h.Sum(nil)))

		for _, p := range pcrs {
			if p == pcrIndex {
				continue
			}
			c.Check(pcrValues[s.Hash][p], DeepEquals, origPcrValues[s.Hash][p])
		}
	}
}

func (s *snapModelMeasureSuite) TestMeasureSnapSystemEpochToTPM1(c *C) {
	s.testMeasureSnapSystemEpochToTPM(c, 12)
}

func (s *snapModelMeasureSuite) TestMeasureSnapSystemEpochToTPM2(c *C) {
	s.testMeasureSnapSystemEpochToTPM(c, 14)
}
