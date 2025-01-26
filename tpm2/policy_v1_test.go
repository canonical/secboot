// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2021 Canonical Ltd
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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"strconv"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/cryptutil"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/policyutil"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type policyV1SuiteNoTPM struct {
	policyOrTreeMixin
}

type policyV1Suite struct {
	tpm2test.TPMTest
}

func (s *policyV1Suite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy | tpm2test.TPMFeaturePCR | tpm2test.TPMFeatureNV
}

var _ = Suite(&policyV1Suite{})
var _ = Suite(&policyV1SuiteNoTPM{})

func (s *policyV1SuiteNoTPM) TestPCRPolicyCounterHandle(c *C) {
	var data KeyDataPolicy = &KeyDataPolicy_v1{
		StaticData: &StaticPolicyData_v1{
			PCRPolicyCounterHandle: 0x01800000}}
	c.Check(data.PCRPolicyCounterHandle(), Equals, tpm2.Handle(0x01800000))

	data = &KeyDataPolicy_v1{
		StaticData: &StaticPolicyData_v1{
			PCRPolicyCounterHandle: tpm2.HandleNull}}
	c.Check(data.PCRPolicyCounterHandle(), Equals, tpm2.HandleNull)
}

func (s *policyV1SuiteNoTPM) TestPCRPolicySequence(c *C) {
	var data KeyDataPolicy = &KeyDataPolicy_v1{
		PCRData: &PcrPolicyData_v1{
			PolicySequence: 10}}
	c.Check(data.PCRPolicySequence(), Equals, uint64(10))

	data = &KeyDataPolicy_v1{
		PCRData: &PcrPolicyData_v1{
			PolicySequence: 500}}
	c.Check(data.PCRPolicySequence(), Equals, uint64(500))
}

type testV1UpdatePCRPolicyData struct {
	policyCounterHandle tpm2.Handle
	authKeyNameAlg      tpm2.HashAlgorithmId
	initialSeq          uint64

	alg        tpm2.HashAlgorithmId
	pcrs       tpm2.PCRSelectionList
	pcrDigests tpm2.DigestList

	expectedPolicy tpm2.Digest
}

func (s *policyV1SuiteNoTPM) testUpdatePCRPolicy(c *C, data *testV1UpdatePCRPolicyData) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)

	var policyCounterPub *tpm2.NVPublic
	var policyCounterName tpm2.Name
	if data.policyCounterHandle != tpm2.HandleNull {
		policyCounterPub = &tpm2.NVPublic{
			Index:   data.policyCounterHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVPolicyRead | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
			Size:    8}
		policyCounterName = policyCounterPub.Name()
	}

	authPublicKey, err := objectutil.NewECCPublicKey(&key.PublicKey, objectutil.WithNameAlg(data.authKeyNameAlg))
	c.Assert(err, IsNil)

	var policyData KeyDataPolicy = &KeyDataPolicy_v1{
		StaticData: &StaticPolicyData_v1{
			AuthPublicKey: authPublicKey},
	}

	params := NewPcrPolicyParams(key.D.Bytes(), data.pcrs, data.pcrDigests, policyCounterPub, data.initialSeq)
	c.Check(policyData.UpdatePCRPolicy(data.alg, params), IsNil)

	c.Check(policyData.(*KeyDataPolicy_v1).PCRData.Selection, tpm2_testutil.TPMValueDeepEquals, data.pcrs)

	orTree, err := policyData.(*KeyDataPolicy_v1).PCRData.OrData.Resolve()
	c.Assert(err, IsNil)
	var digests tpm2.DigestList
	for _, digest := range data.pcrDigests {
		builder := policyutil.NewPolicyBuilder(data.alg)
		builder.RootBranch().PolicyPCRDigest(digest, data.pcrs)
		digest, err := builder.Digest()
		c.Assert(err, IsNil)
		digests = append(digests, digest)
	}
	s.checkPolicyOrTree(c, data.alg, digests, orTree)

	// Skip check for NoCounter case
	if data.policyCounterHandle != tpm2.HandleNull {
		c.Check(policyData.(*KeyDataPolicy_v1).PCRData.PolicySequence, Equals, data.initialSeq)
	}

	c.Logf("%x", policyData.(*KeyDataPolicy_v1).PCRData.AuthorizedPolicy)
	c.Check(policyData.(*KeyDataPolicy_v1).PCRData.AuthorizedPolicy, DeepEquals, data.expectedPolicy)

	c.Check(policyData.(*KeyDataPolicy_v1).PCRData.AuthorizedPolicySignature.SigAlg, Equals, tpm2.SigSchemeAlgECDSA)
	c.Check(policyData.(*KeyDataPolicy_v1).PCRData.AuthorizedPolicySignature.Signature.ECDSA.Hash, Equals, data.authKeyNameAlg)

	digest := policyutil.ComputePolicyAuthorizationTBSDigest(data.authKeyNameAlg.GetHash(),
		policyData.(*KeyDataPolicy_v1).PCRData.AuthorizedPolicy,
		ComputeV1PcrPolicyRefFromCounterName(policyCounterName))
	c.Check(err, IsNil)
	ok, err := cryptutil.VerifySignature(&key.PublicKey, digest, policyData.(*KeyDataPolicy_v1).PCRData.AuthorizedPolicySignature)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)
}

func (s *policyV1SuiteNoTPM) TestUpdatePCRPolicy(c *C) {
	s.testUpdatePCRPolicy(c, &testV1UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1001,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "70affe6f1ca3f4bee098b50fc474d8e247adcf5bc54b1bd6fe356104c2641a8b")})
}

func (s *policyV1SuiteNoTPM) TestUpdatePCRPolicyDepth1(c *C) {
	s.testUpdatePCRPolicy(c, &testV1UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1001,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests: tpm2.DigestList{
			hash(crypto.SHA256, "1"),
			hash(crypto.SHA256, "2"),
			hash(crypto.SHA256, "3"),
			hash(crypto.SHA256, "4"),
			hash(crypto.SHA256, "5")},
		expectedPolicy: testutil.DecodeHexString(c, "96eb06bc20faa6dbfa138b644a33470e92176db65b373577fe0e92f5518a5693")})
}

func (s *policyV1SuiteNoTPM) TestUpdatePCRPolicyDepth2(c *C) {
	data := &testV1UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1001,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		expectedPolicy:      testutil.DecodeHexString(c, "3dbd5e8007fe9a181b38f489da1577a71c2a049fd9d540f04bee5ed760621d36")}
	for i := 1; i < 26; i++ {
		data.pcrDigests = append(data.pcrDigests, hash(crypto.SHA256, strconv.Itoa(i)))
	}
	s.testUpdatePCRPolicy(c, data)
}

func (s *policyV1SuiteNoTPM) TestUpdatePCRPolicyDifferentCounter(c *C) {
	s.testUpdatePCRPolicy(c, &testV1UpdatePCRPolicyData{
		policyCounterHandle: 0x0180ffff,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1001,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "dd3b263babcfaa7316376889c917587b4586fea8096de29dc3360611a887e835")})
}

func (s *policyV1SuiteNoTPM) TestUpdatePCRPolicyNoCounter(c *C) {
	s.testUpdatePCRPolicy(c, &testV1UpdatePCRPolicyData{
		policyCounterHandle: tpm2.HandleNull,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1001,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "830c1432cbdc2f3dc2c1c83430df4fe0f5c2c6b1437b01071ddfd6f70fe33a90")})
}

func (s *policyV1SuiteNoTPM) TestUpdatePCRPolicySHA1AuthKey(c *C) {
	s.testUpdatePCRPolicy(c, &testV1UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA1,
		initialSeq:          1001,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "70affe6f1ca3f4bee098b50fc474d8e247adcf5bc54b1bd6fe356104c2641a8b")})
}

func (s *policyV1SuiteNoTPM) TestUpdatePCRPolicyDifferentSequence(c *C) {
	s.testUpdatePCRPolicy(c, &testV1UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          10000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "abc59e04a533674dc796b6bc51276a5fac18fed2177ab99a87e8a636c83bc8cc")})
}

func (s *policyV1SuiteNoTPM) TestUpdatePCRPolicySHA1Policy(c *C) {
	s.testUpdatePCRPolicy(c, &testV1UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1001,
		alg:                 tpm2.HashAlgorithmSHA1,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA1, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "10d3874da9f0605876695f76efa0bfbf1ea57f16")})
}

func (s *policyV1SuiteNoTPM) TestUpdatePCRPolicyDifferentPCRs(c *C) {
	s.testUpdatePCRPolicy(c, &testV1UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1001,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA1, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "a4569fcb0e2c2f1a6651c53e00c526c383c108edb3142339e6fad9d6ae5a488c")})
}

func (s *policyV1SuiteNoTPM) TestSetPCRPolicyFrom(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)

	policyCounterPub := &tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVPolicyRead | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
		Size:    8}

	authPublicKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	policyData1 := &KeyDataPolicy_v1{
		StaticData: &StaticPolicyData_v1{
			AuthPublicKey: authPublicKey},
	}

	params := NewPcrPolicyParams(key.D.Bytes(),
		tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		tpm2.DigestList{hash(crypto.SHA256, "1"), hash(crypto.SHA256, "2")},
		policyCounterPub, 5000)
	c.Check(policyData1.UpdatePCRPolicy(tpm2.HashAlgorithmSHA256, params), IsNil)

	authPublicKey, err = objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	var policyData2 KeyDataPolicy = &KeyDataPolicy_v1{
		StaticData: &StaticPolicyData_v1{
			AuthPublicKey: authPublicKey}}
	policyData2.SetPCRPolicyFrom(policyData1)

	c.Check(policyData2.(*KeyDataPolicy_v1).PCRData, DeepEquals, policyData1.PCRData)
}

type testV1ExecutePCRPolicyData struct {
	authKeyNameAlg      tpm2.HashAlgorithmId
	policyCounterHandle tpm2.Handle
	alg                 tpm2.HashAlgorithmId

	pcrs      tpm2.PCRSelectionList
	pcrValues []tpm2.PCRValues

	pcrEvents []pcrEvent
}

func (s *policyV1Suite) testExecutePCRPolicy(c *C, data *testV1ExecutePCRPolicyData) {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)
	authKeyPublic, err := objectutil.NewECCPublicKey(&authKey.PublicKey, objectutil.WithNameAlg(data.authKeyNameAlg))
	c.Assert(err, IsNil)

	var policyCounterPub *tpm2.NVPublic
	var policyCount uint64
	if data.policyCounterHandle != tpm2.HandleNull {
		policyCounterPub, policyCount, err = CreatePcrPolicyCounter(s.TPM().TPMContext, s.NextAvailableHandle(c, data.policyCounterHandle), authKeyPublic, s.TPM().HmacSession())
		c.Assert(err, IsNil)
	}

	policyData, expectedDigest, err := NewKeyDataPolicyLegacy(data.alg, authKeyPublic, policyCounterPub, policyCount)
	c.Assert(err, IsNil)
	c.Assert(policyData, testutil.ConvertibleTo, &KeyDataPolicy_v1{})

	var digests tpm2.DigestList
	for _, v := range data.pcrValues {
		d, _ := policyutil.ComputePCRDigest(data.alg, data.pcrs, v)
		digests = append(digests, d)
	}

	params := NewPcrPolicyParams(authKey.D.Bytes(), data.pcrs, digests, policyCounterPub, policyCount)
	c.Check(policyData.UpdatePCRPolicy(data.alg, params), IsNil)

	for _, selection := range data.pcrs {
		for _, pcr := range selection.Select {
			c.Check(s.TPM().PCRReset(s.TPM().PCRHandleContext(pcr), nil), IsNil)
		}
	}

	for _, e := range data.pcrEvents {
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(e.index), []byte(e.data), nil)
		c.Check(err, IsNil)
	}

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, data.alg)
	c.Check(policyData.ExecutePCRPolicy(s.TPM().TPMContext, session, s.TPM().HmacSession()), IsNil)

	digest, err := s.TPM().PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyV1Suite) TestExecutePCRPolicy(c *C) {
	s.testExecutePCRPolicy(c, &testV1ExecutePCRPolicyData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
	})
}

func (s *policyV1Suite) TestExecutePCRPolicyNoPCRs(c *C) {
	s.testExecutePCRPolicy(c, &testV1ExecutePCRPolicyData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrValues:           []tpm2.PCRValues{{}},
	})
}

func (s *policyV1Suite) TestExecutePCRPolicyMultipleDepth1(c *C) {
	var pcrValues []tpm2.PCRValues
	for i := 1; i < 6; i++ {
		pcrValues = append(pcrValues, tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"+strconv.Itoa(i), "bar"+strconv.Itoa(i)),
				23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"+strconv.Itoa(i), "foo"+strconv.Itoa(i)),
			},
		})
	}

	s.testExecutePCRPolicy(c, &testV1ExecutePCRPolicyData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues:           pcrValues,
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo2",
			},
			{
				index: 16,
				data:  "bar2",
			},
			{
				index: 23,
				data:  "bar2",
			},
			{
				index: 23,
				data:  "foo2",
			},
		},
	})
}

func (s *policyV1Suite) TestExecutePCRPolicyMultipleDepth2(c *C) {
	var pcrValues []tpm2.PCRValues
	for i := 1; i < 26; i++ {
		pcrValues = append(pcrValues, tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"+strconv.Itoa(i), "bar"+strconv.Itoa(i)),
				23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"+strconv.Itoa(i), "foo"+strconv.Itoa(i)),
			},
		})
	}

	s.testExecutePCRPolicy(c, &testV1ExecutePCRPolicyData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues:           pcrValues,
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo15",
			},
			{
				index: 16,
				data:  "bar15",
			},
			{
				index: 23,
				data:  "bar15",
			},
			{
				index: 23,
				data:  "foo15",
			},
		},
	})
}

func (s *policyV1Suite) TestExecutePCRPolicySHA1AuthKey(c *C) {
	s.testExecutePCRPolicy(c, &testV1ExecutePCRPolicyData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA1,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
	})
}

func (s *policyV1Suite) TestExecutePCRPolicyDifferentPolicyCounterHandle(c *C) {
	s.testExecutePCRPolicy(c, &testV1ExecutePCRPolicyData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x018ffff0,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
	})
}

func (s *policyV1Suite) TestExecutePCRPolicyNoPolicyCounterHandle(c *C) {
	s.testExecutePCRPolicy(c, &testV1ExecutePCRPolicyData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: tpm2.HandleNull,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
	})
}

func (s *policyV1Suite) TestExecutePCRPolicySHA1Policy(c *C) {
	s.testExecutePCRPolicy(c, &testV1ExecutePCRPolicyData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800ff0,
		alg:                 tpm2.HashAlgorithmSHA1,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
	})
}

func (s *policyV1Suite) TestExecutePCRPolicyDifferentPCRSelection(c *C) {
	s.testExecutePCRPolicy(c, &testV1ExecutePCRPolicyData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800ff0,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA1, Select: []int{23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA1: {
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA1, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
	})
}

type testV1ExecutePCRPolicyErrorHandlingData struct {
	authKeyNameAlg      tpm2.HashAlgorithmId
	policyCounterHandle tpm2.Handle
	alg                 tpm2.HashAlgorithmId

	pcrs      tpm2.PCRSelectionList
	pcrValues []tpm2.PCRValues

	pcrEvents []pcrEvent

	fn func(data *KeyDataPolicy_v1, authKey *ecdsa.PrivateKey)
}

func (s *policyV1Suite) testExecutePCRPolicyErrorHandling(c *C, data *testV1ExecutePCRPolicyErrorHandlingData) error {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)
	authKeyPublic, err := objectutil.NewECCPublicKey(&authKey.PublicKey, objectutil.WithNameAlg(data.authKeyNameAlg))
	c.Assert(err, IsNil)

	var policyCounterPub *tpm2.NVPublic
	var policyCount uint64
	if data.policyCounterHandle != tpm2.HandleNull {
		policyCounterPub, policyCount, err = CreatePcrPolicyCounter(s.TPM().TPMContext, s.NextAvailableHandle(c, data.policyCounterHandle), authKeyPublic, s.TPM().HmacSession())
		c.Assert(err, IsNil)
	}

	policyData, expectedDigest, err := NewKeyDataPolicyLegacy(data.alg, authKeyPublic, policyCounterPub, policyCount)
	c.Assert(err, IsNil)
	c.Assert(policyData, testutil.ConvertibleTo, &KeyDataPolicy_v1{})

	var digests tpm2.DigestList
	for _, v := range data.pcrValues {
		d, _ := policyutil.ComputePCRDigest(data.alg, data.pcrs, v)
		digests = append(digests, d)
	}

	params := NewPcrPolicyParams(authKey.D.Bytes(), data.pcrs, digests, policyCounterPub, policyCount)
	c.Check(policyData.UpdatePCRPolicy(data.alg, params), IsNil)

	for _, selection := range data.pcrs {
		for _, pcr := range selection.Select {
			c.Check(s.TPM().PCRReset(s.TPM().PCRHandleContext(pcr), nil), IsNil)
		}
	}

	for _, e := range data.pcrEvents {
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(e.index), []byte(e.data), nil)
		c.Check(err, IsNil)
	}

	data.fn(policyData.(*KeyDataPolicy_v1), authKey)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, data.alg)
	executeErr := policyData.ExecutePCRPolicy(s.TPM().TPMContext, session, s.TPM().HmacSession())

	digest, err := s.TPM().PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, Not(DeepEquals), expectedDigest)

	return executeErr
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidSelection1(c *C) {
	// Test with a PCR selection that doesn't match the original policy.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, _ *ecdsa.PrivateKey) {
			data.PCRData.Selection = tpm2.PCRSelectionList{}
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot execute PolicyOR assertions: current session digest not found in policy data")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidSelection2(c *C) {
	// Test with an invalid PCR selection.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, _ *ecdsa.PrivateKey) {
			data.PCRData.Selection = tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{50}}}
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: invalid PCR selection")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidOrTree1(c *C) {
	// Test with an invalid PCR policy or tree.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, _ *ecdsa.PrivateKey) {
			data.PCRData.OrData = PolicyOrData_v0{}
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot resolve PolicyOR tree: no nodes")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidOrTree2(c *C) {
	// Test with an invalid PCR policy or tree.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, _ *ecdsa.PrivateKey) {
			data.PCRData.OrData[0].Next = 10
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot resolve PolicyOR tree: index 10 out of range")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidOrTree3(c *C) {
	// Test with an invalid PCR policy or tree by changing a digest in a non
	// leaf node.
	var pcrValues []tpm2.PCRValues
	for i := 1; i < 26; i++ {
		pcrValues = append(pcrValues, tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"+strconv.Itoa(i), "bar"+strconv.Itoa(i)),
				23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"+strconv.Itoa(i), "foo"+strconv.Itoa(i)),
			},
		})
	}

	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues:           pcrValues,
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo1",
			},
			{
				index: 16,
				data:  "bar1",
			},
			{
				index: 23,
				data:  "bar1",
			},
			{
				index: 23,
				data:  "foo1",
			},
		},
		fn: func(data *KeyDataPolicy_v1, _ *ecdsa.PrivateKey) {
			copy(data.PCRData.OrData[4].Digests[0], make(tpm2.Digest, 32))
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot execute PolicyOR assertions: invalid data")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidOrTree4(c *C) {
	// Test by modifying the PCR policy or tree to contain unauthorized conditions.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo1",
			},
			{
				index: 16,
				data:  "bar1",
			},
			{
				index: 23,
				data:  "bar1",
			},
			{
				index: 23,
				data:  "foo1",
			},
		},
		fn: func(data *KeyDataPolicy_v1, key *ecdsa.PrivateKey) {
			digest, _ := policyutil.ComputePCRDigest(tpm2.HashAlgorithmSHA256, data.PCRData.Selection, tpm2.PCRValues{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1", "bar1"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1", "foo1"),
				},
			})

			builder := policyutil.NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
			builder.RootBranch().PolicyPCRDigest(digest, data.PCRData.Selection)
			digest, err := builder.Digest()
			c.Check(err, IsNil)

			orData, _, err := NewPolicyOrTree(tpm2.HashAlgorithmSHA256, tpm2.DigestList{digest})
			c.Assert(err, IsNil)

			data.PCRData.OrData = NewPolicyOrDataV0(orData)
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "the PCR policy is invalid")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidPolicySequence(c *C) {
	// Test by modifying the PCR policy sequence to a higher value.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, _ *ecdsa.PrivateKey) {
			data.PCRData.PolicySequence += 10
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "the PCR policy is invalid")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingPCRMismatch(c *C) {
	var pcrValues []tpm2.PCRValues
	for i := 1; i < 26; i++ {
		pcrValues = append(pcrValues, tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"+strconv.Itoa(i), "bar"+strconv.Itoa(i)),
				23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"+strconv.Itoa(i), "foo"+strconv.Itoa(i)),
			},
		})
	}

	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues:           pcrValues,
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, _ *ecdsa.PrivateKey) {},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot execute PolicyOR assertions: current session digest not found in policy data")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidPCRPolicyCounterHandle1(c *C) {
	// Test with an invalid PCR policy counter handle.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, _ *ecdsa.PrivateKey) {
			data.StaticData.PCRPolicyCounterHandle = 0x81000000
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "invalid handle 0x81000000 for PCR policy counter")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidPCRPolicyCounterHandle2(c *C) {
	// Test with a PCR policy counter handle pointing to an undefined index.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, _ *ecdsa.PrivateKey) {
			handle := tpm2.Handle(0x01800000)
			for s.TPM().DoesHandleExist(handle) {
				handle += 1
			}

			data.StaticData.PCRPolicyCounterHandle = handle
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "no PCR policy counter found")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidPCRPolicyCounterHandle3(c *C) {
	// Test with the PCR policy counter handle undefined when the policy was created
	// with one.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, _ *ecdsa.PrivateKey) {
			data.StaticData.PCRPolicyCounterHandle = tpm2.HandleNull
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot verify PCR policy signature: TPM returned an error for parameter 2 whilst executing command TPM_CC_VerifySignature: TPM_RC_SIGNATURE \\(the signature is not valid\\)")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingRevoked(c *C) {
	// Test with a revoked PCR policy.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, authKey *ecdsa.PrivateKey) {
			pub, _, err := s.TPM().NVReadPublic(tpm2.NewHandleContext(data.StaticData.PCRPolicyCounterHandle))
			c.Assert(err, IsNil)

			target := data.PCRData.PolicySequence

			context, err := data.PCRPolicyCounterContext(s.TPM().TPMContext, pub)
			c.Assert(err, IsNil)
			for {
				current, err := context.Get()
				c.Assert(err, IsNil)

				if current > target {
					break
				}

				c.Assert(context.Increment(authKey.D.Bytes()), IsNil)
			}
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "the PCR policy has been revoked")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidAuthPublicKey(c *C) {
	// Test with an auth public key that has an invalid name algorithm.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, _ *ecdsa.PrivateKey) {
			data.StaticData.AuthPublicKey.NameAlg = tpm2.HashAlgorithmId(tpm2.AlgorithmSM4)
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "public area of dynamic authorization policy signing key is invalid: TPM returned an error for parameter 2 whilst executing command TPM_CC_LoadExternal: "+
		"TPM_RC_HASH \\(hash algorithm not supported or not appropriate\\)")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidAuthorizedPolicySignature(c *C) {
	// Test with an invalid authorized policy signature
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, _ *ecdsa.PrivateKey) {
			copy(data.PCRData.AuthorizedPolicy, make(tpm2.Digest, 32))
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot verify PCR policy signature: TPM returned an error for parameter 2 whilst executing command TPM_CC_VerifySignature: TPM_RC_SIGNATURE \\(the signature is not valid\\)")
}

func (s *policyV1Suite) TestExecutePCRPolicyErrorHandlingInvalidAuthorizedPolicy(c *C) {
	// Test that authorizing a policy with another key and updating the public key
	// in the metadata produces the wrong session digest.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV1ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: tpm2.HandleNull,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}},
		pcrValues: []tpm2.PCRValues{
			{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
				},
			},
		},
		pcrEvents: []pcrEvent{
			{
				index: 16,
				data:  "foo",
			},
			{
				index: 16,
				data:  "bar",
			},
			{
				index: 23,
				data:  "bar",
			},
			{
				index: 23,
				data:  "foo",
			},
		},
		fn: func(data *KeyDataPolicy_v1, key *ecdsa.PrivateKey) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
			c.Assert(err, IsNil)

			authPublicKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
			c.Assert(err, IsNil)
			data.StaticData.AuthPublicKey = authPublicKey

			auth, err := policyutil.SignPolicyAuthorization(testutil.RandReader, data.PCRData.AuthorizedPolicy, authPublicKey, ComputeV1PcrPolicyRefFromCounterName(nil), key, tpm2.HashAlgorithmSHA256)
			c.Assert(err, IsNil)
			data.PCRData.AuthorizedPolicySignature = auth.Signature
		},
	})
	c.Check(err, IsNil)
}

func (s *policyV1Suite) TestPolicyCounterContextGet(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)
	authKeyPublic, err := objectutil.NewECCPublicKey(&authKey.PublicKey)
	c.Assert(err, IsNil)

	policyCounterPub, policyCount, err := CreatePcrPolicyCounter(s.TPM().TPMContext, s.NextAvailableHandle(c, 0x01800000), authKeyPublic, s.TPM().HmacSession())
	c.Assert(err, IsNil)

	data := &KeyDataPolicy_v1{
		StaticData: &StaticPolicyData_v1{
			AuthPublicKey:          authKeyPublic,
			PCRPolicyCounterHandle: policyCounterPub.Index}}

	context, err := data.PCRPolicyCounterContext(s.TPM().TPMContext, policyCounterPub)
	c.Assert(err, IsNil)

	count, err := context.Get()
	c.Check(err, IsNil)
	c.Check(count, Equals, policyCount)
}

func (s *policyV1Suite) TestPolicyCounterContextIncrement(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)
	authKeyPublic, err := objectutil.NewECCPublicKey(&authKey.PublicKey)
	c.Assert(err, IsNil)

	policyCounterPub, policyCount, err := CreatePcrPolicyCounter(s.TPM().TPMContext, s.NextAvailableHandle(c, 0x01800000), authKeyPublic, s.TPM().HmacSession())
	c.Assert(err, IsNil)

	data := &KeyDataPolicy_v1{
		StaticData: &StaticPolicyData_v1{
			AuthPublicKey:          authKeyPublic,
			PCRPolicyCounterHandle: policyCounterPub.Index}}

	context, err := data.PCRPolicyCounterContext(s.TPM().TPMContext, policyCounterPub)
	c.Assert(err, IsNil)

	c.Check(context.Increment(authKey.D.Bytes()), IsNil)

	count, err := context.Get()
	c.Check(err, IsNil)
	c.Check(count, Equals, policyCount+1)
}

func (s *policyV1SuiteNoTPM) TestValidateAuthKey(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)
	authKeyPublic, err := objectutil.NewECCPublicKey(&authKey.PublicKey)
	c.Assert(err, IsNil)

	data := &KeyDataPolicy_v1{
		StaticData: &StaticPolicyData_v1{
			AuthPublicKey: authKeyPublic}}
	c.Check(data.ValidateAuthKey(authKey.D.Bytes()), IsNil)
}

func (s *policyV1SuiteNoTPM) TestValidateAuthKeyWrongKey(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)
	authKeyPublic, err := objectutil.NewECCPublicKey(&authKey.PublicKey)
	c.Assert(err, IsNil)

	data := &KeyDataPolicy_v1{
		StaticData: &StaticPolicyData_v1{
			AuthPublicKey: authKeyPublic}}

	authKey, err = ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)
	err = data.ValidateAuthKey(authKey.D.Bytes())
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "dynamic authorization policy signing private key doesn't match public key")
}

func (s *policyV1SuiteNoTPM) TestRequireUserAuth(c *C) {
	data := &KeyDataPolicy_v1{}
	c.Check(data.RequireUserAuth(), testutil.IsTrue)
}
