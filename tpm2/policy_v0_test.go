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
	"crypto/rsa"
	"crypto/x509"
	"strconv"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/templates"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"

	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type policyV0Mixin struct {
	tpmTest       *tpm2_testutil.TPMTest
	lockIndexName tpm2.Name
}

func (m *policyV0Mixin) createMockLockIndex(c *C) {
	pub := tpm2.NVPublic{
		Index:   LockNVHandle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVReadStClear),
		Size:    0}

	index := m.tpmTest.NVDefineSpace(c, tpm2.HandleOwner, nil, &pub)
	c.Check(m.tpmTest.TPM.NVWrite(index, index, nil, 0, nil), IsNil)
	m.lockIndexName = index.Name()
}

func (m *policyV0Mixin) enablePolicyLock(c *C) {
	index, err := m.tpmTest.TPM.CreateResourceContextFromTPM(LockNVHandle)
	c.Assert(err, IsNil)
	c.Check(m.tpmTest.TPM.NVReadLock(index, index, nil), IsNil)
}

func (m *policyV0Mixin) createMockPcrPolicyCounter(c *C, handle tpm2.Handle, authKeyName tpm2.Name) (*tpm2.NVPublic, uint64, tpm2.DigestList) {
	c.Assert(m.tpmTest, NotNil) // policyV0Mixin.tpmTest must be set!

	pub := &tpm2.NVPublic{
		Index:   handle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVPolicyRead | tpm2.AttrNVNoDA),
		Size:    8}

	trial := util.ComputeAuthPolicy(pub.NameAlg)
	trial.PolicyNvWritten(false)

	policies := tpm2.DigestList{trial.GetDigest()}
	policies = append(policies, ComputeV0PinNVIndexPostInitAuthPolicies(pub.NameAlg, authKeyName)...)

	trial = util.ComputeAuthPolicy(pub.NameAlg)
	trial.PolicyOR(policies)
	pub.AuthPolicy = trial.GetDigest()

	index := m.tpmTest.NVDefineSpace(c, tpm2.HandleOwner, nil, pub)

	session := m.tpmTest.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	defer m.tpmTest.TPM.FlushContext(session)
	c.Check(m.tpmTest.TPM.PolicyNvWritten(session, false), IsNil)
	c.Check(m.tpmTest.TPM.PolicyOR(session, policies), IsNil)
	c.Check(m.tpmTest.TPM.NVIncrement(index, index, session), IsNil)

	pub.Attrs |= tpm2.AttrNVWritten

	c.Check(m.tpmTest.TPM.PolicyCommandCode(session, tpm2.CommandNVRead), IsNil)
	c.Check(m.tpmTest.TPM.PolicyOR(session, policies), IsNil)

	count, err := m.tpmTest.TPM.NVReadCounter(index, index, session)
	c.Check(err, IsNil)

	return pub, count, policies
}

func (m *policyV0Mixin) newMockKeyDataPolicy(c *C, alg tpm2.HashAlgorithmId, authKey *tpm2.Public, pcrPolicyCounter *tpm2.NVPublic,
	pcrPolicySequence uint64, pcrPolicyCounterAuthPolicies tpm2.DigestList) (KeyDataPolicy, tpm2.Digest) {

	trial := util.ComputeAuthPolicy(alg)
	trial.PolicyAuthorize(nil, authKey.Name())
	trial.PolicySecret(pcrPolicyCounter.Name(), nil)
	trial.PolicyNV(m.lockIndexName, nil, 0, tpm2.OpEq)

	return &KeyDataPolicy_v0{
		StaticData: &StaticPolicyData_v0{
			AuthPublicKey:                authKey,
			PCRPolicyCounterHandle:       pcrPolicyCounter.Index,
			PCRPolicyCounterAuthPolicies: pcrPolicyCounterAuthPolicies},
		PCRData: &PcrPolicyData_v0{
			PolicySequence: pcrPolicySequence}}, trial.GetDigest()
}

type policyV0SuiteNoTPM struct {
	policyOrTreeMixin
}

type policyV0Suite struct {
	tpm2test.TPMTest
	policyV0Mixin
}

func (s *policyV0Suite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy | tpm2test.TPMFeaturePCR | tpm2test.TPMFeatureNV
}

func (s *policyV0Suite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)
	s.policyV0Mixin.tpmTest = &s.TPMTest.TPMTest

	s.createMockLockIndex(c)
}

var _ = Suite(&policyV0Suite{})
var _ = Suite(&policyV0SuiteNoTPM{})

type testPolicyOrTreeSerializationData struct {
	alg      tpm2.HashAlgorithmId
	digests  tpm2.DigestList
	numNodes int

	depth    int
	expected tpm2.Digest
}

func (s *policyV0SuiteNoTPM) testPolicyOrTreeSerialization(c *C, data *testPolicyOrTreeSerializationData) {
	trial := util.ComputeAuthPolicy(data.alg)
	tree, err := NewPolicyOrTree(data.alg, trial, data.digests)
	c.Assert(err, IsNil)

	serialized := NewPolicyOrDataV0(tree)
	c.Check(serialized, HasLen, data.numNodes)

	tree2, err := serialized.Resolve()
	c.Assert(err, IsNil)

	policy, depth := s.checkPolicyOrTree(c, data.alg, data.digests, tree2)
	c.Check(policy, DeepEquals, data.expected)
	c.Check(depth, Equals, data.depth)
}

func (s *policyV0SuiteNoTPM) TestPolicyOrTreeSerializationSingleDigest(c *C) {
	s.testPolicyOrTreeSerialization(c, &testPolicyOrTreeSerializationData{
		alg:      tpm2.HashAlgorithmSHA256,
		digests:  tpm2.DigestList{hash(crypto.SHA256, "foo")},
		numNodes: 1,
		depth:    1,
		expected: testutil.DecodeHexString(c, "51d05afe8c2bbc42a2c1f540d7390b0228cd0d59d417a8e765c28af6f43f024c")})
}

func (s *policyV0SuiteNoTPM) TestPolicyOrTreeSerializationDepth1(c *C) {
	s.testPolicyOrTreeSerialization(c, &testPolicyOrTreeSerializationData{
		alg: tpm2.HashAlgorithmSHA256,
		digests: tpm2.DigestList{
			hash(crypto.SHA256, "1"),
			hash(crypto.SHA256, "2"),
			hash(crypto.SHA256, "3"),
			hash(crypto.SHA256, "4"),
			hash(crypto.SHA256, "5")},
		numNodes: 1,
		depth:    1,
		expected: testutil.DecodeHexString(c, "5e5a5c8790bd34336f2df51c216e072ca52bd9c0c2dc67e249d5952aa81aecfa")})
}

func (s *policyV0SuiteNoTPM) TestPolicyOrTreeSerializationDepth2(c *C) {
	var digests tpm2.DigestList
	for i := 1; i < 26; i++ {
		digests = append(digests, hash(crypto.SHA256, strconv.Itoa(i)))
	}
	s.testPolicyOrTreeSerialization(c, &testPolicyOrTreeSerializationData{
		alg:      tpm2.HashAlgorithmSHA256,
		digests:  digests,
		numNodes: 5,
		depth:    2,
		expected: testutil.DecodeHexString(c, "84be2df61f929c0afca3bcec125f7365fd825b410a150019e250b0dfb25110cf")})
}

func (s *policyV0SuiteNoTPM) TestPolicyOrTreeSerializationDepth3(c *C) {
	var digests tpm2.DigestList
	for i := 1; i < 201; i++ {
		digests = append(digests, hash(crypto.SHA256, strconv.Itoa(i)))
	}
	s.testPolicyOrTreeSerialization(c, &testPolicyOrTreeSerializationData{
		alg:      tpm2.HashAlgorithmSHA256,
		digests:  digests,
		numNodes: 30,
		depth:    3,
		expected: testutil.DecodeHexString(c, "9c1cb2f1722a0a06f5e6774a9628cabce76572b0f2201bf66002a9eb2dfd6f11")})
}

func (s *policyV0SuiteNoTPM) TestPolicyOrTreeSerializationDepth4(c *C) {
	var digests tpm2.DigestList
	for i := 1; i < 1601; i++ {
		digests = append(digests, hash(crypto.SHA256, strconv.Itoa(i)))
	}
	s.testPolicyOrTreeSerialization(c, &testPolicyOrTreeSerializationData{
		alg:      tpm2.HashAlgorithmSHA256,
		digests:  digests,
		numNodes: 230,
		depth:    4,
		expected: testutil.DecodeHexString(c, "6f2ccbe268c9b3324c0922fcc2ccd760f6a7d264b7f61dccd3fba21f98412f85")})
}

func (s *policyV0SuiteNoTPM) TestPolicyOrTreeResolveNoNodes(c *C) {
	_, err := PolicyOrData_v0{}.Resolve()
	c.Assert(err, ErrorMatches, "no nodes")
}

func (s *policyV0SuiteNoTPM) TestPolicyOrTreeResolveTooManyNodes(c *C) {
	_, err := PolicyOrData_v0{&PolicyOrDataNode_v0{Next: 5000}}.Resolve()
	c.Assert(err, ErrorMatches, "too many leaf nodes \\(5000\\)")
}

func (s *policyV0SuiteNoTPM) TestPolicyOrTreeResolveError(c *C) {
	var digests tpm2.DigestList
	for i := 1; i < 201; i++ {
		digests = append(digests, make(tpm2.Digest, crypto.SHA256.Size()))
	}

	trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	tree, err := NewPolicyOrTree(tpm2.HashAlgorithmSHA256, trial, digests)
	c.Assert(err, IsNil)

	serialized := NewPolicyOrDataV0(tree)
	serialized[10].Next = 200

	_, err = serialized.Resolve()
	c.Check(err, ErrorMatches, "index 210 out of range")
}

func (s *policyV0Suite) TestPolicyOrTreeExecuteAssertions(c *C) {
	var digests tpm2.DigestList
	for i := 1; i < 201; i++ {
		trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
		trial.PolicyPCR(hash(crypto.SHA256, strconv.Itoa(i)), tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})
		digests = append(digests, trial.GetDigest())
	}

	trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	tree, err := NewPolicyOrTree(tpm2.HashAlgorithmSHA256, trial, digests)
	c.Assert(err, IsNil)
	expectedDigest := trial.GetDigest()

	serialized := NewPolicyOrDataV0(tree)
	tree2, err := serialized.Resolve()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)

	for i := 1; i < 201; i++ {
		c.Assert(s.TPM().PolicyRestart(session), IsNil)
		c.Assert(s.TPM().PolicyPCR(session, hash(crypto.SHA256, strconv.Itoa(i)), tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}), IsNil)
		c.Assert(tree2.ExecuteAssertions(s.TPM().TPMContext, session), IsNil)

		digest, err := s.TPM().PolicyGetDigest(session)
		c.Assert(err, IsNil)
		c.Assert(digest, DeepEquals, expectedDigest)
	}
}

func (s *policyV0SuiteNoTPM) TestPCRPolicyCounterHandle(c *C) {
	var data KeyDataPolicy = &KeyDataPolicy_v0{
		StaticData: &StaticPolicyData_v0{
			PCRPolicyCounterHandle: 0x01800000}}
	c.Check(data.PCRPolicyCounterHandle(), Equals, tpm2.Handle(0x01800000))

	data = &KeyDataPolicy_v0{
		StaticData: &StaticPolicyData_v0{
			PCRPolicyCounterHandle: 0x018000ff}}
	c.Check(data.PCRPolicyCounterHandle(), Equals, tpm2.Handle(0x018000ff))
}

func (s *policyV0SuiteNoTPM) TestPCRPolicySequence(c *C) {
	var data KeyDataPolicy = &KeyDataPolicy_v0{
		PCRData: &PcrPolicyData_v0{
			PolicySequence: 10}}
	c.Check(data.PCRPolicySequence(), Equals, uint64(10))

	data = &KeyDataPolicy_v0{
		PCRData: &PcrPolicyData_v0{
			PolicySequence: 500}}
	c.Check(data.PCRPolicySequence(), Equals, uint64(500))
}

type testV0UpdatePCRPolicyData struct {
	policyCounterHandle tpm2.Handle
	authKeyNameAlg      tpm2.HashAlgorithmId
	initialSeq          uint64

	alg        tpm2.HashAlgorithmId
	pcrs       tpm2.PCRSelectionList
	pcrDigests tpm2.DigestList

	expectedPolicy tpm2.Digest
}

func (s *policyV0SuiteNoTPM) testUpdatePCRPolicy(c *C, data *testV0UpdatePCRPolicyData) {
	key, err := rsa.GenerateKey(testutil.RandReader, 2048)
	c.Assert(err, IsNil)

	policyCounterPub := &tpm2.NVPublic{
		Index:   data.policyCounterHandle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVPolicyRead | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
		Size:    8}

	var policyData KeyDataPolicy = &KeyDataPolicy_v0{
		StaticData: &StaticPolicyData_v0{
			AuthPublicKey: util.NewExternalRSAPublicKey(data.authKeyNameAlg, templates.KeyUsageSign, nil, &key.PublicKey)},
		PCRData: &PcrPolicyData_v0{
			PolicySequence: data.initialSeq}}

	params := NewPcrPolicyParams(x509.MarshalPKCS1PrivateKey(key), data.pcrs, data.pcrDigests, policyCounterPub.Name())
	c.Check(policyData.UpdatePCRPolicy(data.alg, params), IsNil)

	c.Check(policyData.(*KeyDataPolicy_v0).PCRData.Selection, tpm2_testutil.TPMValueDeepEquals, data.pcrs)

	orTree, err := policyData.(*KeyDataPolicy_v0).PCRData.OrData.Resolve()
	c.Assert(err, IsNil)
	var digests tpm2.DigestList
	for _, digest := range data.pcrDigests {
		trial := util.ComputeAuthPolicy(data.alg)
		trial.PolicyPCR(digest, data.pcrs)
		digests = append(digests, trial.GetDigest())
	}
	s.checkPolicyOrTree(c, data.alg, digests, orTree)

	c.Check(policyData.(*KeyDataPolicy_v0).PCRData.PolicySequence, Equals, data.initialSeq+1)

	c.Check(policyData.(*KeyDataPolicy_v0).PCRData.AuthorizedPolicy, DeepEquals, data.expectedPolicy)

	c.Check(policyData.(*KeyDataPolicy_v0).PCRData.AuthorizedPolicySignature.SigAlg, Equals, tpm2.SigSchemeAlgRSAPSS)
	c.Check(policyData.(*KeyDataPolicy_v0).PCRData.AuthorizedPolicySignature.Signature.RSAPSS.Hash, Equals, data.authKeyNameAlg)

	digest, err := util.ComputePolicyAuthorizeDigest(data.authKeyNameAlg, policyData.(*KeyDataPolicy_v0).PCRData.AuthorizedPolicy, nil)
	c.Check(err, IsNil)
	ok, err := util.VerifySignature(&key.PublicKey, digest, policyData.(*KeyDataPolicy_v0).PCRData.AuthorizedPolicySignature)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)
}

func (s *policyV0SuiteNoTPM) TestUpdatePCRPolicy(c *C) {
	s.testUpdatePCRPolicy(c, &testV0UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "70affe6f1ca3f4bee098b50fc474d8e247adcf5bc54b1bd6fe356104c2641a8b")})
}

func (s *policyV0SuiteNoTPM) TestUpdatePCRPolicyDepth1(c *C) {
	s.testUpdatePCRPolicy(c, &testV0UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1000,
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

func (s *policyV0SuiteNoTPM) TestUpdatePCRPolicyDepth2(c *C) {
	data := &testV0UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		expectedPolicy:      testutil.DecodeHexString(c, "3dbd5e8007fe9a181b38f489da1577a71c2a049fd9d540f04bee5ed760621d36")}
	for i := 1; i < 26; i++ {
		data.pcrDigests = append(data.pcrDigests, hash(crypto.SHA256, strconv.Itoa(i)))
	}
	s.testUpdatePCRPolicy(c, data)
}

func (s *policyV0SuiteNoTPM) TestUpdatePCRPolicyDifferentCounter(c *C) {
	s.testUpdatePCRPolicy(c, &testV0UpdatePCRPolicyData{
		policyCounterHandle: 0x0180ffff,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "dd3b263babcfaa7316376889c917587b4586fea8096de29dc3360611a887e835")})
}

func (s *policyV0SuiteNoTPM) TestUpdatePCRPolicySHA1AuthKey(c *C) {
	s.testUpdatePCRPolicy(c, &testV0UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA1,
		initialSeq:          1000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "70affe6f1ca3f4bee098b50fc474d8e247adcf5bc54b1bd6fe356104c2641a8b")})
}

func (s *policyV0SuiteNoTPM) TestUpdatePCRPolicyDifferentSequence(c *C) {
	s.testUpdatePCRPolicy(c, &testV0UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          9999,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "abc59e04a533674dc796b6bc51276a5fac18fed2177ab99a87e8a636c83bc8cc")})
}

func (s *policyV0SuiteNoTPM) TestUpdatePCRPolicySHA1Policy(c *C) {
	s.testUpdatePCRPolicy(c, &testV0UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1000,
		alg:                 tpm2.HashAlgorithmSHA1,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA1, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "10d3874da9f0605876695f76efa0bfbf1ea57f16")})
}

func (s *policyV0SuiteNoTPM) TestUpdatePCRPolicyDifferentPCRs(c *C) {
	s.testUpdatePCRPolicy(c, &testV0UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialSeq:          1000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA1, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "a4569fcb0e2c2f1a6651c53e00c526c383c108edb3142339e6fad9d6ae5a488c")})
}

func (s *policyV0SuiteNoTPM) TestSetPCRPolicyFrom(c *C) {
	key, err := rsa.GenerateKey(testutil.RandReader, 2048)
	c.Assert(err, IsNil)

	policyCounterPub := &tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVPolicyRead | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
		Size:    8}

	policyData1 := &KeyDataPolicy_v0{
		StaticData: &StaticPolicyData_v0{
			AuthPublicKey: util.NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey)},
		PCRData: &PcrPolicyData_v0{
			PolicySequence: 5000}}

	params := NewPcrPolicyParams(x509.MarshalPKCS1PrivateKey(key),
		tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		tpm2.DigestList{hash(crypto.SHA256, "1"), hash(crypto.SHA256, "2")},
		policyCounterPub.Name())
	c.Check(policyData1.UpdatePCRPolicy(tpm2.HashAlgorithmSHA256, params), IsNil)

	var policyData2 KeyDataPolicy = &KeyDataPolicy_v0{
		StaticData: &StaticPolicyData_v0{
			AuthPublicKey: util.NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey)}}
	policyData2.SetPCRPolicyFrom(policyData1)

	c.Check(policyData2.(*KeyDataPolicy_v0).PCRData, DeepEquals, policyData1.PCRData)
}

type pcrEvent struct {
	index int
	data  string
}

type testV0ExecutePCRPolicyData struct {
	authKeyNameAlg      tpm2.HashAlgorithmId
	policyCounterHandle tpm2.Handle
	alg                 tpm2.HashAlgorithmId

	pcrs      tpm2.PCRSelectionList
	pcrValues []tpm2.PCRValues

	pcrEvents []pcrEvent
}

func (s *policyV0Suite) testExecutePCRPolicy(c *C, data *testV0ExecutePCRPolicyData) {
	authKey, err := rsa.GenerateKey(testutil.RandReader, 2048)
	c.Assert(err, IsNil)
	authKeyPublic := util.NewExternalRSAPublicKey(data.authKeyNameAlg, templates.KeyUsageSign, nil, &authKey.PublicKey)

	policyCounterPub, policyCount, policyCounterPolicies := s.createMockPcrPolicyCounter(c, s.NextAvailableHandle(c, data.policyCounterHandle), authKeyPublic.Name())

	policyData, expectedDigest := s.newMockKeyDataPolicy(c, data.alg, authKeyPublic, policyCounterPub, policyCount, policyCounterPolicies)

	var digests tpm2.DigestList
	for _, v := range data.pcrValues {
		d, _ := util.ComputePCRDigest(data.alg, data.pcrs, v)
		digests = append(digests, d)
	}

	params := NewPcrPolicyParams(x509.MarshalPKCS1PrivateKey(authKey), data.pcrs, digests, policyCounterPub.Name())
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

func (s *policyV0Suite) TestExecutePCRPolicy(c *C) {
	s.testExecutePCRPolicy(c, &testV0ExecutePCRPolicyData{
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

func (s *policyV0Suite) TestExecutePCRPolicyNoPCRs(c *C) {
	s.testExecutePCRPolicy(c, &testV0ExecutePCRPolicyData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrValues:           []tpm2.PCRValues{{}},
	})
}

func (s *policyV0Suite) TestExecutePCRPolicyMultipleDepth1(c *C) {
	var pcrValues []tpm2.PCRValues
	for i := 1; i < 6; i++ {
		pcrValues = append(pcrValues, tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"+strconv.Itoa(i), "bar"+strconv.Itoa(i)),
				23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"+strconv.Itoa(i), "foo"+strconv.Itoa(i)),
			},
		})
	}

	s.testExecutePCRPolicy(c, &testV0ExecutePCRPolicyData{
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

func (s *policyV0Suite) TestExecutePCRPolicyMultipleDepth2(c *C) {
	var pcrValues []tpm2.PCRValues
	for i := 1; i < 26; i++ {
		pcrValues = append(pcrValues, tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"+strconv.Itoa(i), "bar"+strconv.Itoa(i)),
				23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"+strconv.Itoa(i), "foo"+strconv.Itoa(i)),
			},
		})
	}

	s.testExecutePCRPolicy(c, &testV0ExecutePCRPolicyData{
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

func (s *policyV0Suite) TestExecutePCRPolicySHA1AuthKey(c *C) {
	s.testExecutePCRPolicy(c, &testV0ExecutePCRPolicyData{
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

func (s *policyV0Suite) TestExecutePCRPolicyDifferentPolicyCounterHandle(c *C) {
	s.testExecutePCRPolicy(c, &testV0ExecutePCRPolicyData{
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

func (s *policyV0Suite) TestExecutePCRPolicySHA1Policy(c *C) {
	s.testExecutePCRPolicy(c, &testV0ExecutePCRPolicyData{
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

func (s *policyV0Suite) TestExecutePCRPolicyDifferentPCRSelection(c *C) {
	s.testExecutePCRPolicy(c, &testV0ExecutePCRPolicyData{
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

type testV0ExecutePCRPolicyErrorHandlingData struct {
	authKeyNameAlg      tpm2.HashAlgorithmId
	policyCounterHandle tpm2.Handle
	alg                 tpm2.HashAlgorithmId

	pcrs      tpm2.PCRSelectionList
	pcrValues []tpm2.PCRValues

	pcrEvents []pcrEvent

	fn func(data *KeyDataPolicy_v0, authKey *rsa.PrivateKey)
}

func (s *policyV0Suite) testExecutePCRPolicyErrorHandling(c *C, data *testV0ExecutePCRPolicyErrorHandlingData) error {
	authKey, err := rsa.GenerateKey(testutil.RandReader, 2048)
	c.Assert(err, IsNil)
	authKeyPublic := util.NewExternalRSAPublicKey(data.authKeyNameAlg, templates.KeyUsageSign, nil, &authKey.PublicKey)

	policyCounterPub, policyCount, policyCounterPolicies := s.createMockPcrPolicyCounter(c, s.NextAvailableHandle(c, data.policyCounterHandle), authKeyPublic.Name())

	policyData, expectedDigest := s.newMockKeyDataPolicy(c, data.alg, authKeyPublic, policyCounterPub, policyCount, policyCounterPolicies)

	var digests tpm2.DigestList
	for _, v := range data.pcrValues {
		d, _ := util.ComputePCRDigest(data.alg, data.pcrs, v)
		digests = append(digests, d)
	}

	params := NewPcrPolicyParams(x509.MarshalPKCS1PrivateKey(authKey), data.pcrs, digests, policyCounterPub.Name())
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

	data.fn(policyData.(*KeyDataPolicy_v0), authKey)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, data.alg)
	executeErr := policyData.ExecutePCRPolicy(s.TPM().TPMContext, session, s.TPM().HmacSession())

	digest, err := s.TPM().PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, Not(DeepEquals), expectedDigest)

	return executeErr
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidSelection1(c *C) {
	// Test with a PCR selection that doesn't match the original policy.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, _ *rsa.PrivateKey) {
			data.PCRData.Selection = tpm2.PCRSelectionList{}
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot execute PolicyOR assertions: current session digest not found in policy data")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidSelection2(c *C) {
	// Test with an invalid PCR selection.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, _ *rsa.PrivateKey) {
			data.PCRData.Selection = tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{50}}}
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: invalid PCR selection")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidOrTree1(c *C) {
	// Test with an invalid PCR policy or tree.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, _ *rsa.PrivateKey) {
			data.PCRData.OrData = PolicyOrData_v0{}
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot resolve PolicyOR tree: no nodes")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidOrTree2(c *C) {
	// Test with an invalid PCR policy or tree.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, _ *rsa.PrivateKey) {
			data.PCRData.OrData[0].Next = 10
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot resolve PolicyOR tree: index 10 out of range")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidOrTree3(c *C) {
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

	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, _ *rsa.PrivateKey) {
			copy(data.PCRData.OrData[4].Digests[0], make(tpm2.Digest, 32))
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot execute PolicyOR assertions: invalid data")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidOrTree4(c *C) {
	// Test by modifying the PCR policy or tree to contain unauthorized conditions.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, key *rsa.PrivateKey) {
			digest, _ := util.ComputePCRDigest(tpm2.HashAlgorithmSHA256, data.PCRData.Selection, tpm2.PCRValues{
				tpm2.HashAlgorithmSHA256: {
					16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo1", "bar1"),
					23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar1", "foo1"),
				},
			})
			trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
			trial.PolicyPCR(digest, data.PCRData.Selection)
			digest = trial.GetDigest()

			trial = util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
			orData, err := NewPolicyOrTree(tpm2.HashAlgorithmSHA256, trial, tpm2.DigestList{digest})
			c.Assert(err, IsNil)

			data.PCRData.OrData = NewPolicyOrDataV0(orData)
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "the PCR policy is invalid")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidPolicySequence(c *C) {
	// Test by modifying the PCR policy sequence to a higher value.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, _ *rsa.PrivateKey) {
			data.PCRData.PolicySequence += 10
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "the PCR policy is invalid")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingPCRMismatch(c *C) {
	var pcrValues []tpm2.PCRValues
	for i := 1; i < 26; i++ {
		pcrValues = append(pcrValues, tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"+strconv.Itoa(i), "bar"+strconv.Itoa(i)),
				23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"+strconv.Itoa(i), "foo"+strconv.Itoa(i)),
			},
		})
	}

	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, _ *rsa.PrivateKey) {},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot execute PolicyOR assertions: current session digest not found in policy data")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidPCRPolicyCounterHandle1(c *C) {
	// Test with an invalid PCR policy counter handle.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, _ *rsa.PrivateKey) {
			data.StaticData.PCRPolicyCounterHandle = 0x81000000
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "invalid handle 0x81000000 for PCR policy counter")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidPCRPolicyCounterHandle2(c *C) {
	// Test with a PCR policy counter handle pointing to an undefined index.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, _ *rsa.PrivateKey) {
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

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidPCRPolicyCounterPolicies(c *C) {
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, _ *rsa.PrivateKey) {
			copy(data.StaticData.PCRPolicyCounterAuthPolicies[0], make(tpm2.Digest, 32))
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "invalid PCR policy counter or associated authorization policy metadata")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingRevoked(c *C) {
	// Test with a revoked PCR policy.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, authKey *rsa.PrivateKey) {
			key := x509.MarshalPKCS1PrivateKey(authKey)

			pub, _, err := s.TPM().NVReadPublic(tpm2.CreatePartialHandleContext(data.StaticData.PCRPolicyCounterHandle))
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

				c.Assert(context.Increment(key), IsNil)
			}
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "the PCR policy has been revoked")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidAuthPublicKey(c *C) {
	// Test with an auth public key that has an invalid name algorithm.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, _ *rsa.PrivateKey) {
			data.StaticData.AuthPublicKey.NameAlg = tpm2.HashAlgorithmId(tpm2.AlgorithmSM4)
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "public area of dynamic authorization policy signing key is invalid: TPM returned an error for parameter 2 whilst executing command TPM_CC_LoadExternal: "+
		"TPM_RC_HASH \\(hash algorithm not supported or not appropriate\\)")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidAuthorizedPolicySignature(c *C) {
	// Test with an invalid authorized policy signature
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, _ *rsa.PrivateKey) {
			copy(data.PCRData.AuthorizedPolicy, make(tpm2.Digest, 32))
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot verify PCR policy signature: TPM returned an error for parameter 2 whilst executing command TPM_CC_VerifySignature: TPM_RC_SIGNATURE \\(the signature is not valid\\)")
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingInvalidAuthorizedPolicy(c *C) {
	// Test that authorizing a policy with another key and updating the public key
	// in the metadata produces the wrong session digest.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v0, key *rsa.PrivateKey) {
			key, err := rsa.GenerateKey(testutil.RandReader, 2048)
			c.Assert(err, IsNil)

			data.StaticData.AuthPublicKey = util.NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey)

			scheme := &tpm2.SigScheme{
				Scheme: tpm2.SigSchemeAlgRSAPSS,
				Details: &tpm2.SigSchemeU{
					RSAPSS: &tpm2.SigSchemeRSAPSS{
						HashAlg: data.StaticData.AuthPublicKey.NameAlg}}}
			_, signature, err := util.PolicyAuthorize(key, scheme, data.PCRData.AuthorizedPolicy, nil)
			c.Assert(err, IsNil)
			data.PCRData.AuthorizedPolicySignature = signature
		},
	})
	c.Check(err, IsNil)
}

func (s *policyV0Suite) TestExecutePCRPolicyErrorHandlingNoLockIndex(c *C) {
	err := s.testExecutePCRPolicyErrorHandling(c, &testV0ExecutePCRPolicyErrorHandlingData{
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
		fn: func(_ *KeyDataPolicy_v0, _ *rsa.PrivateKey) {
			index, err := s.TPM().CreateResourceContextFromTPM(LockNVHandle)
			c.Assert(err, IsNil)
			c.Check(s.TPM().NVUndefineSpace(s.TPM().OwnerHandleContext(), index, nil), IsNil)
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "no lock NV index found")
}

func (s *policyV0Suite) TestPolicyCounterContextGet(c *C) {
	authKey, err := rsa.GenerateKey(testutil.RandReader, 2048)
	c.Assert(err, IsNil)
	authKeyPublic := util.NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &authKey.PublicKey)

	policyCounterPub, policyCount, policyCounterPolicies := s.createMockPcrPolicyCounter(c, s.NextAvailableHandle(c, 0x01800000), authKeyPublic.Name())

	data := &KeyDataPolicy_v0{
		StaticData: &StaticPolicyData_v0{
			AuthPublicKey:                authKeyPublic,
			PCRPolicyCounterHandle:       policyCounterPub.Index,
			PCRPolicyCounterAuthPolicies: policyCounterPolicies}}

	context, err := data.PCRPolicyCounterContext(s.TPM().TPMContext, policyCounterPub)
	c.Assert(err, IsNil)

	count, err := context.Get()
	c.Check(err, IsNil)
	c.Check(count, Equals, policyCount)
}

func (s *policyV0Suite) TestPolicyCounterContextIncrement(c *C) {
	authKey, err := rsa.GenerateKey(testutil.RandReader, 2048)
	c.Assert(err, IsNil)
	authKeyPublic := util.NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &authKey.PublicKey)

	policyCounterPub, policyCount, policyCounterPolicies := s.createMockPcrPolicyCounter(c, s.NextAvailableHandle(c, 0x01800000), authKeyPublic.Name())

	data := &KeyDataPolicy_v0{
		StaticData: &StaticPolicyData_v0{
			AuthPublicKey:                authKeyPublic,
			PCRPolicyCounterHandle:       policyCounterPub.Index,
			PCRPolicyCounterAuthPolicies: policyCounterPolicies}}

	context, err := data.PCRPolicyCounterContext(s.TPM().TPMContext, policyCounterPub)
	c.Assert(err, IsNil)

	c.Check(context.Increment(x509.MarshalPKCS1PrivateKey(authKey)), IsNil)

	count, err := context.Get()
	c.Check(err, IsNil)
	c.Check(count, Equals, policyCount+1)
}

func (s *policyV0SuiteNoTPM) TestValidateAuthKey(c *C) {
	authKey, err := rsa.GenerateKey(testutil.RandReader, 2048)
	c.Assert(err, IsNil)
	authKeyPublic := util.NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &authKey.PublicKey)

	data := &KeyDataPolicy_v0{
		StaticData: &StaticPolicyData_v0{
			AuthPublicKey: authKeyPublic}}
	c.Check(data.ValidateAuthKey(x509.MarshalPKCS1PrivateKey(authKey)), IsNil)
}

func (s *policyV0SuiteNoTPM) TestValidateAuthKeyWrongKey(c *C) {
	authKey, err := rsa.GenerateKey(testutil.RandReader, 2048)
	c.Assert(err, IsNil)
	authKeyPublic := util.NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &authKey.PublicKey)

	data := &KeyDataPolicy_v0{
		StaticData: &StaticPolicyData_v0{
			AuthPublicKey: authKeyPublic}}

	authKey, err = rsa.GenerateKey(testutil.RandReader, 2048)
	c.Assert(err, IsNil)
	err = data.ValidateAuthKey(x509.MarshalPKCS1PrivateKey(authKey))
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "dynamic authorization policy signing private key doesn't match public key")
}
