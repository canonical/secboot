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
	"crypto/x509"
	"encoding/pem"
	"io"
	"strconv"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/templates"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type policyOrTreeMixin struct{}

func (_ policyOrTreeMixin) checkPolicyOrTree(c *C, alg tpm2.HashAlgorithmId, digests tpm2.DigestList, tree *PolicyOrTree) (policy tpm2.Digest, depth int) {
	// Try a manual walk of the tree for every input digest
	for i, digest := range digests {
		trial := util.ComputeAuthPolicy(alg)

		var node *PolicyOrNode
		for _, n := range tree.LeafNodes() {
			if n.Contains(digest) {
				node = n
				break
			}
		}

		c.Assert(node, NotNil)

		d := 0
		for node != nil {
			d += 1

			digests := node.Digests()
			if len(digests) == 1 {
				digests = tpm2.DigestList{digests[0], digests[0]}
			}
			trial.PolicyOR(digests)
			node = node.Parent()
		}

		if i == 0 {
			policy = trial.GetDigest()
			depth = d
		} else {
			c.Assert(trial.GetDigest(), DeepEquals, policy)
			c.Assert(d, Equals, depth)
		}
	}

	return policy, depth
}

type policySuiteNoTPM struct {
	policyOrTreeMixin
}

type policySuite struct {
	tpm2test.TPMTest
}

func (s *policySuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy | tpm2test.TPMFeaturePCR | tpm2test.TPMFeatureNV
}

var _ = Suite(&policySuiteNoTPM{})
var _ = Suite(&policySuite{})

func hash(alg crypto.Hash, data string) []byte {
	h := alg.New()
	io.WriteString(h, data)
	return h.Sum(nil)
}

type testNewPolicyOrTreeData struct {
	alg     tpm2.HashAlgorithmId
	digests tpm2.DigestList

	depth    int
	expected tpm2.Digest
}

func (s *policySuiteNoTPM) testNewPolicyOrTree(c *C, data *testNewPolicyOrTreeData) {
	trial := util.ComputeAuthPolicy(data.alg)

	tree, err := NewPolicyOrTree(data.alg, trial, data.digests)
	c.Assert(err, IsNil)

	c.Assert(trial.GetDigest(), DeepEquals, data.expected)

	policy, depth := s.checkPolicyOrTree(c, data.alg, data.digests, tree)
	c.Check(policy, DeepEquals, data.expected)
	c.Check(depth, Equals, data.depth)
}

func (s *policySuiteNoTPM) TestNewPolicyOrTreeSingleDigest(c *C) {
	s.testNewPolicyOrTree(c, &testNewPolicyOrTreeData{
		alg:      tpm2.HashAlgorithmSHA256,
		digests:  tpm2.DigestList{hash(crypto.SHA256, "foo")},
		depth:    1,
		expected: testutil.DecodeHexString(c, "51d05afe8c2bbc42a2c1f540d7390b0228cd0d59d417a8e765c28af6f43f024c")})
}

func (s *policySuiteNoTPM) TestNewPolicyOrTreeDepth1(c *C) {
	s.testNewPolicyOrTree(c, &testNewPolicyOrTreeData{
		alg: tpm2.HashAlgorithmSHA256,
		digests: tpm2.DigestList{
			hash(crypto.SHA256, "1"),
			hash(crypto.SHA256, "2"),
			hash(crypto.SHA256, "3"),
			hash(crypto.SHA256, "4"),
			hash(crypto.SHA256, "5")},
		depth:    1,
		expected: testutil.DecodeHexString(c, "5e5a5c8790bd34336f2df51c216e072ca52bd9c0c2dc67e249d5952aa81aecfa")})
}

func (s *policySuiteNoTPM) TestNewPolicyOrTreeDepth2(c *C) {
	var digests tpm2.DigestList
	for i := 1; i < 26; i++ {
		digests = append(digests, hash(crypto.SHA256, strconv.Itoa(i)))
	}
	s.testNewPolicyOrTree(c, &testNewPolicyOrTreeData{
		alg:      tpm2.HashAlgorithmSHA256,
		digests:  digests,
		depth:    2,
		expected: testutil.DecodeHexString(c, "84be2df61f929c0afca3bcec125f7365fd825b410a150019e250b0dfb25110cf")})
}

func (s *policySuiteNoTPM) TestNewPolicyOrTreeSHA1(c *C) {
	var digests tpm2.DigestList
	for i := 1; i < 26; i++ {
		digests = append(digests, hash(crypto.SHA1, strconv.Itoa(i)))
	}
	s.testNewPolicyOrTree(c, &testNewPolicyOrTreeData{
		alg:      tpm2.HashAlgorithmSHA1,
		digests:  digests,
		depth:    2,
		expected: testutil.DecodeHexString(c, "dddd1fd38995710c4aa703599b9741e729ac9ceb")})
}

func (s *policySuiteNoTPM) TestNewPolicyOrTreeDepth3(c *C) {
	var digests tpm2.DigestList
	for i := 1; i < 201; i++ {
		digests = append(digests, hash(crypto.SHA256, strconv.Itoa(i)))
	}
	s.testNewPolicyOrTree(c, &testNewPolicyOrTreeData{
		alg:      tpm2.HashAlgorithmSHA256,
		digests:  digests,
		depth:    3,
		expected: testutil.DecodeHexString(c, "9c1cb2f1722a0a06f5e6774a9628cabce76572b0f2201bf66002a9eb2dfd6f11")})
}

func (s *policySuiteNoTPM) TestNewPolicyOrTreeDepth4(c *C) {
	var digests tpm2.DigestList
	for i := 1; i < 1601; i++ {
		digests = append(digests, hash(crypto.SHA256, strconv.Itoa(i)))
	}
	s.testNewPolicyOrTree(c, &testNewPolicyOrTreeData{
		alg:      tpm2.HashAlgorithmSHA256,
		digests:  digests,
		depth:    4,
		expected: testutil.DecodeHexString(c, "6f2ccbe268c9b3324c0922fcc2ccd760f6a7d264b7f61dccd3fba21f98412f85")})
}

func (s *policySuiteNoTPM) TestNewPolicyOrTreeNoDigests(c *C) {
	_, err := NewPolicyOrTree(tpm2.HashAlgorithmSHA256, util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256), nil)
	c.Check(err, ErrorMatches, "no digests supplied")
}

func (s *policySuiteNoTPM) TestNewPolicyOrTreeTooManyDigests(c *C) {
	_, err := NewPolicyOrTree(tpm2.HashAlgorithmSHA256, util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256), make(tpm2.DigestList, 5000))
	c.Check(err, ErrorMatches, "too many digests")
}

func (s *policySuite) TestPolicyOrTreeExecuteAssertions(c *C) {
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

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)

	for i := 1; i < 201; i++ {
		c.Assert(s.TPM().PolicyRestart(session), IsNil)
		c.Assert(s.TPM().PolicyPCR(session, hash(crypto.SHA256, strconv.Itoa(i)), tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}), IsNil)
		c.Assert(tree.ExecuteAssertions(s.TPM().TPMContext, session), IsNil)

		digest, err := s.TPM().PolicyGetDigest(session)
		c.Assert(err, IsNil)
		c.Assert(digest, DeepEquals, expectedDigest)
	}
}

func (s *policySuite) TestPolicyOrTreeExecuteAssertionsDigestNotFound(c *C) {
	var digests tpm2.DigestList
	for i := 1; i < 201; i++ {
		trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
		trial.PolicyPCR(hash(crypto.SHA256, strconv.Itoa(i)), tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})
		digests = append(digests, trial.GetDigest())
	}

	trial := util.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	tree, err := NewPolicyOrTree(tpm2.HashAlgorithmSHA256, trial, digests)
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	c.Check(s.TPM().PolicyPCR(session, hash(crypto.SHA256, "500"), tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}), IsNil)
	c.Check(tree.ExecuteAssertions(s.TPM().TPMContext, session), Equals, ErrSessionDigestNotFound)
}

func (s *policySuite) TestCreatePcrPolicyCounter(c *C) {
	testPublic := tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181fe00),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		Size:    8}
	testIndex := s.NVDefineSpace(c, tpm2.HandleOwner, nil, &testPublic)
	c.Check(s.TPM().NVIncrement(testIndex, testIndex, nil), IsNil)

	testCount, err := s.TPM().NVReadCounter(testIndex, testIndex, nil)
	c.Check(err, IsNil)

	block, _ := pem.Decode([]byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9pYAXaeeWBHZZ9TCRXNHClxi6NBB
69lQKonf26mcR8EFYdFOUjUzRxsrjQ8B9oQQnm5yuYZxHLxZN+aCD3D/0w==
-----END PUBLIC KEY-----`))
	c.Assert(block, NotNil)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	c.Assert(err, IsNil)
	c.Assert(key, tpm2_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	handle := s.NextAvailableHandle(c, 0x0181ff00)
	pub, count, err := CreatePcrPolicyCounter(s.TPM().TPMContext, handle,
		util.NewExternalECCPublicKeyWithDefaults(templates.KeyUsageSign, key.(*ecdsa.PublicKey)), s.TPM().HmacSession())
	c.Assert(err, IsNil)
	c.Check(pub.Index, Equals, handle)
	c.Check(pub.Attrs.Type(), Equals, tpm2.NVTypeCounter)
	c.Check(pub.AuthPolicy, DeepEquals, tpm2.Digest(testutil.DecodeHexString(c, "f47efcbc358c13854bfda01bfc38ce166b1abf0c8509e6b522cdc2edc69488a3")))
	c.Check(count, Equals, testCount)

	name, err := pub.Name()
	c.Check(err, IsNil)

	index, err := s.TPM().CreateResourceContextFromTPM(handle)
	c.Assert(err, IsNil)
	c.Check(name, DeepEquals, index.Name())
}

type testNewKeyDataPolicyData struct {
	alg                 tpm2.HashAlgorithmId
	key                 string
	pcrPolicyCounterPub *tpm2.NVPublic
	pcrPolicySequence   uint64

	expected tpm2.Digest
}

func (s *policySuite) testNewKeyDataPolicy(c *C, data *testNewKeyDataPolicyData) {
	block, _ := pem.Decode([]byte(data.key))
	c.Assert(block, NotNil)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	c.Assert(err, IsNil)
	c.Assert(key, tpm2_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	authKey := util.NewExternalECCPublicKeyWithDefaults(templates.KeyUsageSign, key.(*ecdsa.PublicKey))

	pcrPolicyCounterHandle := tpm2.HandleNull
	if data.pcrPolicyCounterPub != nil {
		pcrPolicyCounterHandle = data.pcrPolicyCounterPub.Index
	}

	policy, digest, err := NewKeyDataPolicy(data.alg, authKey, data.pcrPolicyCounterPub, data.pcrPolicySequence)
	c.Assert(err, IsNil)
	c.Assert(policy, tpm2_testutil.ConvertibleTo, &KeyDataPolicy_v2{})
	c.Check(policy.(*KeyDataPolicy_v2).StaticData.AuthPublicKey, DeepEquals, authKey)
	c.Check(policy.PCRPolicyCounterHandle(), Equals, pcrPolicyCounterHandle)
	c.Check(policy.PCRPolicySequence(), Equals, data.pcrPolicySequence)

	c.Check(digest, DeepEquals, data.expected)
}

func (s *policySuite) TestNewKeyDataPolicy(c *C) {
	s.testNewKeyDataPolicy(c, &testNewKeyDataPolicyData{
		alg: tpm2.HashAlgorithmSHA256,
		key: `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE49+rltJgmI3V7QqrkLBpB4V3xunW
xtjPyepMPNg3K7iPmPopFLA5Ap8RjR1Eu9B8LllUHTqYHJY6YQ3o+CP5TQ==
-----END PUBLIC KEY-----`,
		pcrPolicyCounterPub: &tpm2.NVPublic{
			Index:   0x0181fff0,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
			Size:    8},
		pcrPolicySequence: 10,
		expected:          testutil.DecodeHexString(c, "61f5396bcbd2bd3ed1392edaf88314da1230f6f252962c704119659295eca112")})
}

func (s *policySuite) TestNewKeyDataPolicySHA1(c *C) {
	s.testNewKeyDataPolicy(c, &testNewKeyDataPolicyData{
		alg: tpm2.HashAlgorithmSHA1,
		key: `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE49+rltJgmI3V7QqrkLBpB4V3xunW
xtjPyepMPNg3K7iPmPopFLA5Ap8RjR1Eu9B8LllUHTqYHJY6YQ3o+CP5TQ==
-----END PUBLIC KEY-----`,
		pcrPolicyCounterPub: &tpm2.NVPublic{
			Index:   0x0181fff0,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
			Size:    8},
		pcrPolicySequence: 10,
		expected:          testutil.DecodeHexString(c, "1a1afefb96937bd752a24cc23dbc16ecde3c8268")})
}

func (s *policySuite) TestNewKeyDataPolicyNoPCRPolicyCounterHandle(c *C) {
	s.testNewKeyDataPolicy(c, &testNewKeyDataPolicyData{
		alg: tpm2.HashAlgorithmSHA256,
		key: `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE49+rltJgmI3V7QqrkLBpB4V3xunW
xtjPyepMPNg3K7iPmPopFLA5Ap8RjR1Eu9B8LllUHTqYHJY6YQ3o+CP5TQ==
-----END PUBLIC KEY-----`,
		expected: testutil.DecodeHexString(c, "2171bcd975facbf5bf0ac504e2e9812d3cf5583c0162f96c849dd9b8154f4dc0")})
}

func (s *policySuite) TestNewKeyDataPolicyDifferentInitialSequence(c *C) {
	s.testNewKeyDataPolicy(c, &testNewKeyDataPolicyData{
		alg: tpm2.HashAlgorithmSHA256,
		key: `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE49+rltJgmI3V7QqrkLBpB4V3xunW
xtjPyepMPNg3K7iPmPopFLA5Ap8RjR1Eu9B8LllUHTqYHJY6YQ3o+CP5TQ==
-----END PUBLIC KEY-----`,
		pcrPolicyCounterPub: &tpm2.NVPublic{
			Index:   0x0181fff0,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
			Size:    8},
		pcrPolicySequence: 3000,
		expected:          testutil.DecodeHexString(c, "61f5396bcbd2bd3ed1392edaf88314da1230f6f252962c704119659295eca112")})
}

func (s *policySuite) testBlockPCRProtectionPolicies(c *C, n []int) {
	pcrs := tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}},
		{Hash: tpm2.HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}}}
	_, pcrValues, err := s.TPM().PCRRead(pcrs)
	c.Assert(err, IsNil)

	c.Check(BlockPCRProtectionPolicies(s.TPM(), n), IsNil)

	for _, p := range pcrs {
		h := p.Hash.NewHash()
		h.Write(make([]byte, 4))
		fenceHash := h.Sum(nil)

		for _, s := range n {
			h = p.Hash.NewHash()
			h.Write(pcrValues[p.Hash][s])
			h.Write(fenceHash)
			pcrValues[p.Hash][s] = h.Sum(nil)
		}
	}

	_, pcrValues2, err := s.TPM().PCRRead(pcrs)
	c.Assert(err, IsNil)
	c.Check(pcrValues2, DeepEquals, pcrValues)
}

func (s *policySuite) TestBlockPCRProtectionPolicies1(c *C) {
	s.testBlockPCRProtectionPolicies(c, []int{23})
}

func (s *policySuite) TestBlockPCRProtectionPolicies2(c *C) {
	s.testBlockPCRProtectionPolicies(c, []int{16})
}

func (s *policySuite) TestBlockPCRProtectionPolicies3(c *C) {
	s.testBlockPCRProtectionPolicies(c, []int{16, 23})
}
