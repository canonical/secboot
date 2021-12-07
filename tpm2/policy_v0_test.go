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
	"strconv"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"

	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type policyV0SuiteNoTPM struct {
	policyOrTreeMixin
}

type policyV0Suite struct {
	tpm2test.TPMTest
}

func (s *policyV0Suite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy | tpm2test.TPMFeaturePCR | tpm2test.TPMFeatureNV
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
	c.Check(serialized, tpm2_testutil.LenEquals, data.numNodes)

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
