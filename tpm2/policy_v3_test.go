// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2023 Canonical Ltd
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
	"errors"
	"math/rand"
	"strconv"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/cryptutil"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/policyutil"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type policyV3Mixin struct{}

func (_ policyV3Mixin) newPolicyAuthPublicKey(c *C, nameAlg tpm2.HashAlgorithmId, key secboot.PrimaryKey) *tpm2.Public {
	ecdsaKey, err := DeriveV3PolicyAuthKey(nameAlg.GetHash(), key)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&ecdsaKey.PublicKey, objectutil.WithNameAlg(nameAlg))
	c.Assert(err, IsNil)
	return pubKey
}

type policyV3SuiteNoTPM struct {
	policyOrTreeMixin
	policyV3Mixin
}

type policyV3Suite struct {
	tpm2test.TPMTest
	policyV3Mixin
}

func (s *policyV3Suite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy | tpm2test.TPMFeaturePCR | tpm2test.TPMFeatureNV
}

var _ = Suite(&policyV3Suite{})
var _ = Suite(&policyV3SuiteNoTPM{})

func (s *policyV3SuiteNoTPM) TestDerivePolicyAuthKey(c *C) {
	key := testutil.DecodeHexString(c, "fb8978601d0c2dd4129e3b9c1bb3f3116f4c5dd217c29b1017ab7cd31a882d3c")

	ecdsaKey, err := DeriveV3PolicyAuthKey(crypto.SHA256, key)
	c.Assert(err, IsNil)

	c.Check(ecdsaKey.D.Bytes(), DeepEquals, testutil.DecodeHexString(c, "e47351fb43a2e46fc71e08a735e7849e4769d895411e638cd530747b8876aecc"))
	c.Check(ecdsaKey.Curve, DeepEquals, elliptic.P256())
}

func (s *policyV3SuiteNoTPM) TestDerivePolicyAuthKeyDifferent(c *C) {
	key := testutil.DecodeHexString(c, "a8a4214838cc42fd1b82721dc5d6e1f81f14e2e572d777d439d8a96184e353be")

	ecdsaKey, err := DeriveV3PolicyAuthKey(crypto.SHA256, key)
	c.Assert(err, IsNil)

	c.Check(ecdsaKey.D.Bytes(), DeepEquals, testutil.DecodeHexString(c, "5e805d33b4b34af8f3f4aff543321a0c2b570d8e617f7687504a4c1b47a14668"))
	c.Check(ecdsaKey.Curve, DeepEquals, elliptic.P256())
}

func (s *policyV3SuiteNoTPM) TestPCRPolicyCounterHandle(c *C) {
	var data KeyDataPolicy = &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{
			PCRPolicyCounterHandle: 0x01800000}}
	c.Check(data.PCRPolicyCounterHandle(), Equals, tpm2.Handle(0x01800000))

	data = &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{
			PCRPolicyCounterHandle: tpm2.HandleNull}}
	c.Check(data.PCRPolicyCounterHandle(), Equals, tpm2.HandleNull)
}

func (s *policyV3SuiteNoTPM) TestPCRPolicySequence(c *C) {
	var data KeyDataPolicy = &KeyDataPolicy_v3{
		PCRData: NewPcrPolicyData_v3(
			&PcrPolicyData_v2{
				PolicySequence: 10})}
	c.Check(data.PCRPolicySequence(), Equals, uint64(10))

	data = &KeyDataPolicy_v3{
		PCRData: NewPcrPolicyData_v3(
			&PcrPolicyData_v2{
				PolicySequence: 500})}
	c.Check(data.PCRPolicySequence(), Equals, uint64(500))
}

type testV3UpdatePCRPolicyData struct {
	policyCounterHandle tpm2.Handle
	authKeyNameAlg      tpm2.HashAlgorithmId

	initialPolicyRef tpm2.Nonce

	alg            tpm2.HashAlgorithmId
	role           []byte
	pcrs           tpm2.PCRSelectionList
	pcrDigests     tpm2.DigestList
	policySequence uint64

	expectedPolicy tpm2.Digest
}

func (s *policyV3SuiteNoTPM) testUpdatePCRPolicy(c *C, data *testV3UpdatePCRPolicyData) {
	key := make(secboot.PrimaryKey, 32)
	rand.Read(key)

	authPublicKey := s.newPolicyAuthPublicKey(c, data.authKeyNameAlg, key)

	var (
		policyCounterPub  *tpm2.NVPublic
		policyCounterName tpm2.Name
	)
	if data.policyCounterHandle != tpm2.HandleNull {
		policyCounterPub = &tpm2.NVPublic{
			Index:   data.policyCounterHandle,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVPolicyRead | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
			Size:    8}
		policyCounterName = policyCounterPub.Name()
	}

	policyRef := ComputeV3PcrPolicyRef(data.alg, data.role, policyCounterName)

	initialPolicyRef := policyRef
	if data.initialPolicyRef != nil {
		initialPolicyRef = data.initialPolicyRef
	}

	var policyData KeyDataPolicy = &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{
			AuthPublicKey: authPublicKey,
			PCRPolicyRef:  initialPolicyRef,
		},
	}

	params := NewPcrPolicyParams(key, data.role, data.pcrs, data.pcrDigests, policyCounterPub, data.policySequence)
	c.Check(policyData.UpdatePCRPolicy(data.alg, params), IsNil)

	c.Check(policyData.(*KeyDataPolicy_v3).PCRData.Selection, tpm2_testutil.TPMValueDeepEquals, data.pcrs)

	orTree, err := policyData.(*KeyDataPolicy_v3).PCRData.OrData.Resolve()
	c.Assert(err, IsNil)
	var digests tpm2.DigestList
	for _, digest := range data.pcrDigests {
		builder := policyutil.NewPolicyBuilder(data.alg)
		builder.RootBranch().PolicyPCRDigest(digest, data.pcrs)
		policy, err := builder.Digest()
		c.Check(err, IsNil)
		digests = append(digests, policy)
	}
	s.checkPolicyOrTree(c, data.alg, digests, orTree)

	c.Check(policyData.(*KeyDataPolicy_v3).StaticData.PCRPolicyRef, DeepEquals, policyRef)

	c.Check(policyData.(*KeyDataPolicy_v3).PCRData.PolicySequence, Equals, data.policySequence)

	c.Check(policyData.(*KeyDataPolicy_v3).PCRData.AuthorizedPolicy, DeepEquals, data.expectedPolicy)

	c.Check(policyData.(*KeyDataPolicy_v3).PCRData.AuthorizedPolicySignature.SigAlg, Equals, tpm2.SigSchemeAlgECDSA)
	c.Check(policyData.(*KeyDataPolicy_v3).PCRData.AuthorizedPolicySignature.Signature.ECDSA.Hash, Equals, data.authKeyNameAlg)

	digest := policyutil.ComputePolicyAuthorizationTBSDigest(data.authKeyNameAlg.GetHash(),
		policyData.(*KeyDataPolicy_v3).PCRData.AuthorizedPolicy,
		policyRef)
	c.Check(err, IsNil)
	ok, err := cryptutil.VerifySignature(authPublicKey.Public(), digest, policyData.(*KeyDataPolicy_v3).PCRData.AuthorizedPolicySignature)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)
}

func (s *policyV3SuiteNoTPM) TestUpdatePCRPolicy(c *C) {
	s.testUpdatePCRPolicy(c, &testV3UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		alg:                 tpm2.HashAlgorithmSHA256,
		role:                []byte("foo"),
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		policySequence:      1,
		expectedPolicy:      testutil.DecodeHexString(c, "214063f761968beacf47ed3cfa692480aaba7981e3a4f95f606da88cc45182f3")})
}

func (s *policyV3SuiteNoTPM) TestUpdatePCRPolicyDepth1(c *C) {
	s.testUpdatePCRPolicy(c, &testV3UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		alg:                 tpm2.HashAlgorithmSHA256,
		role:                []byte("foo"),
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests: tpm2.DigestList{
			hash(crypto.SHA256, "1"),
			hash(crypto.SHA256, "2"),
			hash(crypto.SHA256, "3"),
			hash(crypto.SHA256, "4"),
			hash(crypto.SHA256, "5")},
		policySequence: 1,
		expectedPolicy: testutil.DecodeHexString(c, "0ced4fca4da1c7a3c7342e37a7e5c0f40a9c4d19d53eb3c4c63371fba54e4bac")})
}

func (s *policyV3SuiteNoTPM) TestUpdatePCRPolicyDepth2(c *C) {
	data := &testV3UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		alg:                 tpm2.HashAlgorithmSHA256,
		role:                []byte("foo"),
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		policySequence:      1,
		expectedPolicy:      testutil.DecodeHexString(c, "e51cd2aa2f8f6b872c2f3e3e98f6093591928af6deeaceae191e5b3ade3290f1")}
	for i := 1; i < 26; i++ {
		data.pcrDigests = append(data.pcrDigests, hash(crypto.SHA256, strconv.Itoa(i)))
	}
	s.testUpdatePCRPolicy(c, data)
}

func (s *policyV3SuiteNoTPM) TestUpdatePCRPolicyDifferentCounter(c *C) {
	s.testUpdatePCRPolicy(c, &testV3UpdatePCRPolicyData{
		policyCounterHandle: 0x0180ffff,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		alg:                 tpm2.HashAlgorithmSHA256,
		role:                []byte("foo"),
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		policySequence:      1,
		expectedPolicy:      testutil.DecodeHexString(c, "e08a219a6a7fdbaf52e64f9f3fb7208948ed3994997be53cc79be4464bd6405f")})
}

func (s *policyV3SuiteNoTPM) TestUpdatePCRPolicyNoCounter(c *C) {
	s.testUpdatePCRPolicy(c, &testV3UpdatePCRPolicyData{
		policyCounterHandle: tpm2.HandleNull,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		alg:                 tpm2.HashAlgorithmSHA256,
		role:                []byte("foo"),
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		expectedPolicy:      testutil.DecodeHexString(c, "830c1432cbdc2f3dc2c1c83430df4fe0f5c2c6b1437b01071ddfd6f70fe33a90")})
}

func (s *policyV3SuiteNoTPM) TestUpdatePCRPolicySHA1AuthKey(c *C) {
	s.testUpdatePCRPolicy(c, &testV3UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA1,
		alg:                 tpm2.HashAlgorithmSHA256,
		role:                []byte("foo"),
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		policySequence:      1,
		expectedPolicy:      testutil.DecodeHexString(c, "214063f761968beacf47ed3cfa692480aaba7981e3a4f95f606da88cc45182f3")})
}

func (s *policyV3SuiteNoTPM) TestUpdatePCRPolicyDifferentSequence(c *C) {
	s.testUpdatePCRPolicy(c, &testV3UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		alg:                 tpm2.HashAlgorithmSHA256,
		role:                []byte("foo"),
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		policySequence:      50,
		expectedPolicy:      testutil.DecodeHexString(c, "95a0abac2bcdfd0150dc1317062602c9c0540eaba0acbb31b21cbaf6a3da94c5")})
}

func (s *policyV3SuiteNoTPM) TestUpdatePCRPolicySHA1Policy(c *C) {
	s.testUpdatePCRPolicy(c, &testV3UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		alg:                 tpm2.HashAlgorithmSHA1,
		role:                []byte("foo"),
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA1, "1")},
		policySequence:      1,
		expectedPolicy:      testutil.DecodeHexString(c, "e537ec1e4b1d4ec5bae9a3644194e8d1a9181bf1")})
}

func (s *policyV3SuiteNoTPM) TestUpdatePCRPolicyDifferentPCRs(c *C) {
	s.testUpdatePCRPolicy(c, &testV3UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		alg:                 tpm2.HashAlgorithmSHA256,
		role:                []byte("foo"),
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA1, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		policySequence:      1,
		expectedPolicy:      testutil.DecodeHexString(c, "ce6e3eb8ecd88ef2e21327ad58c77b21a8b563b5b373f1eab08dcc8296c6ee56")})
}

func (s *policyV3SuiteNoTPM) TestUpdatePCRPolicyIncorrectInitialPolicyRef(c *C) {
	s.testUpdatePCRPolicy(c, &testV3UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		initialPolicyRef:    []byte("1234"),
		alg:                 tpm2.HashAlgorithmSHA256,
		role:                []byte("foo"),
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		policySequence:      1,
		expectedPolicy:      testutil.DecodeHexString(c, "214063f761968beacf47ed3cfa692480aaba7981e3a4f95f606da88cc45182f3")})
}

func (s *policyV3SuiteNoTPM) TestUpdatePCRPolicyDifferentRole(c *C) {
	s.testUpdatePCRPolicy(c, &testV3UpdatePCRPolicyData{
		policyCounterHandle: 0x01800000,
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		alg:                 tpm2.HashAlgorithmSHA256,
		role:                []byte("bar"),
		pcrs:                tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		pcrDigests:          tpm2.DigestList{hash(crypto.SHA256, "1")},
		policySequence:      1,
		expectedPolicy:      testutil.DecodeHexString(c, "214063f761968beacf47ed3cfa692480aaba7981e3a4f95f606da88cc45182f3")})
}

func (s *policyV3SuiteNoTPM) TestSetPCRPolicyFrom(c *C) {
	key := make(secboot.PrimaryKey, 32)
	rand.Read(key)

	policyCounterPub := &tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVPolicyRead | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
		Size:    8}

	policyData1 := &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{
			AuthPublicKey: s.newPolicyAuthPublicKey(c, tpm2.HashAlgorithmSHA256, key)},
	}

	params := NewPcrPolicyParams(key, nil,
		tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7, 12}}},
		tpm2.DigestList{hash(crypto.SHA256, "1"), hash(crypto.SHA256, "2")},
		policyCounterPub, 5000)
	c.Check(policyData1.UpdatePCRPolicy(tpm2.HashAlgorithmSHA256, params), IsNil)

	var policyData2 KeyDataPolicy = &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{
			AuthPublicKey: s.newPolicyAuthPublicKey(c, tpm2.HashAlgorithmSHA256, key)}}
	policyData2.SetPCRPolicyFrom(policyData1)

	c.Check(policyData2.(*KeyDataPolicy_v3).PCRData, DeepEquals, policyData1.PCRData)
}

type testV3ExecutePCRPolicyData struct {
	authKeyNameAlg      tpm2.HashAlgorithmId
	policyCounterHandle tpm2.Handle
	alg                 tpm2.HashAlgorithmId

	pcrs      tpm2.PCRSelectionList
	pcrValues []tpm2.PCRValues

	pcrEvents []pcrEvent
}

func (s *policyV3Suite) testExecutePCRPolicy(c *C, data *testV3ExecutePCRPolicyData) {
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)

	authKeyPublic := s.newPolicyAuthPublicKey(c, data.authKeyNameAlg, primaryKey)

	var policyCounterPub *tpm2.NVPublic
	if data.policyCounterHandle != tpm2.HandleNull {
		var err error
		policyCounterPub, err = EnsurePcrPolicyCounter(s.TPM().TPMContext, s.NextAvailableHandle(c, data.policyCounterHandle), authKeyPublic, s.TPM().HmacSession())
		c.Assert(err, IsNil)
	}

	policyData, expectedDigest, err := NewKeyDataPolicy(data.alg, authKeyPublic, "", policyCounterPub, false)
	c.Assert(err, IsNil)
	c.Assert(policyData, testutil.ConvertibleTo, &KeyDataPolicy_v3{})

	var policyCount uint64
	if data.policyCounterHandle != tpm2.HandleNull {
		context, err := policyData.PCRPolicyCounterContext(s.TPM().TPMContext, policyCounterPub)
		c.Assert(err, IsNil)

		policyCount, err = context.Get()
		c.Assert(err, IsNil)
	}

	var digests tpm2.DigestList
	for _, v := range data.pcrValues {
		d, _ := policyutil.ComputePCRDigest(data.alg, data.pcrs, v)
		digests = append(digests, d)
	}

	params := NewPcrPolicyParams(primaryKey, nil, data.pcrs, digests, policyCounterPub, policyCount)
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

func (s *policyV3Suite) TestExecutePCRPolicy(c *C) {
	s.testExecutePCRPolicy(c, &testV3ExecutePCRPolicyData{
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

func (s *policyV3Suite) TestExecutePCRPolicyNoPCRs(c *C) {
	s.testExecutePCRPolicy(c, &testV3ExecutePCRPolicyData{
		authKeyNameAlg:      tpm2.HashAlgorithmSHA256,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrValues:           []tpm2.PCRValues{{}},
	})
}

func (s *policyV3Suite) TestExecutePCRPolicyMultipleDepth1(c *C) {
	var pcrValues []tpm2.PCRValues
	for i := 1; i < 6; i++ {
		pcrValues = append(pcrValues, tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"+strconv.Itoa(i), "bar"+strconv.Itoa(i)),
				23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"+strconv.Itoa(i), "foo"+strconv.Itoa(i)),
			},
		})
	}

	s.testExecutePCRPolicy(c, &testV3ExecutePCRPolicyData{
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

func (s *policyV3Suite) TestExecutePCRPolicyMultipleDepth2(c *C) {
	var pcrValues []tpm2.PCRValues
	for i := 1; i < 26; i++ {
		pcrValues = append(pcrValues, tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"+strconv.Itoa(i), "bar"+strconv.Itoa(i)),
				23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"+strconv.Itoa(i), "foo"+strconv.Itoa(i)),
			},
		})
	}

	s.testExecutePCRPolicy(c, &testV3ExecutePCRPolicyData{
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

func (s *policyV3Suite) TestExecutePCRPolicySHA1AuthKey(c *C) {
	s.testExecutePCRPolicy(c, &testV3ExecutePCRPolicyData{
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

func (s *policyV3Suite) TestExecutePCRPolicyDifferentPolicyCounterHandle(c *C) {
	s.testExecutePCRPolicy(c, &testV3ExecutePCRPolicyData{
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

func (s *policyV3Suite) TestExecutePCRPolicyNoPolicyCounterHandle(c *C) {
	s.testExecutePCRPolicy(c, &testV3ExecutePCRPolicyData{
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

func (s *policyV3Suite) TestExecutePCRPolicySHA1Policy(c *C) {
	s.testExecutePCRPolicy(c, &testV3ExecutePCRPolicyData{
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

func (s *policyV3Suite) TestExecutePCRPolicyDifferentPCRSelection(c *C) {
	s.testExecutePCRPolicy(c, &testV3ExecutePCRPolicyData{
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

type testV3ExecutePCRPolicyErrorHandlingData struct {
	authKeyNameAlg      tpm2.HashAlgorithmId
	policyCounterHandle tpm2.Handle
	alg                 tpm2.HashAlgorithmId

	pcrs      tpm2.PCRSelectionList
	pcrValues []tpm2.PCRValues

	pcrEvents []pcrEvent

	fn func(data *KeyDataPolicy_v3, primaryKey secboot.PrimaryKey)
}

func (s *policyV3Suite) testExecutePCRPolicyErrorHandling(c *C, data *testV3ExecutePCRPolicyErrorHandlingData) error {
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)

	authKeyPublic := s.newPolicyAuthPublicKey(c, data.authKeyNameAlg, primaryKey)

	var policyCounterPub *tpm2.NVPublic
	if data.policyCounterHandle != tpm2.HandleNull {
		var err error
		policyCounterPub, err = EnsurePcrPolicyCounter(s.TPM().TPMContext, s.NextAvailableHandle(c, data.policyCounterHandle), authKeyPublic, s.TPM().HmacSession())
		c.Assert(err, IsNil)
	}

	policyData, expectedDigest, err := NewKeyDataPolicy(data.alg, authKeyPublic, "", policyCounterPub, false)
	c.Assert(err, IsNil)
	c.Assert(policyData, testutil.ConvertibleTo, &KeyDataPolicy_v3{})

	var policyCount uint64
	if data.policyCounterHandle != tpm2.HandleNull {
		context, err := policyData.PCRPolicyCounterContext(s.TPM().TPMContext, policyCounterPub)
		c.Assert(err, IsNil)

		policyCount, err = context.Get()
		c.Assert(err, IsNil)
	}

	var digests tpm2.DigestList
	for _, v := range data.pcrValues {
		d, _ := policyutil.ComputePCRDigest(data.alg, data.pcrs, v)
		digests = append(digests, d)
	}

	params := NewPcrPolicyParams(primaryKey, nil, data.pcrs, digests, policyCounterPub, policyCount)
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

	data.fn(policyData.(*KeyDataPolicy_v3), primaryKey)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, data.alg)
	executeErr := policyData.ExecutePCRPolicy(s.TPM().TPMContext, session, s.TPM().HmacSession())

	digest, err := s.TPM().PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, Not(DeepEquals), expectedDigest)

	return executeErr
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidSelection1(c *C) {
	// Test with a PCR selection that doesn't match the original policy.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
			data.PCRData.Selection = tpm2.PCRSelectionList{}
		},
	})
	c.Check(IsPCRPolicyDataError(err), testutil.IsTrue)
	c.Check(errors.Is(err, ErrPcrPolicyNotAuthorized), testutil.IsTrue)
	c.Check(err, ErrorMatches, "the PCR policy is not authorized for the current configuration")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidSelection2(c *C) {
	// Test with an invalid PCR selection.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
			data.PCRData.Selection = tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{50}}}
		},
	})
	c.Check(IsPCRPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: invalid PCR selection")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidOrTree1(c *C) {
	// Test with an invalid PCR policy or tree.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
			data.PCRData.OrData = PolicyOrData_v0{}
		},
	})
	c.Check(IsPCRPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot resolve PolicyOR tree: no nodes")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidOrTree2(c *C) {
	// Test with an invalid PCR policy or tree.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
			data.PCRData.OrData[0].Next = 10
		},
	})
	c.Check(IsPCRPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot resolve PolicyOR tree: index 10 out of range")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidOrTree3(c *C) {
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

	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
			copy(data.PCRData.OrData[4].Digests[0], make(tpm2.Digest, 32))
		},
	})
	c.Check(IsPCRPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot execute PCR assertions: cannot execute PolicyOR assertions: invalid data")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidOrTree4(c *C) {
	// Test by modifying the PCR policy or tree to contain unauthorized conditions.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
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
	c.Check(IsPCRPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "the PCR policy is invalid")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidPolicySequence(c *C) {
	// Test by modifying the PCR policy sequence to a higher value.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
			data.PCRData.PolicySequence += 10
		},
	})
	c.Check(IsPCRPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "the PCR policy is invalid")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingPCRMismatch(c *C) {
	var pcrValues []tpm2.PCRValues
	for i := 1; i < 26; i++ {
		pcrValues = append(pcrValues, tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo"+strconv.Itoa(i), "bar"+strconv.Itoa(i)),
				23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar"+strconv.Itoa(i), "foo"+strconv.Itoa(i)),
			},
		})
	}

	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {},
	})
	c.Check(IsPCRPolicyDataError(err), testutil.IsTrue)
	c.Check(errors.Is(err, ErrPcrPolicyNotAuthorized), testutil.IsTrue)
	c.Check(err, ErrorMatches, "the PCR policy is not authorized for the current configuration")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidPCRPolicyCounterHandle1(c *C) {
	// Test with an invalid PCR policy counter handle.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
			data.StaticData.PCRPolicyCounterHandle = 0x81000000
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "invalid handle 0x81000000 for PCR policy counter")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidPCRPolicyCounterHandle2(c *C) {
	// Test with a PCR policy counter handle pointing to an undefined index.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
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

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidPCRPolicyCounterHandle3(c *C) {
	// Test with the PCR policy counter handle undefined when the policy was created
	// with one.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
			data.StaticData.PCRPolicyCounterHandle = tpm2.HandleNull
		},
	})
	c.Check(IsPCRPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "the PCR policy is invalid")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingRevoked(c *C) {
	// Test with a revoked PCR policy.
	alg := tpm2.HashAlgorithmSHA256
	pcrs := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{16, 23}}}
	pcrValues := []tpm2.PCRValues{
		{
			tpm2.HashAlgorithmSHA256: {
				16: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "foo", "bar"),
				23: tpm2test.MakePCRValueFromEvents(tpm2.HashAlgorithmSHA256, "bar", "foo"),
			},
		},
	}

	var digests tpm2.DigestList
	for _, v := range pcrValues {
		d, _ := policyutil.ComputePCRDigest(alg, pcrs, v)
		digests = append(digests, d)
	}

	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
		authKeyNameAlg:      alg,
		policyCounterHandle: 0x01800000,
		alg:                 tpm2.HashAlgorithmSHA256,
		pcrs:                pcrs,
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
		fn: func(data *KeyDataPolicy_v3, primaryKey secboot.PrimaryKey) {
			pub, _, err := s.TPM().NVReadPublic(tpm2.NewHandleContext(data.StaticData.PCRPolicyCounterHandle))
			c.Assert(err, IsNil)

			target := data.PCRData.PolicySequence

			authKeyPublic := s.newPolicyAuthPublicKey(c, alg, primaryKey)
			policyCounterPub, err := EnsurePcrPolicyCounter(s.TPM().TPMContext, s.NextAvailableHandle(c, 0x01800000), authKeyPublic, s.TPM().HmacSession())
			c.Assert(err, IsNil)

			params := NewPcrPolicyParams(primaryKey, nil, pcrs, digests, policyCounterPub, target+1)
			data.UpdatePCRPolicy(alg, params)

			context, err := data.PCRPolicyCounterContext(s.TPM().TPMContext, pub)
			c.Assert(err, IsNil)
			for {
				current, err := context.Get()
				c.Assert(err, IsNil)

				if current > target {
					break
				}

				c.Assert(context.Increment(primaryKey), IsNil)
			}
		},
	})
	c.Check(IsPCRPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "the PCR policy is invalid")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidAuthPublicKey(c *C) {
	// Test with an auth public key that has an invalid name algorithm.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
			data.StaticData.AuthPublicKey.NameAlg = tpm2.HashAlgorithmId(tpm2.AlgorithmSM4)
		},
	})
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot compute auth policies for PCR policy counter: could not build policy: encountered an error when calling PolicySigned: invalid authKey")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidAuthorizedPolicySignature(c *C) {
	// Test with an invalid authorized policy signature
	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
			copy(data.PCRData.AuthorizedPolicy, make(tpm2.Digest, 32))
		},
	})
	c.Check(IsPCRPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "cannot verify PCR policy signature: TPM returned an error for parameter 2 whilst executing command TPM_CC_VerifySignature: TPM_RC_SIGNATURE \\(the signature is not valid\\)")
}

func (s *policyV3Suite) TestExecutePCRPolicyErrorHandlingInvalidAuthorizedPolicy(c *C) {
	// Test that authorizing a policy with another key and updating the public key
	// in the metadata produces the wrong session digest.
	err := s.testExecutePCRPolicyErrorHandling(c, &testV3ExecutePCRPolicyErrorHandlingData{
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
		fn: func(data *KeyDataPolicy_v3, _ secboot.PrimaryKey) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
			c.Assert(err, IsNil)

			authPublicKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
			c.Assert(err, IsNil)
			data.StaticData.AuthPublicKey = authPublicKey

			auth, err := policyutil.SignPolicyAuthorization(testutil.RandReader, data.PCRData.AuthorizedPolicy, authPublicKey, ComputeV3PcrPolicyRef(tpm2.HashAlgorithmSHA256, []byte(""), nil), key, tpm2.HashAlgorithmSHA256)
			c.Assert(err, IsNil)
			data.PCRData.AuthorizedPolicySignature = auth.Signature
		},
	})
	c.Check(err, IsNil)
}

func (s *policyV3Suite) TestPolicyCounterContextGet(c *C) {
	authKey := make(secboot.PrimaryKey, 32)
	rand.Read(authKey)
	authKeyPublic := s.newPolicyAuthPublicKey(c, tpm2.HashAlgorithmSHA256, authKey)

	policyCounterPub, err := EnsurePcrPolicyCounter(s.TPM().TPMContext, s.NextAvailableHandle(c, 0x01800000), authKeyPublic, s.TPM().HmacSession())
	c.Assert(err, IsNil)

	policyCounterContext, err := tpm2.NewNVIndexResourceContextFromPub(policyCounterPub)
	c.Assert(err, IsNil)

	expected, err := s.TPM().NVReadCounter(policyCounterContext, policyCounterContext, nil)
	c.Check(err, IsNil)

	data := &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{
			AuthPublicKey:          authKeyPublic,
			PCRPolicyCounterHandle: policyCounterPub.Index}}

	context, err := data.PCRPolicyCounterContext(s.TPM().TPMContext, policyCounterPub)
	c.Assert(err, IsNil)

	count, err := context.Get()
	c.Check(err, IsNil)
	c.Check(count, Equals, expected)
}

func (s *policyV3Suite) TestPolicyCounterContextIncrement(c *C) {
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)
	authKeyPublic := s.newPolicyAuthPublicKey(c, tpm2.HashAlgorithmSHA256, primaryKey)

	policyCounterPub, err := EnsurePcrPolicyCounter(s.TPM().TPMContext, s.NextAvailableHandle(c, 0x01800000), authKeyPublic, s.TPM().HmacSession())
	c.Assert(err, IsNil)

	data := &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{
			AuthPublicKey:          authKeyPublic,
			PCRPolicyCounterHandle: policyCounterPub.Index}}

	context, err := data.PCRPolicyCounterContext(s.TPM().TPMContext, policyCounterPub)
	c.Assert(err, IsNil)

	initialCount, err := context.Get()
	c.Check(err, IsNil)

	c.Check(context.Increment(primaryKey), IsNil)

	incCount, err := context.Get()
	c.Check(err, IsNil)

	c.Check(incCount, Equals, initialCount+1)
}

func (s *policyV3SuiteNoTPM) TestValidateAuthKey(c *C) {
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)
	authKeyPublic := s.newPolicyAuthPublicKey(c, tpm2.HashAlgorithmSHA256, primaryKey)

	data := &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{
			AuthPublicKey: authKeyPublic}}
	c.Check(data.ValidateAuthKey(primaryKey), IsNil)
}

func (s *policyV3SuiteNoTPM) TestValidateAuthKeyWrongKey(c *C) {
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)
	authKeyPublic := s.newPolicyAuthPublicKey(c, tpm2.HashAlgorithmSHA256, primaryKey)

	data := &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{
			AuthPublicKey: authKeyPublic}}

	rand.Read(primaryKey)

	err := data.ValidateAuthKey(primaryKey)
	c.Check(IsPolicyDataError(err), testutil.IsTrue)
	c.Check(err, ErrorMatches, "dynamic authorization policy signing private key doesn't match public key")
}

func (s *policyV3SuiteNoTPM) TestRequireUserAuthTrue(c *C) {
	data := &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{RequireAuthValue: true}}
	c.Check(data.RequireUserAuth(), testutil.IsTrue)
}

func (s *policyV3SuiteNoTPM) TestRequireUserAuthFalse(c *C) {
	data := &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{RequireAuthValue: false}}
	c.Check(data.RequireUserAuth(), testutil.IsFalse)
}
