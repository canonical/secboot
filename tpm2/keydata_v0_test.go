// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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
	"bytes"
	"crypto/rsa"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/templates"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type keyDataV0Suite struct {
	tpm2test.TPMTest
	policyV0Mixin
	primary tpm2.ResourceContext
}

func (s *keyDataV0Suite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy | tpm2test.TPMFeatureNV
}

func (s *keyDataV0Suite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)
	s.policyV0Mixin.tpmTest = &s.TPMTest.TPMTest

	s.createMockLockIndex(c)
	s.enablePolicyLock(c)

	primary := s.CreateStoragePrimaryKeyRSA(c)
	s.primary = s.EvictControl(c, tpm2.HandleOwner, primary, tcg.SRKHandle)
}

func (s *keyDataV0Suite) newMockKeyData(c *C, pcrPolicyCounterHandle tpm2.Handle) (KeyData, *tpm2.NVPublic) {
	// Create the RSA auth key
	authKey, err := rsa.GenerateKey(testutil.RandReader, 2048)
	c.Assert(err, IsNil)

	authKeyPublic := util.NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &authKey.PublicKey)
	mu.MustCopyValue(&authKeyPublic, authKeyPublic)

	// Create a mock PCR policy counter
	policyCounter, count, policyCounterPolicies := s.createMockPcrPolicyCounter(c, pcrPolicyCounterHandle, authKeyPublic.Name())

	// Create sealed object
	secret := []byte("secret data")

	template := tpm2_testutil.NewSealedObjectTemplate()

	policyData, policy := s.newMockKeyDataPolicy(c, template.NameAlg, authKeyPublic, policyCounter, policyCounterPolicies)
	template.AuthPolicy = policy

	policyData.(*KeyDataPolicy_v0).PCRData = &PcrPolicyData_v0{
		PolicySequence:   count,
		AuthorizedPolicy: make(tpm2.Digest, 32),
		AuthorizedPolicySignature: &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgRSAPSS,
			Signature: &tpm2.SignatureU{
				RSAPSS: &tpm2.SignatureRSAPSS{
					Hash: tpm2.HashAlgorithmSHA256,
					Sig:  make(tpm2.PublicKeyRSA, 2048)}}}}

	sensitive := tpm2.SensitiveCreate{Data: secret}

	priv, pub, _, _, _, err := s.TPM().Create(s.primary, &sensitive, template, nil, nil, nil)
	c.Assert(err, IsNil)

	return &KeyData_v0{
		KeyPrivate: priv,
		KeyPublic:  pub,
		PolicyData: policyData.(*KeyDataPolicy_v0)}, policyCounter
}

var _ = Suite(&keyDataV0Suite{})

func (s *keyDataV0Suite) TestVersion(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))
	c.Check(data.Version(), Equals, uint32(0))
}

func (s *keyDataV0Suite) TestSealedObjectData(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))
	c.Check(data.Private(), DeepEquals, data.(*KeyData_v0).KeyPrivate)
	c.Check(data.Public(), DeepEquals, data.(*KeyData_v0).KeyPublic)
}

func (s *keyDataV0Suite) TestNoImport(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))
	private := data.Private()

	c.Check(data.ImportSymSeed(), IsNil)
	c.Check(func() { data.Imported(nil) }, PanicMatches, "not supported")
	c.Check(data.Private(), DeepEquals, private)
}

func (s *keyDataV0Suite) TestValidateOK1(c *C) {
	data, expectedPcrPolicyCounter := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter.Name(), DeepEquals, expectedPcrPolicyCounter.Name())
}

func (s *keyDataV0Suite) TestValidateOK2(c *C) {
	data, expectedPcrPolicyCounter := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x018ff000))

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter.Name(), DeepEquals, expectedPcrPolicyCounter.Name())
}

func (s *keyDataV0Suite) TestValidateNoLockIndex(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	index, err := s.TPM().CreateResourceContextFromTPM(LockNVHandle)
	c.Assert(err, IsNil)
	c.Check(s.TPM().NVUndefineSpace(s.TPM().OwnerHandleContext(), index, nil), IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err = data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "lock NV index is unavailable")
}

func (s *keyDataV0Suite) TestValidateInvalidAuthPublicKeyNameAlg(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	data.(*KeyData_v0).PolicyData.StaticData.AuthPublicKey.NameAlg = tpm2.HashAlgorithmNull

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "cannot compute name of dynamic authorization policy key: unsupported name algorithm or algorithm not linked into binary: TPM_ALG_NULL")
}

func (s *keyDataV0Suite) TestValidateInvalidAuthPublicKeyType(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	data.(*KeyData_v0).PolicyData.StaticData.AuthPublicKey.Type = tpm2.ObjectTypeECC

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "public area of dynamic authorization policy signing key has the wrong type")
}

func (s *keyDataV0Suite) TestValidateInvalidAuthPublicKeyScheme(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	data.(*KeyData_v0).PolicyData.StaticData.AuthPublicKey.Params.RSADetail.Scheme = tpm2.RSAScheme{
		Scheme: tpm2.RSASchemeRSASSA,
		Details: &tpm2.AsymSchemeU{
			RSASSA: &tpm2.SigSchemeRSASSA{HashAlg: tpm2.HashAlgorithmSHA256}}}

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "dynamic authorization policy signing key has unexpected scheme")
}

func (s *keyDataV0Suite) TestValidateInvalidPolicyCounterHandle(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	data.(*KeyData_v0).PolicyData.StaticData.PCRPolicyCounterHandle = 0x81000000

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "PCR policy counter handle is invalid")
}

func (s *keyDataV0Suite) TestValidateNoPolicyCounter(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	index, err := s.TPM().CreateResourceContextFromTPM(data.Policy().PCRPolicyCounterHandle())
	c.Assert(err, IsNil)
	c.Check(s.TPM().NVUndefineSpace(s.TPM().OwnerHandleContext(), index, nil), IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err = data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "PCR policy counter is unavailable")
}

func (s *keyDataV0Suite) TestValidateInvalidSealedObjectNameAlg(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	data.Public().NameAlg = tpm2.HashAlgorithmNull

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "cannot determine if static authorization policy matches sealed key object: algorithm unavailable")
}

func (s *keyDataV0Suite) TestValidateWrongAuthKey(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	authKey, err := rsa.GenerateKey(testutil.RandReader, 2048)
	c.Assert(err, IsNil)
	data.(*KeyData_v0).PolicyData.StaticData.AuthPublicKey = util.NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &authKey.PublicKey)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err = data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}

func (s *keyDataV0Suite) TestValidateWrongPolicyCounter(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	index, err := s.TPM().CreateResourceContextFromTPM(data.Policy().PCRPolicyCounterHandle())
	handle := index.Handle()
	c.Assert(err, IsNil)
	c.Check(s.TPM().NVUndefineSpace(s.TPM().OwnerHandleContext(), index, nil), IsNil)

	nvPub := tpm2.NVPublic{
		Index:   handle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		Size:    8}
	s.NVDefineSpace(c, tpm2.HandleOwner, nil, &nvPub)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err = data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}

func (s *keyDataV0Suite) TestValidateWrongLockIndex(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	index, err := s.TPM().CreateResourceContextFromTPM(LockNVHandle)
	c.Assert(err, IsNil)
	c.Check(s.TPM().NVUndefineSpace(s.TPM().OwnerHandleContext(), index, nil), IsNil)

	nvPub := tpm2.NVPublic{
		Index:   LockNVHandle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		Size:    0}
	s.NVDefineSpace(c, tpm2.HandleOwner, nil, &nvPub)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err = data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}

func (s *keyDataV0Suite) TestValidateWrongPolicyCounterAuthPolicies1(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	data.(*KeyData_v0).PolicyData.StaticData.PCRPolicyCounterAuthPolicies = data.(*KeyData_v0).PolicyData.StaticData.PCRPolicyCounterAuthPolicies[1:]

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "unexpected number of OR policy digests for PCR policy counter")
}

func (s *keyDataV0Suite) TestValidateWrongPolicyCounterAuthPolicies2(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	copy(data.(*KeyData_v0).PolicyData.StaticData.PCRPolicyCounterAuthPolicies[1], make([]byte, 32))

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "unexpected OR policy digest for PCR policy counter")
}

func (s *keyDataV0Suite) TestValidateWrongPolicyCounterAuthPolicies3(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	copy(data.(*KeyData_v0).PolicyData.StaticData.PCRPolicyCounterAuthPolicies[0], make([]byte, 32))

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, nil, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "PCR policy counter has unexpected authorization policy")
}

func (s *keyDataV0Suite) TestSerialization(c *C) {
	data1, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	buf := new(bytes.Buffer)
	c.Check(data1.Write(buf), IsNil)

	data2, err := ReadKeyDataV0(buf)
	c.Assert(err, IsNil)
	c.Check(data2, DeepEquals, data1)
}

func (s *keyDataV0Suite) TestValidateInvalidRoleSupplied(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	_, err := data.ValidateData(s.TPM().TPMContext, []byte("foo"), nil)
	c.Check(err, ErrorMatches, "unexpected role")
}
