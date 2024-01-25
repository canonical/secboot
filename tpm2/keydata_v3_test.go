// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021-2023 Canonical Ltd
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/rand"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/templates"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type keyDataV3Suite struct {
	tpm2test.TPMTest
	policyV3Mixin

	primary tpm2.ResourceContext
}

func (s *keyDataV3Suite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy | tpm2test.TPMFeatureNV
}

func (s *keyDataV3Suite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)

	primary := s.CreateStoragePrimaryKeyRSA(c)
	s.primary = s.EvictControl(c, tpm2.HandleOwner, primary, tcg.SRKHandle)
}

func (s *keyDataV3Suite) newMockKeyData(c *C, pcrPolicyCounterHandle tpm2.Handle) (KeyData, tpm2.Name) {
	// Create the auth key
	authKey := make(secboot.PrimaryKey, 32)
	rand.Read(authKey)

	authKeyPublic := s.newPolicyAuthPublicKey(c, tpm2.HashAlgorithmSHA256, authKey)

	// Create a mock PCR policy counter
	var policyCounterPub *tpm2.NVPublic
	var policyCount uint64
	var policyCounterName tpm2.Name
	if pcrPolicyCounterHandle != tpm2.HandleNull {
		var err error
		policyCounterPub, policyCount, err = CreatePcrPolicyCounter(s.TPM().TPMContext, pcrPolicyCounterHandle, authKeyPublic, s.TPM().HmacSession())
		c.Assert(err, IsNil)
		policyCounterName = policyCounterPub.Name()
	}

	// Create sealed object
	secret := []byte("secret data")

	template := tpm2_testutil.NewSealedObjectTemplate()

	policyData, policy, err := NewKeyDataPolicy(template.NameAlg, authKeyPublic, policyCounterPub, policyCount)
	c.Assert(err, IsNil)
	c.Assert(policyData, testutil.ConvertibleTo, &KeyDataPolicy_v3{})

	template.AuthPolicy = policy

	policyData.(*KeyDataPolicy_v3).PCRData = &PcrPolicyData_v3{
		PolicySequence:   policyData.PCRPolicySequence(),
		AuthorizedPolicy: make(tpm2.Digest, 32),
		AuthorizedPolicySignature: &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: &tpm2.SignatureU{
				ECDSA: &tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA256,
					SignatureR: make(tpm2.ECCParameter, 32),
					SignatureS: make(tpm2.ECCParameter, 32)}}}}

	sensitive := tpm2.SensitiveCreate{Data: secret}

	priv, pub, _, _, _, err := s.TPM().Create(s.primary, &sensitive, template, nil, nil, nil)
	c.Assert(err, IsNil)

	return &KeyData_v3{
		KeyPrivate: priv,
		KeyPublic:  pub,
		PolicyData: policyData.(*KeyDataPolicy_v3)}, policyCounterName
}

func (s *keyDataV3Suite) newMockImportableKeyData(c *C) KeyData {
	// Create the auth key
	authKey := make(secboot.PrimaryKey, 32)
	rand.Read(authKey)

	authKeyPublic := s.newPolicyAuthPublicKey(c, tpm2.HashAlgorithmSHA256, authKey)

	// Create sealed object
	secret := []byte("secret data")

	pub, sensitive := tpm2_testutil.NewExternalSealedObject(nil, secret)

	policyData, policy, err := NewKeyDataPolicy(pub.NameAlg, authKeyPublic, nil, 0)
	c.Assert(err, IsNil)
	c.Assert(policyData, testutil.ConvertibleTo, &KeyDataPolicy_v3{})

	pub.AuthPolicy = policy

	policyData.(*KeyDataPolicy_v3).PCRData = &PcrPolicyData_v3{
		Selection:        tpm2.PCRSelectionList{},
		OrData:           PolicyOrData_v0{},
		PolicySequence:   policyData.PCRPolicySequence(),
		AuthorizedPolicy: make(tpm2.Digest, 32),
		AuthorizedPolicySignature: &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: &tpm2.SignatureU{
				ECDSA: &tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA256,
					SignatureR: make(tpm2.ECCParameter, 32),
					SignatureS: make(tpm2.ECCParameter, 32)}}}}

	srkPub, _, _, err := s.TPM().ReadPublic(s.primary)
	c.Assert(err, IsNil)

	_, priv, symSeed, err := util.CreateDuplicationObject(sensitive, pub, srkPub, nil, nil)
	c.Assert(err, IsNil)

	return &KeyData_v3{
		KeyPrivate:       priv,
		KeyPublic:        pub,
		KeyImportSymSeed: symSeed,
		PolicyData:       policyData.(*KeyDataPolicy_v3)}
}

var _ = Suite(&keyDataV3Suite{})

func (s *keyDataV3Suite) TestVersion(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)
	c.Check(data.Version(), Equals, uint32(3))
}

func (s *keyDataV3Suite) TestSealedObjectData(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)
	c.Check(data.Private(), DeepEquals, data.(*KeyData_v3).KeyPrivate)
	c.Check(data.Public(), DeepEquals, data.(*KeyData_v3).KeyPublic)
}

func (s *keyDataV3Suite) TestImportNotImportable(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)
	private := data.Private()

	c.Check(data.ImportSymSeed(), IsNil)
	c.Check(func() { data.Imported(nil) }, PanicMatches, "does not need to be imported")
	c.Check(data.Private(), DeepEquals, private)
}

func (s *keyDataV3Suite) TestImportImportable(c *C) {
	data := s.newMockImportableKeyData(c)
	c.Check(data.ImportSymSeed(), DeepEquals, data.(*KeyData_v3).KeyImportSymSeed)

	priv, err := s.TPM().Import(s.primary, nil, data.Public(), data.Private(), data.ImportSymSeed(), nil, nil)
	c.Check(err, IsNil)
	data.Imported(priv)

	c.Check(data.Private(), DeepEquals, priv)
}

func (s *keyDataV3Suite) TestValidateImportable(c *C) {
	data := s.newMockImportableKeyData(c)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, ErrorMatches, "cannot validate importable key data")
}

func (s *keyDataV3Suite) TestValidateOK1(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter, IsNil)
}

func (s *keyDataV3Suite) TestValidateOK2(c *C) {
	data, pcrPolicyCounterName := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter.Name(), DeepEquals, pcrPolicyCounterName)
}

func (s *keyDataV3Suite) TestValidateOK3(c *C) {
	data, pcrPolicyCounterName := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x0180ff00))

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter.Name(), DeepEquals, pcrPolicyCounterName)
}

func (s *keyDataV3Suite) TestValidateImportedOK(c *C) {
	data := s.newMockImportableKeyData(c)
	c.Check(data.ImportSymSeed(), DeepEquals, data.(*KeyData_v3).KeyImportSymSeed)

	priv, err := s.TPM().Import(s.primary, nil, data.Public(), data.Private(), data.ImportSymSeed(), nil, nil)
	c.Check(err, IsNil)
	data.Imported(priv)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter, IsNil)
}

func (s *keyDataV3Suite) TestValidateInvalidAuthPublicKeyNameAlg(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	data.(*KeyData_v3).PolicyData.StaticData.AuthPublicKey.NameAlg = tpm2.HashAlgorithmNull

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "cannot compute name of dynamic authorization policy key: unsupported name algorithm or algorithm not linked into binary: TPM_ALG_NULL")
}

func (s *keyDataV3Suite) TestValidateInvalidAuthPublicKeyType(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	data.(*KeyData_v3).PolicyData.StaticData.AuthPublicKey.Type = tpm2.ObjectTypeRSA

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "public area of dynamic authorization policy signing key has the wrong type")
}

func (s *keyDataV3Suite) TestValidateInvalidAuthPublicKeyScheme1(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	data.(*KeyData_v3).PolicyData.StaticData.AuthPublicKey.Params.ECCDetail.Scheme = tpm2.ECCScheme{
		Scheme: tpm2.ECCSchemeECDAA,
		Details: &tpm2.AsymSchemeU{
			ECDAA: &tpm2.SigSchemeECDAA{HashAlg: tpm2.HashAlgorithmSHA256}}}

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "dynamic authorization policy signing key has unexpected scheme")
}

func (s *keyDataV3Suite) TestValidateInvalidAuthPublicKeyScheme2(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	data.(*KeyData_v3).PolicyData.StaticData.AuthPublicKey.Params.ECCDetail.Scheme = tpm2.ECCScheme{
		Scheme: tpm2.ECCSchemeECDSA,
		Details: &tpm2.AsymSchemeU{
			ECDSA: &tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA512}}}

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "dynamic authorization policy signing key algorithm must match name algorithm")
}

func (s *keyDataV3Suite) TestValidateInvalidPolicyCounterHandle(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	data.(*KeyData_v3).PolicyData.StaticData.PCRPolicyCounterHandle = 0x81000000

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "PCR policy counter handle is invalid")
}

func (s *keyDataV3Suite) TestValidateNoPolicyCounter(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	index, err := s.TPM().CreateResourceContextFromTPM(data.Policy().PCRPolicyCounterHandle())
	c.Assert(err, IsNil)
	c.Check(s.TPM().NVUndefineSpace(s.TPM().OwnerHandleContext(), index, nil), IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err = data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "PCR policy counter is unavailable")
}

func (s *keyDataV3Suite) TestValidateInvalidSealedObjectNameAlg(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	data.Public().NameAlg = tpm2.HashAlgorithmNull

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "cannot determine if static authorization policy matches sealed key object: algorithm unavailable")
}

func (s *keyDataV3Suite) TestValidateWrongAuthKey(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)
	data.(*KeyData_v3).PolicyData.StaticData.AuthPublicKey = util.NewExternalECCPublicKeyWithDefaults(templates.KeyUsageSign, &authKey.PublicKey)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err = data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}

func (s *keyDataV3Suite) TestValidateWrongPolicyCounter1(c *C) {
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
	_, err = data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}

func (s *keyDataV3Suite) TestValidateWrongPolicyCounter2(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	data.(*KeyData_v3).PolicyData.StaticData.PCRPolicyCounterHandle = tpm2.HandleNull

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}

func (s *keyDataV3Suite) TestValidateWrongPolicyCounter3(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	nvPub := tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x01800000),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		Size:    8}
	s.NVDefineSpace(c, tpm2.HandleOwner, nil, &nvPub)
	data.(*KeyData_v3).PolicyData.StaticData.PCRPolicyCounterHandle = nvPub.Index

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}

func (s *keyDataV3Suite) TestSerialization(c *C) {
	data1, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	buf := new(bytes.Buffer)
	c.Check(data1.Write(buf), IsNil)

	data2, err := ReadKeyDataV3(buf)
	c.Assert(err, IsNil)
	c.Check(data2, tpm2_testutil.TPMValueDeepEquals, data1)
}
