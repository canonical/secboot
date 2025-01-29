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
	"github.com/canonical/go-tpm2/objectutil"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

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

func (s *keyDataV3Suite) newMockKeyData(c *C, pcrPolicyCounterHandle tpm2.Handle, role string, requireAuthValue bool) (KeyData, tpm2.Name) {
	// Create the auth key
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)

	authPublicKey := s.newPolicyAuthPublicKey(c, tpm2.HashAlgorithmSHA256, primaryKey)

	// Create a mock PCR policy counter
	var pcrPolicyCounterPub *tpm2.NVPublic
	var policyCounterName tpm2.Name
	var policyCount uint64
	if pcrPolicyCounterHandle != tpm2.HandleNull {
		var err error
		pcrPolicyCounterPub, err = EnsurePcrPolicyCounter(s.TPM().TPMContext, pcrPolicyCounterHandle, authPublicKey, s.TPM().HmacSession())
		c.Assert(err, IsNil)
		policyCounterName = pcrPolicyCounterPub.Name()

		context, err := tpm2.NewNVIndexResourceContextFromPub(pcrPolicyCounterPub)
		c.Assert(err, IsNil)
		policyCount, err = s.TPM().NVReadCounter(context, context, nil)
		c.Assert(err, IsNil)
	}

	// Create sealed object
	secret := []byte("secret data")

	template := tpm2_testutil.NewSealedObjectTemplate()

	policyData, policyDigest, err := NewKeyDataPolicy(template.NameAlg, authPublicKey, role, pcrPolicyCounterPub, requireAuthValue)
	c.Assert(err, IsNil)
	c.Assert(policyData, testutil.ConvertibleTo, &KeyDataPolicy_v3{})

	template.AuthPolicy = policyDigest

	policyData.(*KeyDataPolicy_v3).PCRData = NewPcrPolicyData_v3(
		&PcrPolicyData_v2{
			PolicySequence:   policyCount,
			AuthorizedPolicy: make(tpm2.Digest, 32),
			AuthorizedPolicySignature: &tpm2.Signature{
				SigAlg: tpm2.SigSchemeAlgECDSA,
				Signature: &tpm2.SignatureU{
					ECDSA: &tpm2.SignatureECDSA{
						Hash:       tpm2.HashAlgorithmSHA256,
						SignatureR: make(tpm2.ECCParameter, 32),
						SignatureS: make(tpm2.ECCParameter, 32)}}}})

	sensitive := tpm2.SensitiveCreate{Data: secret}

	priv, pub, _, _, _, err := s.TPM().Create(s.primary, &sensitive, template, nil, nil, nil)
	c.Assert(err, IsNil)

	return &KeyData_v3{
		KeyPrivate: priv,
		KeyPublic:  pub,
		PolicyData: policyData.(*KeyDataPolicy_v3)}, policyCounterName
}

func (s *keyDataV3Suite) newMockImportableKeyData(c *C, role string, requireAuthValue bool) KeyData {
	// Create the auth key
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)

	authPublicKey := s.newPolicyAuthPublicKey(c, tpm2.HashAlgorithmSHA256, primaryKey)

	// Create sealed object
	secret := []byte("secret data")

	pub, sensitive := tpm2_testutil.NewExternalSealedObject(nil, secret)

	policyData, policy, err := NewKeyDataPolicy(pub.NameAlg, authPublicKey, role, nil, requireAuthValue)
	c.Assert(err, IsNil)
	c.Assert(policyData, testutil.ConvertibleTo, &KeyDataPolicy_v3{})

	pub.AuthPolicy = policy

	policyData.(*KeyDataPolicy_v3).PCRData = NewPcrPolicyData_v3(
		&PcrPolicyData_v2{
			Selection:        tpm2.PCRSelectionList{},
			OrData:           PolicyOrData_v0{},
			PolicySequence:   0,
			AuthorizedPolicy: make(tpm2.Digest, 32),
			AuthorizedPolicySignature: &tpm2.Signature{
				SigAlg: tpm2.SigSchemeAlgECDSA,
				Signature: &tpm2.SignatureU{
					ECDSA: &tpm2.SignatureECDSA{
						Hash:       tpm2.HashAlgorithmSHA256,
						SignatureR: make(tpm2.ECCParameter, 32),
						SignatureS: make(tpm2.ECCParameter, 32)}}}})

	srkPub, _, _, err := s.TPM().ReadPublic(s.primary)
	c.Assert(err, IsNil)

	_, priv, symSeed, err := objectutil.CreateImportable(testutil.RandReader, sensitive, pub, srkPub, nil, nil)
	c.Assert(err, IsNil)

	return &KeyData_v3{
		KeyPrivate:       priv,
		KeyPublic:        pub,
		KeyImportSymSeed: symSeed,
		PolicyData:       policyData.(*KeyDataPolicy_v3)}
}

var _ = Suite(&keyDataV3Suite{})

func (s *keyDataV3Suite) TestVersion(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, "foo", false)
	c.Check(data.Version(), Equals, uint32(3))
}

func (s *keyDataV3Suite) TestSealedObjectData(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, "foo", false)
	c.Check(data.Private(), DeepEquals, data.(*KeyData_v3).KeyPrivate)
	c.Check(data.Public(), DeepEquals, data.(*KeyData_v3).KeyPublic)
}

func (s *keyDataV3Suite) TestImportNotImportable(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, "foo", false)
	private := data.Private()

	c.Check(data.ImportSymSeed(), IsNil)
	c.Check(func() { data.Imported(nil) }, PanicMatches, "does not need to be imported")
	c.Check(data.Private(), DeepEquals, private)
}

func (s *keyDataV3Suite) TestImportImportable(c *C) {
	data := s.newMockImportableKeyData(c, "foo", false)
	c.Check(data.ImportSymSeed(), DeepEquals, data.(*KeyData_v3).KeyImportSymSeed)

	priv, err := s.TPM().Import(s.primary, nil, data.Public(), data.Private(), data.ImportSymSeed(), nil, nil)
	c.Check(err, IsNil)
	data.Imported(priv)

	c.Check(data.Private(), DeepEquals, priv)
}

func (s *keyDataV3Suite) TestValidateImportable(c *C) {
	data := s.newMockImportableKeyData(c, "", false)

	_, err := data.ValidateData(s.TPM().TPMContext, nil)
	c.Check(err, ErrorMatches, "cannot validate importable key data")
}

func (s *keyDataV3Suite) TestValidateOK1(c *C) {
	role := "foo"
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, role, false)

	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, []byte(role))
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter, IsNil)
}

func (s *keyDataV3Suite) TestValidateOK2(c *C) {
	role := "foo"
	data, pcrPolicyCounterName := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000), role, false)

	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, []byte(role))
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter.Name(), DeepEquals, pcrPolicyCounterName)
}

func (s *keyDataV3Suite) TestValidateOK3(c *C) {
	role := "foo"
	data, pcrPolicyCounterName := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x0180ff00), role, false)

	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, []byte(role))
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter.Name(), DeepEquals, pcrPolicyCounterName)
}

func (s *keyDataV3Suite) TestValidateImportedOK(c *C) {
	role := "foo"
	data := s.newMockImportableKeyData(c, role, false)
	c.Check(data.ImportSymSeed(), DeepEquals, data.(*KeyData_v3).KeyImportSymSeed)

	priv, err := s.TPM().Import(s.primary, nil, data.Public(), data.Private(), data.ImportSymSeed(), nil, nil)
	c.Check(err, IsNil)
	data.Imported(priv)

	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, []byte(role))
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter, IsNil)
}

func (s *keyDataV3Suite) TestValidateInvalidAuthPublicKeyNameAlg(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, "", false)

	data.(*KeyData_v3).PolicyData.StaticData.AuthPublicKey.NameAlg = tpm2.HashAlgorithmNull

	_, err := data.ValidateData(s.TPM().TPMContext, nil)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "name algorithm for signing key is invalid or not available: TPM_ALG_NULL")
}

func (s *keyDataV3Suite) TestValidateInvalidAuthPublicKeyType(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, "", false)

	data.(*KeyData_v3).PolicyData.StaticData.AuthPublicKey.Type = tpm2.ObjectTypeRSA

	_, err := data.ValidateData(s.TPM().TPMContext, nil)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "public area of dynamic authorization policy signing key has the wrong type")
}

func (s *keyDataV3Suite) TestValidateInvalidAuthPublicKeyScheme1(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, "", false)

	data.(*KeyData_v3).PolicyData.StaticData.AuthPublicKey.Params.ECCDetail.Scheme = tpm2.ECCScheme{
		Scheme: tpm2.ECCSchemeECDAA,
		Details: &tpm2.AsymSchemeU{
			ECDAA: &tpm2.SigSchemeECDAA{HashAlg: tpm2.HashAlgorithmSHA256}}}

	_, err := data.ValidateData(s.TPM().TPMContext, nil)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "dynamic authorization policy signing key has unexpected scheme")
}

func (s *keyDataV3Suite) TestValidateInvalidAuthPublicKeyScheme2(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, "", false)

	data.(*KeyData_v3).PolicyData.StaticData.AuthPublicKey.Params.ECCDetail.Scheme = tpm2.ECCScheme{
		Scheme: tpm2.ECCSchemeECDSA,
		Details: &tpm2.AsymSchemeU{
			ECDSA: &tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA512}}}

	_, err := data.ValidateData(s.TPM().TPMContext, nil)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "dynamic authorization policy signing key algorithm must match name algorithm")
}

func (s *keyDataV3Suite) TestValidateInvalidPolicyCounterHandle(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, "", false)

	data.(*KeyData_v3).PolicyData.StaticData.PCRPolicyCounterHandle = 0x81000000

	_, err := data.ValidateData(s.TPM().TPMContext, nil)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "PCR policy counter handle is invalid")
}

func (s *keyDataV3Suite) TestValidateNoPolicyCounter(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000), "", false)

	index, err := s.TPM().NewResourceContext(data.Policy().PCRPolicyCounterHandle())
	c.Assert(err, IsNil)
	c.Check(s.TPM().NVUndefineSpace(s.TPM().OwnerHandleContext(), index, nil), IsNil)

	_, err = data.ValidateData(s.TPM().TPMContext, nil)
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "PCR policy counter is unavailable")
}

func (s *keyDataV3Suite) TestValidateInvalidSealedObjectNameAlg(c *C) {
	role := "foo"
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, role, false)

	data.Public().NameAlg = tpm2.HashAlgorithmNull

	_, err := data.ValidateData(s.TPM().TPMContext, []byte(role))
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "cannot determine if static authorization policy matches sealed key object: algorithm TPM_ALG_NULL unavailable")
}

func (s *keyDataV3Suite) TestValidateWrongAuthKey(c *C) {
	role := "foo"
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, role, true)

	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)
	authPublicKey, err := objectutil.NewECCPublicKey(&authKey.PublicKey)
	c.Assert(err, IsNil)
	data.(*KeyData_v3).PolicyData.StaticData.AuthPublicKey = authPublicKey

	_, err = data.ValidateData(s.TPM().TPMContext, []byte(role))
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}

func (s *keyDataV3Suite) TestValidateWrongPolicyCounter1(c *C) {
	role := "foo"
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000), role, false)

	index, err := s.TPM().NewResourceContext(data.Policy().PCRPolicyCounterHandle())
	handle := index.Handle()
	c.Assert(err, IsNil)
	c.Check(s.TPM().NVUndefineSpace(s.TPM().OwnerHandleContext(), index, nil), IsNil)

	nvPub := tpm2.NVPublic{
		Index:   handle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVPolicyRead | tpm2.AttrNVNoDA),
		Size:    8}
	s.NVDefineSpace(c, tpm2.HandleOwner, nil, &nvPub)

	_, err = data.ValidateData(s.TPM().TPMContext, []byte(role))
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "unexpected PCR policy ref")
}

func (s *keyDataV3Suite) TestValidateWrongPolicyCounter2(c *C) {
	role := "foo"
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000), role, false)

	data.(*KeyData_v3).PolicyData.StaticData.PCRPolicyCounterHandle = tpm2.HandleNull

	_, err := data.ValidateData(s.TPM().TPMContext, []byte(role))
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "unexpected PCR policy ref")
}

func (s *keyDataV3Suite) TestValidateWrongPolicyCounter3(c *C) {
	role := "foo"
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, role, false)

	nvPub := tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x01800000),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		Size:    8}
	s.NVDefineSpace(c, tpm2.HandleOwner, nil, &nvPub)
	data.(*KeyData_v3).PolicyData.StaticData.PCRPolicyCounterHandle = nvPub.Index

	_, err := data.ValidateData(s.TPM().TPMContext, []byte(role))
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "unexpected PCR policy ref")
}

func (s *keyDataV3Suite) TestSerialization(c *C) {
	data1, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000), "foo", false)

	buf := new(bytes.Buffer)
	c.Check(data1.Write(buf), IsNil)

	data2, err := ReadKeyDataV3(buf)
	c.Assert(err, IsNil)
	c.Check(data2, tpm2_testutil.TPMValueDeepEquals, data1)
}

func (s *keyDataV3Suite) TestValidateInvalidRole(c *C) {
	authRole := "foo"
	validationRole := "bar"
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, authRole, false)

	_, err := data.ValidateData(s.TPM().TPMContext, []byte(validationRole))
	c.Check(err, ErrorMatches, "unexpected PCR policy ref")
}

func (s *keyDataV3Suite) TestValidateWrongAuthValueRequirement(c *C) {
	role := "foo"
	data, _ := s.newMockKeyData(c, tpm2.HandleNull, role, true)

	data.(*KeyData_v3).PolicyData.StaticData.RequireAuthValue = false

	_, err := data.ValidateData(s.TPM().TPMContext, []byte(role))
	c.Check(err, testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}
