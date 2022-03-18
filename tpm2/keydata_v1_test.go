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
	"crypto/ecdsa"
	"crypto/elliptic"

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

type keyDataV1Suite struct {
	tpm2test.TPMTest
	primary tpm2.ResourceContext
}

func (s *keyDataV1Suite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy | tpm2test.TPMFeatureNV
}

func (s *keyDataV1Suite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)

	primary := s.CreateStoragePrimaryKeyRSA(c)
	s.primary = s.EvictControl(c, tpm2.HandleOwner, primary, tcg.SRKHandle)
}

func (s *keyDataV1Suite) newMockKeyData(c *C, pcrPolicyCounterHandle tpm2.Handle) (KeyData, tpm2.Name) {
	// Create the elliptic auth key
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)

	authKeyPublic := util.NewExternalECCPublicKeyWithDefaults(templates.KeyUsageSign, &authKey.PublicKey)
	mu.MustCopyValue(&authKeyPublic, authKeyPublic)
	authKeyName, err := authKeyPublic.Name()
	c.Assert(err, IsNil)

	// Create a mock PCR policy counter
	var policyCounterName tpm2.Name
	var count uint64
	if pcrPolicyCounterHandle != tpm2.HandleNull {
		var nvPub *tpm2.NVPublic
		nvPub, count, err = CreatePcrPolicyCounter(s.TPM().TPMContext, pcrPolicyCounterHandle, authKeyPublic, s.TPM().HmacSession())
		c.Assert(err, IsNil)
		policyCounterName, err = nvPub.Name()
		c.Check(err, IsNil)
	}

	// Create sealed object
	secret := []byte("secret data")

	template := tpm2_testutil.NewSealedObjectTemplate()

	trial := util.ComputeAuthPolicy(template.NameAlg)
	trial.PolicyAuthorize(ComputeV1PcrPolicyRefFromCounterName(policyCounterName), authKeyName)
	trial.PolicyAuthValue()

	template.AuthPolicy = trial.GetDigest()

	sensitive := tpm2.SensitiveCreate{Data: secret}

	priv, pub, _, _, _, err := s.TPM().Create(s.primary, &sensitive, template, nil, nil, nil)
	c.Assert(err, IsNil)

	return &KeyData_v1{
		KeyPrivate: priv,
		KeyPublic:  pub,
		StaticPolicyData: &StaticPolicyDataRaw_v1{
			AuthPublicKey:          authKeyPublic,
			PCRPolicyCounterHandle: pcrPolicyCounterHandle},
		DynamicPolicyData: &DynamicPolicyDataRaw_v0{
			PCRSelection:     tpm2.PCRSelectionList{},
			PCROrData:        PolicyOrData_v0{},
			PolicyCount:      count,
			AuthorizedPolicy: make(tpm2.Digest, 32),
			AuthorizedPolicySignature: &tpm2.Signature{
				SigAlg: tpm2.SigSchemeAlgECDSA,
				Signature: &tpm2.SignatureU{
					ECDSA: &tpm2.SignatureECDSA{
						Hash:       tpm2.HashAlgorithmSHA256,
						SignatureR: make(tpm2.ECCParameter, 32),
						SignatureS: make(tpm2.ECCParameter, 32)}}}}}, policyCounterName
}

var _ = Suite(&keyDataV1Suite{})

func (s *keyDataV1Suite) TestVersion(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)
	c.Check(data.Version(), Equals, uint32(1))
}

func (s *keyDataV1Suite) TestSealedObjectData(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)
	c.Check(data.Private(), DeepEquals, data.(*KeyData_v1).KeyPrivate)
	c.Check(data.Public(), DeepEquals, data.(*KeyData_v1).KeyPublic)
}

func (s *keyDataV1Suite) TestNoImport(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)
	private := data.Private()

	c.Check(data.ImportSymSeed(), IsNil)
	c.Check(func() { data.Imported(nil) }, PanicMatches, "not supported")
	c.Check(data.Private(), DeepEquals, private)
}

func (s *keyDataV1Suite) TestValidateOK1(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter, IsNil)
}

func (s *keyDataV1Suite) TestValidateOK2(c *C) {
	data, pcrPolicyCounterName := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter.Name(), DeepEquals, pcrPolicyCounterName)
}

func (s *keyDataV1Suite) TestValidateOK3(c *C) {
	data, pcrPolicyCounterName := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x0180ff00))

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter.Name(), DeepEquals, pcrPolicyCounterName)
}

func (s *keyDataV1Suite) TestValidateInvalidAuthPublicKeyNameAlg(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	data.(*KeyData_v1).StaticPolicyData.AuthPublicKey.NameAlg = tpm2.HashAlgorithmNull

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, tpm2_testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "cannot compute name of dynamic authorization policy key: unsupported name algorithm or algorithm not linked into binary: TPM_ALG_NULL")
}

func (s *keyDataV1Suite) TestValidateInvalidAuthPublicKeyType(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	data.(*KeyData_v1).StaticPolicyData.AuthPublicKey.Type = tpm2.ObjectTypeRSA

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, tpm2_testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "public area of dynamic authorization policy signing key has the wrong type")
}

func (s *keyDataV1Suite) TestValidateInvalidAuthPublicKeyScheme(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	data.(*KeyData_v1).StaticPolicyData.AuthPublicKey.Params.ECCDetail.Scheme = tpm2.ECCScheme{
		Scheme: tpm2.ECCSchemeECDAA,
		Details: &tpm2.AsymSchemeU{
			ECDAA: &tpm2.SigSchemeECDAA{HashAlg: tpm2.HashAlgorithmSHA256}}}

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, tpm2_testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "dynamic authorization policy signing key has unexpected scheme")
}

func (s *keyDataV1Suite) TestValidateInvalidPolicyCounterHandle(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	data.(*KeyData_v1).StaticPolicyData.PCRPolicyCounterHandle = 0x81000000

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, tpm2_testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "PCR policy counter handle is invalid")
}

func (s *keyDataV1Suite) TestValidateNoPolicyCounter(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	index, err := s.TPM().CreateResourceContextFromTPM(data.PcrPolicyCounterHandle())
	c.Assert(err, IsNil)
	c.Check(s.TPM().NVUndefineSpace(s.TPM().OwnerHandleContext(), index, nil), IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err = data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, tpm2_testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "PCR policy counter is unavailable")
}

func (s *keyDataV1Suite) TestValidateInvalidSealedObjectNameAlg(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	data.Public().NameAlg = tpm2.HashAlgorithmNull

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, tpm2_testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "cannot determine if static authorization policy matches sealed key object: algorithm unavailable")
}

func (s *keyDataV1Suite) TestValidateWrongAuthKey(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)
	data.(*KeyData_v1).StaticPolicyData.AuthPublicKey = util.NewExternalECCPublicKeyWithDefaults(templates.KeyUsageSign, &authKey.PublicKey)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err = data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, tpm2_testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}

func (s *keyDataV1Suite) TestValidateWrongPolicyCounter1(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	index, err := s.TPM().CreateResourceContextFromTPM(data.PcrPolicyCounterHandle())
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
	c.Check(err, tpm2_testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}

func (s *keyDataV1Suite) TestValidateWrongPolicyCounter2(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	data.(*KeyData_v1).StaticPolicyData.PCRPolicyCounterHandle = tpm2.HandleNull

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, tpm2_testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}

func (s *keyDataV1Suite) TestValidateWrongPolicyCounter3(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	nvPub := tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x01800000),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
		Size:    8}
	s.NVDefineSpace(c, tpm2.HandleOwner, nil, &nvPub)
	data.(*KeyData_v1).StaticPolicyData.PCRPolicyCounterHandle = nvPub.Index

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256).WithAttrs(tpm2.AttrContinueSession)
	_, err := data.ValidateData(s.TPM().TPMContext, session)
	c.Check(err, tpm2_testutil.ConvertibleTo, KeyDataError{})
	c.Check(err, ErrorMatches, "the sealed key object's authorization policy is inconsistent with the associated metadata or persistent TPM resources")
}

func (s *keyDataV1Suite) TestSerialization(c *C) {
	data1, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	buf := new(bytes.Buffer)
	c.Check(data1.Write(buf), IsNil)

	data2, err := ReadKeyDataV1(buf)
	c.Assert(err, IsNil)
	c.Check(data2, DeepEquals, data1)
}
