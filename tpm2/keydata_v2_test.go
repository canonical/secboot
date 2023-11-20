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

type keyDataV2Suite struct {
	tpm2test.TPMTest
	primary tpm2.ResourceContext
}

func (s *keyDataV2Suite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy | tpm2test.TPMFeatureNV
}

func (s *keyDataV2Suite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)

	primary := s.CreateStoragePrimaryKeyRSA(c)
	s.primary = s.EvictControl(c, tpm2.HandleOwner, primary, tcg.SRKHandle)
}

func (s *keyDataV2Suite) newMockKeyData(c *C, pcrPolicyCounterHandle tpm2.Handle) (KeyData, tpm2.Name) {
	// Create the elliptic auth key
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)

	authKeyPublic := util.NewExternalECCPublicKeyWithDefaults(templates.KeyUsageSign, &authKey.PublicKey)
	mu.MustCopyValue(&authKeyPublic, authKeyPublic)

	// Create a mock PCR policy counter
	var policyCounterPub *tpm2.NVPublic
	var policyCount uint64
	var policyCounterName tpm2.Name
	if pcrPolicyCounterHandle != tpm2.HandleNull {
		policyCounterPub, policyCount, err = CreatePcrPolicyCounter(s.TPM().TPMContext, pcrPolicyCounterHandle, authKeyPublic, s.TPM().HmacSession())
		c.Assert(err, IsNil)
		policyCounterName = policyCounterPub.Name()
	}

	// Create sealed object
	secret := []byte("secret data")

	template := tpm2_testutil.NewSealedObjectTemplate()

	policyData, policy, err := NewKeyDataPolicyLegacy(template.NameAlg, authKeyPublic, policyCounterPub, policyCount)
	c.Assert(err, IsNil)
	c.Assert(policyData, testutil.ConvertibleTo, &KeyDataPolicy_v2{})

	template.AuthPolicy = policy

	policyData.(*KeyDataPolicy_v2).PCRData = &PcrPolicyData_v2{
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

	return &KeyData_v2{
		KeyPrivate: priv,
		KeyPublic:  pub,
		PolicyData: policyData.(*KeyDataPolicy_v2)}, policyCounterName
}

func (s *keyDataV2Suite) newMockImportableKeyData(c *C) KeyData {
	// Create the elliptic auth key
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)

	authKeyPublic := util.NewExternalECCPublicKeyWithDefaults(templates.KeyUsageSign, &authKey.PublicKey)
	mu.MustCopyValue(&authKeyPublic, authKeyPublic)

	// Create sealed object
	secret := []byte("secret data")

	pub, sensitive := tpm2_testutil.NewExternalSealedObject(nil, secret)
	mu.MustCopyValue(&pub, pub)

	policyData, policy, err := NewKeyDataPolicyLegacy(pub.NameAlg, authKeyPublic, nil, 0)
	c.Assert(err, IsNil)
	c.Assert(policyData, testutil.ConvertibleTo, &KeyDataPolicy_v2{})

	pub.AuthPolicy = policy

	policyData.(*KeyDataPolicy_v2).PCRData = &PcrPolicyData_v2{
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

	return &KeyData_v2{
		KeyPrivate:       priv,
		KeyPublic:        pub,
		KeyImportSymSeed: symSeed,
		PolicyData:       policyData.(*KeyDataPolicy_v2)}
}

var _ = Suite(&keyDataV2Suite{})

func (s *keyDataV2Suite) TestVersionNonImportable(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)
	c.Check(data.Version(), Equals, uint32(1))
}

func (s *keyDataV2Suite) TestVersionImportable(c *C) {
	data := s.newMockImportableKeyData(c)
	c.Check(data.Version(), Equals, uint32(2))
}

func (s *keyDataV2Suite) TestSealedObjectData(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)
	c.Check(data.Private(), DeepEquals, data.(*KeyData_v2).KeyPrivate)
	c.Check(data.Public(), DeepEquals, data.(*KeyData_v2).KeyPublic)
}

func (s *keyDataV2Suite) TestImportNotImportable(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)
	private := data.Private()

	c.Check(data.ImportSymSeed(), IsNil)
	c.Check(func() { data.Imported(nil) }, PanicMatches, "does not need to be imported")
	c.Check(data.Private(), DeepEquals, private)
}

func (s *keyDataV2Suite) TestImportImportable(c *C) {
	data := s.newMockImportableKeyData(c)
	c.Check(data.ImportSymSeed(), DeepEquals, data.(*KeyData_v2).KeyImportSymSeed)

	priv, err := s.TPM().Import(s.primary, nil, data.Public(), data.Private(), data.ImportSymSeed(), nil, nil)
	c.Check(err, IsNil)
	data.Imported(priv)

	c.Check(data.Version(), Equals, uint32(1))
	c.Check(data.Private(), DeepEquals, priv)
}

func (s *keyDataV2Suite) TestValidateImportable(c *C) {
	data := s.newMockImportableKeyData(c)

	_, err := data.ValidateData(s.TPM().TPMContext)
	c.Check(err, ErrorMatches, "cannot validate importable key data")
}

func (s *keyDataV2Suite) TestValidateOK1(c *C) {
	data, _ := s.newMockKeyData(c, tpm2.HandleNull)

	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter, IsNil)
}

func (s *keyDataV2Suite) TestValidateOK2(c *C) {
	data, pcrPolicyCounterName := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter.Name(), DeepEquals, pcrPolicyCounterName)
}

func (s *keyDataV2Suite) TestValidateOK3(c *C) {
	data, pcrPolicyCounterName := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x0180ff00))

	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter.Name(), DeepEquals, pcrPolicyCounterName)
}

func (s *keyDataV2Suite) TestValidateImportedOK(c *C) {
	data := s.newMockImportableKeyData(c)
	c.Check(data.ImportSymSeed(), DeepEquals, data.(*KeyData_v2).KeyImportSymSeed)

	priv, err := s.TPM().Import(s.primary, nil, data.Public(), data.Private(), data.ImportSymSeed(), nil, nil)
	c.Check(err, IsNil)
	data.Imported(priv)

	pcrPolicyCounter, err := data.ValidateData(s.TPM().TPMContext)
	c.Check(err, IsNil)
	c.Check(pcrPolicyCounter, IsNil)
}

func (s *keyDataV2Suite) TestSerializationNonImportable(c *C) {
	data1, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	buf := new(bytes.Buffer)
	c.Check(data1.Write(buf), IsNil)

	// If it is not importable, it is serialized as v1
	data2, err := ReadKeyDataV1(buf)
	c.Assert(err, IsNil)
	c.Check(data2.(*KeyData_v1), DeepEquals, data1.(*KeyData_v2).AsV1())
}

func (s *keyDataV2Suite) TestSerializationImportable(c *C) {
	data1 := s.newMockImportableKeyData(c)

	buf := new(bytes.Buffer)
	c.Check(data1.Write(buf), IsNil)

	data2, err := ReadKeyDataV2(buf)
	c.Assert(err, IsNil)
	c.Check(data2, DeepEquals, data1)
}

func (s *keyDataV2Suite) TestReadNonImportableAsV2Fails(c *C) {
	data, _ := s.newMockKeyData(c, s.NextAvailableHandle(c, 0x01800000))

	// The V2 reader will read a size of 35-bytes for the import seed if
	// it's fed V1 data (from the type field of the auth key, which is 0x0023).
	// This means it will read the size field of the auth policy digest from
	// somewhere inside the auth policy digest. Fill the digest with 1s in
	// order to trigger a reproduceable error, and test that for fun!
	data.(*KeyData_v2).PolicyData.StaticData.AuthPublicKey.AuthPolicy = testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	buf := new(bytes.Buffer)
	c.Check(data.Write(buf), IsNil)

	_, err := ReadKeyDataV2(buf)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type tpm2.Digest: unexpected EOF\n\n"+
		"=== BEGIN STACK ===\n"+
		"... tpm2.Public field AuthPolicy\n"+
		"... tpm2.staticPolicyData_v1 field AuthPublicKey\n"+
		"... tpm2.keyDataPolicy_v1 field StaticData\n"+
		"... tpm2.keyData_v2 field PolicyData\n"+
		"=== END STACK ===\n")
}
