// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2022 Canonical Ltd
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
	"crypto/aes"
	"crypto/cipher"
	_ "crypto/sha256"
	"errors"
	"math/rand"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/templates"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type sealSuite struct {
	tpm2test.TPMTest
	primaryKeyMixin
}

func (s *sealSuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeatureLockoutHierarchy | // Allow the test fixture to reset the DA counter
		tpm2test.TPMFeaturePCR |
		tpm2test.TPMFeatureNV
}

func (s *sealSuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)

	s.primaryKeyMixin.tpmTest = &s.TPMTest.TPMTest
	c.Assert(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil),
		testutil.InSlice(Equals), []error{ErrTPMProvisioningRequiresLockout, nil})
}

var _ = Suite(&sealSuite{})

func (s *sealSuite) testProtectKeyWithTPM(c *C, params *ProtectKeyParams) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	k, authKey, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	for _, model := range params.AuthorizedSnapModels {
		ok, err := k.IsSnapModelAuthorized(authKey, model)
		c.Check(err, IsNil)
		c.Check(ok, testutil.IsTrue)
	}

	skd, err := NewSealedKeyData(k)
	c.Assert(err, IsNil)
	c.Check(skd.Validate(s.TPM().TPMContext, authKey, s.TPM().HmacSession()), IsNil)

	c.Check(skd.Version(), Equals, uint32(3))
	c.Check(skd.PCRPolicyCounterHandle(), Equals, params.PCRPolicyCounterHandle)

	policyAuthPublicKey, err := NewPolicyAuthPublicKey(authKey)
	c.Assert(err, IsNil)

	var pcrPolicyCounterPub *tpm2.NVPublic
	var pcrPolicySequence uint64
	if params.PCRPolicyCounterHandle != tpm2.HandleNull {
		index, err := s.TPM().CreateResourceContextFromTPM(params.PCRPolicyCounterHandle)
		c.Assert(err, IsNil)

		pcrPolicyCounterPub, _, err = s.TPM().NVReadPublic(index)
		c.Check(err, IsNil)

		pcrPolicySequence, err = s.TPM().NVReadCounter(index, index, nil)
		c.Check(err, IsNil)
	}

	expectedPolicyData, expectedPolicyDigest, err := NewKeyDataPolicy(tpm2.HashAlgorithmSHA256, policyAuthPublicKey, pcrPolicyCounterPub, pcrPolicySequence)
	c.Assert(err, IsNil)

	c.Check(skd.Data().Public().NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(skd.Data().Public().AuthPolicy, DeepEquals, expectedPolicyDigest)
	c.Check(skd.Data().Policy().(*KeyDataPolicy_v3).StaticData, tpm2_testutil.TPMValueDeepEquals, expectedPolicyData.(*KeyDataPolicy_v3).StaticData)

	if params.AuthKey != nil {
		c.Check(authKey, DeepEquals, params.AuthKey)
	}

	keyUnsealed, authKeyUnsealed, err := k.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)

	if params.PCRProfile != nil {
		// Verify that the key is sealed with the supplied PCR profile by changing
		// the PCR values.
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
		c.Check(err, IsNil)
		_, _, err = k.RecoverKeys()
		c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
			"cannot execute PolicyOR assertions: current session digest not found in policy data")
	}

	if params.PCRPolicyCounterHandle != tpm2.HandleNull {
		c.Check(s.TPM().DoesHandleExist(params.PCRPolicyCounterHandle), testutil.IsTrue)
	}
}

func (s *sealSuite) TestProtectKeyWithTPM(c *C) {
	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}})
}

func (s *sealSuite) TestProtectKeyWithTPMDifferentPCRPolicyCounterHandle(c *C) {
	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}})
}

func (s *sealSuite) TestProtectKeyWithTPMWithNewConnection(c *C) {
	// ProtectKeyWithTPM behaves slightly different if called immediately after
	// EnsureProvisioned with the same Connection
	s.ReinitTPMConnectionFromExisting(c)

	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}})

	s.validateSRK(c)
}

func (s *sealSuite) TestProtectKeyWithTPMMissingSRK(c *C) {
	// Ensure that calling ProtectKeyWithTPM recreates the SRK with the standard template
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

	s.ReinitTPMConnectionFromExisting(c)

	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}})

	s.validateSRK(c)
}

func (s *sealSuite) TestProtectKeyWithTPMMissingCustomSRK(c *C) {
	// Ensure that calling ProtectKeyWithTPM recreates the SRK with the custom
	// template originally supplied during provisioning
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

	template := &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA |
			tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
	tmplBytes := mu.MustMarshalToBytes(template)

	nvPub := tpm2.NVPublic{
		Index:   SrkTemplateHandle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVOwnerRead | tpm2.AttrNVNoDA),
		Size:    uint16(len(tmplBytes))}
	nv := s.NVDefineSpace(c, tpm2.HandleOwner, nil, &nvPub)
	c.Check(s.TPM().NVWrite(nv, nv, tmplBytes, 0, nil), IsNil)

	s.ReinitTPMConnectionFromExisting(c)

	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}})

	s.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, template)
}

func (s *sealSuite) TestProtectKeyWithTPMMissingSRKWithInvalidCustomTemplate(c *C) {
	// Ensure that calling ProtectKeyWithTPM recreates the SRK with the standard
	// template if the NV index we use to store custom templates has invalid
	// contents - if the contents are invalid then we didn't create it.
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

	template := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA |
			tpm2.AttrRestricted | tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.RSAScheme{
					Scheme: tpm2.RSASchemeRSAPSS,
					Details: &tpm2.AsymSchemeU{
						RSAPSS: &tpm2.SigSchemeRSAPSS{HashAlg: tpm2.HashAlgorithmSHA256},
					},
				},
				KeyBits:  2048,
				Exponent: 0}}}
	tmplBytes := mu.MustMarshalToBytes(template)

	nvPub := tpm2.NVPublic{
		Index:   SrkTemplateHandle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVOwnerRead | tpm2.AttrNVNoDA),
		Size:    uint16(len(tmplBytes))}
	nv := s.NVDefineSpace(c, tpm2.HandleOwner, nil, &nvPub)
	c.Check(s.TPM().NVWrite(nv, nv, tmplBytes, 0, nil), IsNil)

	s.ReinitTPMConnectionFromExisting(c)

	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}})

	s.validateSRK(c)
}

func (s *sealSuite) TestProtectKeyWithTPMNilPCRProfileAndNoAuthorizedSnapModels(c *C) {
	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
}

func (s *sealSuite) TestProtectKeyWithTPMNoPCRPolicyCounterHandle(c *C) {
	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}})
}

func (s *sealSuite) TestProtectKeyWithTPMWithProvidedAuthKey(c *C) {
	authKey := make(secboot.PrimaryKey, 32)
	rand.Read(authKey)

	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")},
		AuthKey: authKey})
}

type testProtectKeysWithTPMData struct {
	n      int
	params *ProtectKeyParams
}

func (s *sealSuite) testProtectKeysWithTPM(c *C, data *testProtectKeysWithTPMData) {
	var keys []secboot.DiskUnlockKey
	for i := 0; i < data.n; i++ {
		key := make(secboot.DiskUnlockKey, 32)
		rand.Read(key)

		keys = append(keys, key)
	}

	protectedKeys, authKey, err := ProtectKeysWithTPM(s.TPM(), keys, data.params)
	c.Check(err, IsNil)
	c.Check(protectedKeys, HasLen, data.n)

	policyAuthPublicKey, err := NewPolicyAuthPublicKey(authKey)
	c.Assert(err, IsNil)

	var pcrPolicyCounterPub *tpm2.NVPublic
	var pcrPolicySequence uint64
	if data.params.PCRPolicyCounterHandle != tpm2.HandleNull {
		index, err := s.TPM().CreateResourceContextFromTPM(data.params.PCRPolicyCounterHandle)
		c.Assert(err, IsNil)

		pcrPolicyCounterPub, _, err = s.TPM().NVReadPublic(index)
		c.Check(err, IsNil)

		pcrPolicySequence, err = s.TPM().NVReadCounter(index, index, nil)
		c.Check(err, IsNil)
	}

	expectedPolicyData, expectedPolicyDigest, err := NewKeyDataPolicy(tpm2.HashAlgorithmSHA256, policyAuthPublicKey, pcrPolicyCounterPub, pcrPolicySequence)
	c.Assert(err, IsNil)

	for i, k := range protectedKeys {
		for _, model := range data.params.AuthorizedSnapModels {
			ok, err := k.IsSnapModelAuthorized(authKey, model)
			c.Check(err, IsNil)
			c.Check(ok, testutil.IsTrue)
		}

		skd, err := NewSealedKeyData(k)
		c.Assert(err, IsNil)
		c.Check(skd.Validate(s.TPM().TPMContext, authKey, s.TPM().HmacSession()), IsNil)

		c.Check(skd.Version(), Equals, uint32(3))
		c.Check(skd.PCRPolicyCounterHandle(), Equals, data.params.PCRPolicyCounterHandle)

		c.Check(skd.Data().Public().NameAlg, Equals, tpm2.HashAlgorithmSHA256)
		c.Check(skd.Data().Public().AuthPolicy, DeepEquals, expectedPolicyDigest)
		c.Check(skd.Data().Policy().(*KeyDataPolicy_v3).StaticData, tpm2_testutil.TPMValueDeepEquals, expectedPolicyData.(*KeyDataPolicy_v3).StaticData)

		keyUnsealed, authKeyUnsealed, err := k.RecoverKeys()
		c.Check(err, IsNil)
		c.Check(keyUnsealed, DeepEquals, keys[i])
		c.Check(authKeyUnsealed, DeepEquals, authKey)
	}

	if data.params.AuthKey != nil {
		c.Check(authKey, DeepEquals, data.params.AuthKey)
	}

	if data.params.PCRProfile != nil {
		// Verify that the keys are sealed with the supplied PCR profile by changing
		// the PCR values.
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
		c.Check(err, IsNil)

		for _, k := range protectedKeys {
			_, _, err = k.RecoverKeys()
			c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
				"cannot execute PolicyOR assertions: current session digest not found in policy data")
		}
	}
}

func (s *sealSuite) TestProtectKeysWithTPMSingle(c *C) {
	s.testProtectKeysWithTPM(c, &testProtectKeysWithTPMData{
		n: 1,
		params: &ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			AuthorizedSnapModels: []secboot.SnapModel{
				testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}}})
}

func (s *sealSuite) TestProtectKeysWithTPM2Keys(c *C) {
	s.testProtectKeysWithTPM(c, &testProtectKeysWithTPMData{
		n: 2,
		params: &ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			AuthorizedSnapModels: []secboot.SnapModel{
				testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}}})
}

func (s *sealSuite) TestProtectKeysWithTPMDifferentPCRPolicyCounterHandle(c *C) {
	s.testProtectKeysWithTPM(c, &testProtectKeysWithTPMData{
		n: 2,
		params: &ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
			AuthorizedSnapModels: []secboot.SnapModel{
				testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}}})
}

func (s *sealSuite) TestProtectKeysWithTPMWithNewConnection(c *C) {
	// ProtectKeysWithTPM behaves slightly different if called immediately
	// after EnsureProvisioned with the same Connection
	s.ReinitTPMConnectionFromExisting(c)

	s.testProtectKeysWithTPM(c, &testProtectKeysWithTPMData{
		n: 2,
		params: &ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			AuthorizedSnapModels: []secboot.SnapModel{
				testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}}})
}

func (s *sealSuite) TestProtectKeysWithTPMMissingSRK(c *C) {
	// Ensure that calling ProtectKeysWithTPM recreates the SRK with the standard
	// template
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

	s.ReinitTPMConnectionFromExisting(c)

	s.testProtectKeysWithTPM(c, &testProtectKeysWithTPMData{
		n: 2,
		params: &ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			AuthorizedSnapModels: []secboot.SnapModel{
				testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}}})

	s.validateSRK(c)
}

func (s *sealSuite) TestProtectKeyWithTPMMultipeNilPCRProfileAndNoAuthorizedSnapModels(c *C) {
	s.testProtectKeysWithTPM(c, &testProtectKeysWithTPMData{
		n: 2,
		params: &ProtectKeyParams{
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)}})
}

func (s *sealSuite) TestProtectKeysWithTPMNoPCRPolicyCounterHandle(c *C) {
	s.testProtectKeysWithTPM(c, &testProtectKeysWithTPMData{
		n: 2,
		params: &ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: tpm2.HandleNull,
			AuthorizedSnapModels: []secboot.SnapModel{
				testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}}})
}

func (s *sealSuite) TestProtectKeysWithTPMWithProvidedAuthKey(c *C) {
	authKey := make(secboot.PrimaryKey, 32)
	rand.Read(authKey)

	s.testProtectKeysWithTPM(c, &testProtectKeysWithTPMData{
		n: 2,
		params: &ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			AuthorizedSnapModels: []secboot.SnapModel{
				testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
					"authority-id": "fake-brand",
					"series":       "16",
					"brand-id":     "fake-brand",
					"model":        "fake-model",
					"grade":        "secured",
				}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")},
			AuthKey: authKey}})
}

func (s *sealSuite) testProtectKeyWithTPMErrorHandling(c *C, params *ProtectKeyParams) error {
	var origCounter tpm2.ResourceContext
	if params != nil && params.PCRPolicyCounterHandle != tpm2.HandleNull {
		var err error
		origCounter, err = s.TPM().CreateResourceContextFromTPM(params.PCRPolicyCounterHandle)
		if tpm2.IsResourceUnavailableError(err, params.PCRPolicyCounterHandle) {
			err = nil
		}
		c.Check(err, IsNil)
	}

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	_, _, sealErr := ProtectKeyWithTPM(s.TPM(), key, params)

	var counter tpm2.ResourceContext
	if params != nil && params.PCRPolicyCounterHandle != tpm2.HandleNull {
		var err error
		counter, err = s.TPM().CreateResourceContextFromTPM(params.PCRPolicyCounterHandle)
		if tpm2.IsResourceUnavailableError(err, params.PCRPolicyCounterHandle) {
			err = nil
		}
		c.Check(err, IsNil)
	}

	switch {
	case origCounter == nil:
		c.Check(counter, IsNil)
	case origCounter != nil:
		c.Assert(counter, NotNil)
		c.Check(counter.Name(), DeepEquals, origCounter.Name())
	}

	return sealErr
}

func (s *sealSuite) TestProtectKeyWithTPMErrorHandlingNilParams(c *C) {
	c.Check(s.testProtectKeyWithTPMErrorHandling(c, nil), ErrorMatches, "no ProtectKeyParams provided")
}

func (s *sealSuite) TestProtectKeyWithTPMErrorHandlingOwnerAuthFail(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
	s.TPM().OwnerHandleContext().SetAuthValue(nil)

	s.ReinitTPMConnectionFromExisting(c)

	err := s.testProtectKeyWithTPMErrorHandling(c, &ProtectKeyParams{
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Assert(err, testutil.ConvertibleTo, AuthFailError{})
	c.Check(err.(AuthFailError).Handle, Equals, tpm2.HandleOwner)
}

func (s *sealSuite) TestProtectKeyWithTPMErrorHandlingPCRPolicyCounterExists(c *C) {
	public := tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181ffff),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead),
		Size:    0}
	s.NVDefineSpace(c, tpm2.HandleOwner, nil, &public)

	err := s.testProtectKeyWithTPMErrorHandling(c, &ProtectKeyParams{
		PCRPolicyCounterHandle: public.Index})
	c.Assert(err, testutil.ConvertibleTo, TPMResourceExistsError{})
	c.Check(err.(TPMResourceExistsError).Handle, Equals, public.Index)
}

func (s *sealSuite) TestProtectKeyWithTPMErrorHandlingInvalidPCRProfile(c *C) {
	err := s.testProtectKeyWithTPMErrorHandling(c, &ProtectKeyParams{
		PCRProfile: tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}).
			AddProfileOR(
				NewPCRProtectionProfile(),
				NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 8)),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181ffff), // verify that this gets undefined on error
	})
	c.Check(err, ErrorMatches, "cannot set initial PCR policy: cannot compute PCR digests from protection profile: "+
		"not all branches contain values for the same sets of PCRs")
}

func (s *sealSuite) TestProtectKeyWithTPMErrorHandlingInvalidPCRProfileSelection(c *C) {
	err := s.testProtectKeyWithTPMErrorHandling(c, &ProtectKeyParams{
		PCRProfile:             NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 50, make([]byte, tpm2.HashAlgorithmSHA256.Size())),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, ErrorMatches, "cannot set initial PCR policy: PCR protection profile contains digests for unsupported PCRs")
}

func (s *sealSuite) testProtectKeyWithExternalStorageKey(c *C, params *ProtectKeyParams) {
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)

	srkPub, _, _, err := s.TPM().ReadPublic(srk)
	c.Assert(err, IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	k, authKey, err := ProtectKeyWithExternalStorageKey(srkPub, key, params)
	c.Assert(err, IsNil)

	for _, model := range params.AuthorizedSnapModels {
		ok, err := k.IsSnapModelAuthorized(authKey, model)
		c.Check(err, IsNil)
		c.Check(ok, testutil.IsTrue)
	}

	skd, err := NewSealedKeyData(k)
	c.Assert(err, IsNil)
	c.Check(skd.Validate(s.TPM().TPMContext, authKey, s.TPM().HmacSession()), IsNil)

	c.Check(skd.Version(), Equals, uint32(3))
	c.Check(skd.PCRPolicyCounterHandle(), Equals, tpm2.HandleNull)

	policyAuthPublicKey, err := NewPolicyAuthPublicKey(authKey)
	c.Assert(err, IsNil)

	expectedPolicyData, expectedPolicyDigest, err := NewKeyDataPolicy(tpm2.HashAlgorithmSHA256, policyAuthPublicKey, nil, 0)
	c.Assert(err, IsNil)

	c.Check(skd.Data().Public().NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(skd.Data().Public().AuthPolicy, DeepEquals, expectedPolicyDigest)
	c.Check(skd.Data().Policy().(*KeyDataPolicy_v3).StaticData, tpm2_testutil.TPMValueDeepEquals, expectedPolicyData.(*KeyDataPolicy_v3).StaticData)

	if params.AuthKey != nil {
		c.Check(authKey, DeepEquals, params.AuthKey)
	}

	keyUnsealed, authKeyUnsealed, err := k.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)

	if params.PCRProfile != nil {
		// Verify that the key is sealed with the supplied PCR profile by changing
		// the PCR values.
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
		c.Check(err, IsNil)
		_, _, err = k.RecoverKeys()
		c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
			"cannot execute PolicyOR assertions: current session digest not found in policy data")
	}
}

func (s *sealSuite) TestProtectKeyWithExternalStorageKey(c *C) {
	s.testProtectKeyWithExternalStorageKey(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}})
}

func (s *sealSuite) TestProtectKeyWithExternalStorageKeyNilPCRProfileAndNoAuthorizedSnapModels(c *C) {
	s.testProtectKeyWithExternalStorageKey(c, &ProtectKeyParams{
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *sealSuite) TestProtectKeyWithExternalStorageKeyWithProvidedAuthKey(c *C) {
	authKey := make(secboot.PrimaryKey, 32)
	rand.Read(authKey)

	s.testProtectKeyWithExternalStorageKey(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
		AuthorizedSnapModels: []secboot.SnapModel{
			testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")},
		AuthKey: authKey})
}

func (s *sealSuite) testProtectKeyWithExternalStorageKeyErrorHandling(c *C, params *ProtectKeyParams) error {
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)

	srkPub, _, _, err := s.TPM().ReadPublic(srk)
	c.Assert(err, IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	_, _, sealErr := ProtectKeyWithExternalStorageKey(srkPub, key, params)
	return sealErr
}

func (s *sealSuite) TestProtectKeyWithExternalStorageKeyErrorHandlingNilParams(c *C) {
	c.Check(s.testProtectKeyWithExternalStorageKeyErrorHandling(c, nil), ErrorMatches, "no ProtectKeyParams provided")
}

func (s *sealSuite) TestProtectKeyWithExternalStorageKeyErrorHandlingInvalidPCRProfile(c *C) {
	err := s.testProtectKeyWithExternalStorageKeyErrorHandling(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, ErrorMatches, "cannot set initial PCR policy: cannot compute PCR digests from protection profile: "+
		"cannot read current PCR values from TPM: no context")
}

func (s *sealSuite) TestProtectKeyWithExternalStorageKeyErrorHandlingInvalidPCRProfileSelection(c *C) {
	err := s.testProtectKeyWithExternalStorageKeyErrorHandling(c, &ProtectKeyParams{
		PCRProfile:             NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 50, make([]byte, tpm2.HashAlgorithmSHA256.Size())),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, ErrorMatches, "cannot set initial PCR policy: PCR protection profile contains digests for unsupported PCRs")
}

func (s *sealSuite) TestProtectKeyWithExternalStorageKeyErrorHandlingWithPCRPolicyCounter(c *C) {
	err := s.testProtectKeyWithExternalStorageKeyErrorHandling(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Check(err, ErrorMatches, "PCR policy counter handle must be tpm2.HandleNull when creating an importable sealed key")
}

type mockKeySealer struct {
	called bool
}

func (s *mockKeySealer) CreateSealedObject(data []byte, nameAlg tpm2.HashAlgorithmId, policy tpm2.Digest) (tpm2.Private, *tpm2.Public, tpm2.EncryptedSecret, error) {
	if s.called {
		return nil, nil, nil, errors.New("called more than once")
	}

	pub := templates.NewSealedObject(nameAlg)
	pub.AuthPolicy = policy

	return tpm2.Private(data), pub, nil, nil
}

type mockSessionContext struct {
	tpm2.SessionContext
}

type sealSuiteNoTPM struct {
	tpm2_testutil.BaseTest

	lastKeyParams *secboot.KeyParams

	lastAuthKey       secboot.PrimaryKey
	lastAuthKeyPublic *tpm2.Public
}

func (s *sealSuiteNoTPM) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.lastKeyParams = nil
	s.AddCleanup(MockSecbootNewKeyData(func(params *secboot.KeyParams) (*secboot.KeyData, error) {
		s.lastKeyParams = params
		return secboot.NewKeyData(params)
	}))

	s.lastAuthKey = nil
	s.lastAuthKeyPublic = nil
	s.AddCleanup(MockNewPolicyAuthPublicKey(func(authKey secboot.PrimaryKey) (*tpm2.Public, error) {
		s.lastAuthKey = authKey

		pub, err := NewPolicyAuthPublicKey(authKey)
		s.lastAuthKeyPublic = pub
		return pub, err
	}))
}

var _ = Suite(&sealSuiteNoTPM{})

type testMakeKeyDataWithPolicyData struct {
	policy *KeyDataPolicyParams
}

func (s *sealSuiteNoTPM) testMakeKeyDataWithPolicy(c *C, data *testMakeKeyDataWithPolicyData) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)
	authKey := make(secboot.PrimaryKey, 32)
	rand.Read(authKey)

	var sealer mockKeySealer

	kd, err := MakeKeyDataWithPolicy(key, authKey, data.policy, &sealer)
	c.Check(err, IsNil)
	c.Assert(kd, NotNil)

	c.Assert(s.lastKeyParams, NotNil)
	c.Check(s.lastKeyParams.PlatformName, Equals, "tpm2")
	c.Check(s.lastKeyParams.PrimaryKey, DeepEquals, authKey)
	c.Check(s.lastKeyParams.SnapModelAuthHash, Equals, crypto.SHA256)

	skd, err := NewSealedKeyData(kd)
	c.Assert(err, IsNil)

	c.Check(skd.Data().Policy(), tpm2_testutil.TPMValueDeepEquals, data.policy.PolicyData)
	c.Check(skd.Data().Public().NameAlg, Equals, data.policy.Alg)
	c.Check(skd.Data().Public().AuthPolicy, DeepEquals, data.policy.AuthPolicy)

	payload := make(secboot.KeyPayload, len(s.lastKeyParams.EncryptedPayload))

	c.Assert(skd.Data().Private(), HasLen, 48)
	b, err := aes.NewCipher(skd.Data().Private()[:32])
	c.Assert(err, IsNil)
	stream := cipher.NewCFBDecrypter(b, skd.Data().Private()[32:])
	stream.XORKeyStream(payload, s.lastKeyParams.EncryptedPayload)

	recoveredKey, recoveredAuthKey, err := payload.Unmarshal()
	c.Check(err, IsNil)
	c.Check(recoveredKey, DeepEquals, key)
	c.Check(recoveredAuthKey, DeepEquals, authKey)
}

func (s *sealSuiteNoTPM) TestMakeKeyDataWithPolicy(c *C) {
	policyData := &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{
			AuthPublicKey:          templates.NewECCKey(tpm2.HashAlgorithmSHA256, templates.KeyUsageSign, nil, tpm2.ECCCurveNIST_P256),
			PCRPolicyCounterHandle: tpm2.HandleNull,
		},
		PCRData: &PcrPolicyData_v3{
			AuthorizedPolicySignature: &tpm2.Signature{SigAlg: tpm2.SigSchemeAlgECDSA},
		},
	}

	s.testMakeKeyDataWithPolicy(c, &testMakeKeyDataWithPolicyData{
		policy: &KeyDataPolicyParams{
			Alg:        tpm2.HashAlgorithmSHA256,
			PolicyData: policyData,
			AuthPolicy: []byte{1, 2, 3, 4}}})
}

func (s *sealSuiteNoTPM) TestMakeKeyDataWithPolicyDifferentNameAlg(c *C) {
	policyData := &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{
			AuthPublicKey:          templates.NewECCKey(tpm2.HashAlgorithmSHA256, templates.KeyUsageSign, nil, tpm2.ECCCurveNIST_P256),
			PCRPolicyCounterHandle: tpm2.HandleNull,
		},
		PCRData: &PcrPolicyData_v3{
			AuthorizedPolicySignature: &tpm2.Signature{SigAlg: tpm2.SigSchemeAlgECDSA},
		},
	}

	s.testMakeKeyDataWithPolicy(c, &testMakeKeyDataWithPolicyData{
		policy: &KeyDataPolicyParams{
			Alg:        tpm2.HashAlgorithmSHA1,
			PolicyData: policyData,
			AuthPolicy: []byte{1, 2, 3, 4}}})
}

func (s *sealSuiteNoTPM) TestMakeKeyDataWithPolicyDifferentPolicyDigest(c *C) {
	policyData := &KeyDataPolicy_v3{
		StaticData: &StaticPolicyData_v3{
			AuthPublicKey:          templates.NewECCKey(tpm2.HashAlgorithmSHA256, templates.KeyUsageSign, nil, tpm2.ECCCurveNIST_P256),
			PCRPolicyCounterHandle: tpm2.HandleNull,
		},
		PCRData: &PcrPolicyData_v3{
			AuthorizedPolicySignature: &tpm2.Signature{SigAlg: tpm2.SigSchemeAlgECDSA},
		},
	}

	s.testMakeKeyDataWithPolicy(c, &testMakeKeyDataWithPolicyData{
		policy: &KeyDataPolicyParams{
			Alg:        tpm2.HashAlgorithmSHA256,
			PolicyData: policyData,
			AuthPolicy: []byte{5, 6, 7, 8, 9}}})
}

func (s *sealSuiteNoTPM) TestMakeKeyDataWithPolicyDifferentPolicyVersion(c *C) {
	policyData := &KeyDataPolicy_v1{
		StaticData: &StaticPolicyData_v1{
			AuthPublicKey:          templates.NewECCKey(tpm2.HashAlgorithmSHA256, templates.KeyUsageSign, nil, tpm2.ECCCurveNIST_P256),
			PCRPolicyCounterHandle: tpm2.HandleNull,
		},
		PCRData: &PcrPolicyData_v1{
			AuthorizedPolicySignature: &tpm2.Signature{SigAlg: tpm2.SigSchemeAlgECDSA},
		},
	}

	s.testMakeKeyDataWithPolicy(c, &testMakeKeyDataWithPolicyData{
		policy: &KeyDataPolicyParams{
			Alg:        tpm2.HashAlgorithmSHA256,
			PolicyData: policyData,
			AuthPolicy: []byte{1, 2, 3, 4}}})
}

type testMakeKeyDataPolicyData struct {
	pcrPolicyCounterHandle       tpm2.Handle
	authKey                      secboot.PrimaryKey
	initialPcrPolicyCounterValue uint64
}

func (s *sealSuiteNoTPM) testMakeKeyDataPolicy(c *C, data *testMakeKeyDataPolicyData) {
	var mockTpm *tpm2.TPMContext
	var mockSession tpm2.SessionContext
	if data.pcrPolicyCounterHandle != tpm2.HandleNull {
		mockTpm = new(tpm2.TPMContext)
		mockSession = new(mockSessionContext)
	}

	var mockPcrPolicyCounterPub *tpm2.NVPublic
	restore := MockCreatePcrPolicyCounter(func(tpm *tpm2.TPMContext, handle tpm2.Handle, pub *tpm2.Public, session tpm2.SessionContext) (*tpm2.NVPublic, uint64, error) {
		c.Assert(mockTpm, NotNil)

		c.Check(tpm, Equals, mockTpm)
		c.Check(handle, Equals, data.pcrPolicyCounterHandle)
		c.Check(pub, Equals, s.lastAuthKeyPublic)
		c.Check(session, Equals, mockSession)

		mockPcrPolicyCounterPub = &tpm2.NVPublic{
			Index:      handle,
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
			AuthPolicy: make([]byte, 32),
			Size:       8}

		return mockPcrPolicyCounterPub, data.initialPcrPolicyCounterValue, nil
	})
	defer restore()

	var mockPolicyData *KeyDataPolicy_v3
	var mockPolicyDigest tpm2.Digest
	restore = MockNewKeyDataPolicy(func(alg tpm2.HashAlgorithmId, key *tpm2.Public, pcrPolicyCounterPub *tpm2.NVPublic, pcrPolicySequence uint64) (KeyDataPolicy, tpm2.Digest, error) {
		c.Check(alg, Equals, tpm2.HashAlgorithmSHA256)
		c.Check(key, Equals, s.lastAuthKeyPublic)
		c.Check(pcrPolicyCounterPub, Equals, mockPcrPolicyCounterPub)
		c.Check(pcrPolicySequence, Equals, data.initialPcrPolicyCounterValue)

		index := tpm2.HandleNull
		if pcrPolicyCounterPub != nil {
			index = pcrPolicyCounterPub.Index
		}

		mockPolicyData = &KeyDataPolicy_v3{
			StaticData: &StaticPolicyData_v3{
				AuthPublicKey:          key,
				PCRPolicyCounterHandle: index},
			PCRData: &PcrPolicyData_v3{
				PolicySequence:            pcrPolicySequence,
				AuthorizedPolicySignature: &tpm2.Signature{SigAlg: tpm2.SigSchemeAlgNull}}}

		mockPolicyDigest = make([]byte, alg.Size())
		rand.Read(mockPolicyDigest)

		return mockPolicyData, mockPolicyDigest, nil
	})
	defer restore()

	policy, pcrPolicyCounter, authKeyOut, err := MakeKeyDataPolicy(mockTpm, data.pcrPolicyCounterHandle, data.authKey, mockSession)
	c.Assert(err, IsNil)

	c.Assert(s.lastAuthKey, NotNil)
	c.Assert(mockPolicyData, NotNil)

	c.Assert(policy, NotNil)
	c.Check(policy.Alg, Equals, tpm2.HashAlgorithmSHA256)
	c.Assert(policy.PolicyData, testutil.ConvertibleTo, new(KeyDataPolicy_v3))
	c.Check(policy.PolicyData.(*KeyDataPolicy_v3), Equals, mockPolicyData)
	c.Check(policy.AuthPolicy, DeepEquals, mockPolicyDigest)

	if data.pcrPolicyCounterHandle == tpm2.HandleNull {
		c.Check(pcrPolicyCounter, IsNil)
	} else {
		c.Check(pcrPolicyCounter, NotNil)
		c.Check(pcrPolicyCounter.Pub(), Equals, mockPcrPolicyCounterPub)
		c.Check(pcrPolicyCounter.TPM(), Equals, mockTpm)
		c.Check(pcrPolicyCounter.Session(), Equals, mockSession)
	}

	c.Check(authKeyOut, DeepEquals, s.lastAuthKey)
	c.Check(policy.PolicyData.ValidateAuthKey(authKeyOut), IsNil)
	if data.authKey != nil {
		c.Check(authKeyOut, DeepEquals, data.authKey)
	}

}

func (s *sealSuiteNoTPM) TestMakeKeyDataPolicy(c *C) {
	s.testMakeKeyDataPolicy(c, &testMakeKeyDataPolicyData{
		pcrPolicyCounterHandle: tpm2.HandleNull})
}

func (s *sealSuiteNoTPM) TestMakeKeyDataPolicyWithPolicyCounter(c *C) {
	s.testMakeKeyDataPolicy(c, &testMakeKeyDataPolicyData{
		pcrPolicyCounterHandle:       0x01800001,
		initialPcrPolicyCounterValue: 20})
}

func (s *sealSuiteNoTPM) TestMakeKeyDataPolicyWithPolicyCounterDifferentInitialValue(c *C) {
	s.testMakeKeyDataPolicy(c, &testMakeKeyDataPolicyData{
		pcrPolicyCounterHandle:       0x01800001,
		initialPcrPolicyCounterValue: 1000})
}

func (s *sealSuiteNoTPM) TestMakeKeyDataPolicyWithProvidedAuthKey(c *C) {
	s.testMakeKeyDataPolicy(c, &testMakeKeyDataPolicyData{
		authKey: testutil.DecodeHexString(c, "fb8978601d0c2dd4129e3b9c1bb3f3116f4c5dd217c29b1017ab7cd31a882d3c")})
}

type testMakeKeyDataData struct {
	authKey                      secboot.PrimaryKey
	params                       *KeyDataParams
	initialPcrPolicyCounterValue uint64
}

func (s *sealSuiteNoTPM) testMakeKeyData(c *C, data *testMakeKeyDataData) {
	var mockTpm *tpm2.TPMContext
	var mockSession tpm2.SessionContext
	if data.params.PCRPolicyCounterHandle != tpm2.HandleNull {
		mockTpm = new(tpm2.TPMContext)
		mockSession = new(mockSessionContext)
	}

	var mockPcrPolicyCounterPub *tpm2.NVPublic
	restore := MockCreatePcrPolicyCounter(func(tpm *tpm2.TPMContext, handle tpm2.Handle, pub *tpm2.Public, session tpm2.SessionContext) (*tpm2.NVPublic, uint64, error) {
		c.Assert(mockTpm, NotNil)

		c.Check(tpm, Equals, mockTpm)
		c.Check(handle, Equals, data.params.PCRPolicyCounterHandle)
		c.Check(pub, Equals, s.lastAuthKeyPublic)
		c.Check(session, Equals, mockSession)

		mockPcrPolicyCounterPub = &tpm2.NVPublic{
			Index:      handle,
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
			AuthPolicy: make([]byte, 32),
			Size:       8}

		return mockPcrPolicyCounterPub, data.initialPcrPolicyCounterValue, nil
	})
	defer restore()

	var mockPolicyData *KeyDataPolicy_v3
	var mockPolicyDigest tpm2.Digest
	restore = MockNewKeyDataPolicy(func(alg tpm2.HashAlgorithmId, key *tpm2.Public, pcrPolicyCounterPub *tpm2.NVPublic, pcrPolicySequence uint64) (KeyDataPolicy, tpm2.Digest, error) {
		c.Check(alg, Equals, tpm2.HashAlgorithmSHA256)
		c.Check(key, Equals, s.lastAuthKeyPublic)
		c.Check(pcrPolicyCounterPub, Equals, mockPcrPolicyCounterPub)
		c.Check(pcrPolicySequence, Equals, data.initialPcrPolicyCounterValue)

		index := tpm2.HandleNull
		if pcrPolicyCounterPub != nil {
			index = pcrPolicyCounterPub.Index
		}

		mockPolicyData = &KeyDataPolicy_v3{
			StaticData: &StaticPolicyData_v3{
				AuthPublicKey:          key,
				PCRPolicyCounterHandle: index},
			PCRData: &PcrPolicyData_v3{
				PolicySequence:            pcrPolicySequence,
				AuthorizedPolicySignature: &tpm2.Signature{SigAlg: tpm2.SigSchemeAlgNull}}}

		mockPolicyDigest = make([]byte, alg.Size())
		rand.Read(mockPolicyDigest)

		return mockPolicyData, mockPolicyDigest, nil
	})
	defer restore()

	pcrPolicyInitialized := false
	restore = MockSkdbUpdatePCRProtectionPolicyImpl(func(skdb *SealedKeyDataBase, tpm *tpm2.TPMContext, authKey secboot.PrimaryKey, counterPub *tpm2.NVPublic, profile *PCRProtectionProfile, session tpm2.SessionContext) error {
		c.Check(tpm, Equals, mockTpm)
		c.Check(authKey, DeepEquals, s.lastAuthKey)
		c.Check(counterPub, Equals, mockPcrPolicyCounterPub)
		c.Check(profile, NotNil)
		if data.params.PCRProfile != nil {
			c.Check(profile, Equals, data.params.PCRProfile)
		}
		c.Check(session, Equals, mockSession)
		pcrPolicyInitialized = true
		return nil
	})
	defer restore()

	var sealer mockKeySealer

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	kd, authKeyOut, pcrPolicyCounter, err := MakeKeyData(mockTpm, key, data.authKey, data.params, &sealer, mockSession)
	c.Assert(err, IsNil)

	c.Assert(s.lastAuthKey, NotNil)
	c.Assert(mockPolicyData, NotNil)
	c.Assert(pcrPolicyInitialized, testutil.IsTrue)

	c.Assert(s.lastKeyParams, NotNil)
	c.Check(s.lastKeyParams.PlatformName, Equals, "tpm2")
	c.Check(s.lastKeyParams.PrimaryKey, DeepEquals, s.lastAuthKey)
	c.Check(s.lastKeyParams.SnapModelAuthHash, Equals, crypto.SHA256)

	skd, err := NewSealedKeyData(kd)
	c.Assert(err, IsNil)

	c.Check(skd.Data().Policy(), tpm2_testutil.TPMValueDeepEquals, mockPolicyData)
	c.Check(skd.Data().Public().NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(skd.Data().Public().AuthPolicy, DeepEquals, mockPolicyDigest)

	payload := make(secboot.KeyPayload, len(s.lastKeyParams.EncryptedPayload))

	c.Assert(skd.Data().Private(), HasLen, 48)
	b, err := aes.NewCipher(skd.Data().Private()[:32])
	c.Assert(err, IsNil)
	stream := cipher.NewCFBDecrypter(b, skd.Data().Private()[32:])
	stream.XORKeyStream(payload, s.lastKeyParams.EncryptedPayload)

	recoveredKey, recoveredAuthKey, err := payload.Unmarshal()
	c.Check(err, IsNil)
	c.Check(recoveredKey, DeepEquals, key)
	c.Check(recoveredAuthKey, DeepEquals, s.lastAuthKey)

	c.Check(skd.Data().Policy().ValidateAuthKey(authKeyOut), IsNil)
	c.Check(authKeyOut, DeepEquals, s.lastAuthKey)
	if data.authKey != nil {
		c.Check(authKeyOut, DeepEquals, data.authKey)
	}

	if data.params.PCRPolicyCounterHandle == tpm2.HandleNull {
		c.Check(pcrPolicyCounter, IsNil)
	} else {
		c.Check(pcrPolicyCounter, NotNil)
		c.Check(pcrPolicyCounter.Pub(), Equals, mockPcrPolicyCounterPub)
		c.Check(pcrPolicyCounter.TPM(), Equals, mockTpm)
		c.Check(pcrPolicyCounter.Session(), Equals, mockSession)
	}
}

func (s *sealSuiteNoTPM) TestMakeKeyData(c *C) {
	s.testMakeKeyData(c, &testMakeKeyDataData{
		params: &KeyDataParams{
			PCRPolicyCounterHandle: tpm2.HandleNull,
			PCRProfile:             NewPCRProtectionProfile()}})
}

func (s *sealSuiteNoTPM) TestMakeKeyDataWithPolicyCounter(c *C) {
	s.testMakeKeyData(c, &testMakeKeyDataData{
		params: &KeyDataParams{
			PCRPolicyCounterHandle: 0x01810000,
			PCRProfile:             NewPCRProtectionProfile()},
		initialPcrPolicyCounterValue: 30})
}

func (s *sealSuiteNoTPM) TestMakeKeyDataWithPolicyCounterDifferentInitialValue(c *C) {
	s.testMakeKeyData(c, &testMakeKeyDataData{
		params: &KeyDataParams{
			PCRPolicyCounterHandle: 0x01810000,
			PCRProfile:             NewPCRProtectionProfile()},
		initialPcrPolicyCounterValue: 500})
}

func (s *sealSuiteNoTPM) TestMakeKeyDataNilPCRProfile(c *C) {
	s.testMakeKeyData(c, &testMakeKeyDataData{
		params: &KeyDataParams{
			PCRPolicyCounterHandle: tpm2.HandleNull}})
}
