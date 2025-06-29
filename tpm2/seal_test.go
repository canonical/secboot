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
	"github.com/canonical/go-tpm2/objectutil"
	tpm2_testutil "github.com/canonical/go-tpm2/testutil"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type protectedKeys struct {
	Primary secboot.PrimaryKey
	Unique  []byte
}

func unmarshalProtectedKeys(data []byte) (*protectedKeys, error) {
	s := cryptobyte.String(data)
	if !s.ReadASN1(&s, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("malformed input")
	}

	pk := new(protectedKeys)

	if !s.ReadASN1Bytes((*[]byte)(&pk.Primary), cryptobyte_asn1.OCTET_STRING) {
		return nil, errors.New("malformed primary key")
	}
	if !s.ReadASN1Bytes(&pk.Unique, cryptobyte_asn1.OCTET_STRING) {
		return nil, errors.New("malformed unique key")
	}

	return pk, nil
}

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
	origKdf := secboot.SetArgon2KDF(&testutil.MockArgon2KDF{})
	s.AddCleanup(func() { secboot.SetArgon2KDF(origKdf) })
}

var _ = Suite(&sealSuite{})

func (s *sealSuite) testProtectKeyWithTPM(c *C, params *ProtectKeyParams) {
	s.AddCleanup(MockSecbootNewKeyData(func(keyParams *secboot.KeyParams) (*secboot.KeyData, error) {
		c.Check(keyParams.Role, Equals, params.Role)
		c.Check(keyParams.PlatformName, Equals, "tpm2")
		c.Check(keyParams.KDFAlg, Equals, crypto.SHA256)

		// TODO: Check EncryptedPayload and Handle fields

		return secboot.NewKeyData(keyParams)
	}))

	k, primaryKey, unlockKey, err := NewTPMProtectedKey(s.TPM(), params)
	c.Assert(err, IsNil)

	c.Check(k.AuthMode(), Equals, secboot.AuthModeNone)

	skd, err := NewSealedKeyData(k)
	c.Assert(err, IsNil)
	c.Check(skd.Validate(s.TPM().TPMContext, primaryKey), IsNil)

	c.Check(skd.Version(), Equals, uint32(3))
	c.Check(skd.PCRPolicyCounterHandle(), Equals, params.PCRPolicyCounterHandle)

	policyAuthPublicKey, err := NewPolicyAuthPublicKey(primaryKey)
	c.Assert(err, IsNil)

	var pcrPolicyCounterPub *tpm2.NVPublic
	if params.PCRPolicyCounterHandle != tpm2.HandleNull {
		index, err := s.TPM().NewResourceContext(params.PCRPolicyCounterHandle)
		c.Assert(err, IsNil)

		pcrPolicyCounterPub, _, err = s.TPM().NVReadPublic(index)
		c.Check(err, IsNil)

	}

	expectedPolicyData, expectedPolicyDigest, err := NewKeyDataPolicy(tpm2.HashAlgorithmSHA256, policyAuthPublicKey, params.Role, pcrPolicyCounterPub, false)
	c.Assert(err, IsNil)

	c.Check(skd.Data().Public().NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(skd.Data().Public().Attrs, Equals, tpm2.AttrFixedTPM|tpm2.AttrFixedParent|tpm2.AttrNoDA)
	c.Check(skd.Data().Public().AuthPolicy, DeepEquals, expectedPolicyDigest)
	c.Check(skd.Data().Policy().(*KeyDataPolicy_v3).StaticData, tpm2_testutil.TPMValueDeepEquals, expectedPolicyData.(*KeyDataPolicy_v3).StaticData)

	if params.PrimaryKey != nil {
		c.Check(primaryKey, DeepEquals, params.PrimaryKey)
	}

	s.AddCleanup(s.CloseMockConnection(c))

	unlockKeyUnsealed, primaryKeyUnsealed, err := k.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(unlockKeyUnsealed, DeepEquals, unlockKey)
	c.Check(primaryKeyUnsealed, DeepEquals, primaryKey)

	if params.PCRProfile != nil {
		// Verify that the key is sealed with the supplied PCR profile by changing
		// the PCR values.
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
		c.Check(err, IsNil)
		_, _, err = k.RecoverKeys()
		c.Check(err, ErrorMatches, "incompatible key data role params: invalid PCR policy data: cannot complete authorization "+
			"policy assertions: cannot execute PCR assertions: cannot execute PolicyOR assertions: current session digest not found in policy data")
	}

	if params.PCRPolicyCounterHandle != tpm2.HandleNull {
		c.Check(s.TPM().DoesHandleExist(params.PCRPolicyCounterHandle), testutil.IsTrue)
	}
}

func (s *sealSuite) TestProtectKeyWithTPM(c *C) {
	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		Role:                   "foo",
	})
}

func (s *sealSuite) TestProtectKeyWithTPMDifferentPCRPolicyCounterHandle(c *C) {
	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "foo",
	})
}

func (s *sealSuite) TestProtectKeyWithTPMWithNewConnection(c *C) {
	// ProtectKeyWithTPM behaves slightly different if called immediately after
	// EnsureProvisioned with the same Connection
	s.ReinitTPMConnectionFromExisting(c)

	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		Role:                   "foo",
	})

	s.validateSRK(c)
}

func (s *sealSuite) TestProtectKeyWithTPMMissingSRK(c *C) {
	// Ensure that calling ProtectKeyWithTPM recreates the SRK with the standard template
	srk, err := s.TPM().NewResourceContext(tcg.SRKHandle)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

	s.ReinitTPMConnectionFromExisting(c)

	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		Role:                   "foo",
	})

	s.validateSRK(c)
}

func (s *sealSuite) TestProtectKeyWithTPMMissingCustomSRK(c *C) {
	// Ensure that calling ProtectKeyWithTPM recreates the SRK with the custom
	// template originally supplied during provisioning
	srk, err := s.TPM().NewResourceContext(tcg.SRKHandle)
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
		Role:                   "foo",
	})

	s.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, template)
}

func (s *sealSuite) TestProtectKeyWithTPMMissingSRKWithInvalidCustomTemplate(c *C) {
	// Ensure that calling ProtectKeyWithTPM recreates the SRK with the standard
	// template if the NV index we use to store custom templates has invalid
	// contents - if the contents are invalid then we didn't create it.
	srk, err := s.TPM().NewResourceContext(tcg.SRKHandle)
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
		Role:                   "foo",
	})

	s.validateSRK(c)
}

func (s *sealSuite) TestProtectKeyWithTPMNoPCRPolicyCounterHandle(c *C) {
	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
		Role:                   "foo",
	})
}

func (s *sealSuite) TestProtectKeyWithTPMWithProvidedPrimaryKey(c *C) {
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)

	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		Role:                   "foo",
		PrimaryKey:             primaryKey})
}

func (s *sealSuite) TestProtectKeyWithTPMWithDifferentRole(c *C) {
	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		Role:                   "bar"})
}

func (s *sealSuite) TestProtectKeyWithTPMWithNoRole(c *C) {
	s.testProtectKeyWithTPM(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
}

func (s *sealSuite) testProtectKeyWithTPMErrorHandling(c *C, params *ProtectKeyParams) error {
	var origCounter tpm2.ResourceContext
	if params != nil && params.PCRPolicyCounterHandle != tpm2.HandleNull {
		var err error
		origCounter, err = s.TPM().NewResourceContext(params.PCRPolicyCounterHandle)
		if tpm2.IsResourceUnavailableError(err, params.PCRPolicyCounterHandle) {
			err = nil
		}
		c.Check(err, IsNil)
	}

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	_, _, _, sealErr := NewTPMProtectedKey(s.TPM(), params)

	var counter tpm2.ResourceContext
	if params != nil && params.PCRPolicyCounterHandle != tpm2.HandleNull {
		var err error
		counter, err = s.TPM().NewResourceContext(params.PCRPolicyCounterHandle)
		if tpm2.IsResourceUnavailableError(err, params.PCRPolicyCounterHandle) {
			err = nil
		}
		c.Check(err, IsNil)
	}

	if params != nil && params.PCRPolicyCounterHandle != tpm2.HandleNull {
		c.Assert(counter, NotNil)
		if origCounter != nil {
			c.Check(counter.Name(), DeepEquals, origCounter.Name())
		}
	} else {
		c.Check(counter, IsNil)
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

func (s *sealSuite) TestProtectKeyWithTPMErrorHandlingInvalidRole(c *C) {
	err := s.testProtectKeyWithTPMErrorHandling(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
		Role:                   "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"})
	c.Check(err, ErrorMatches, `cannot create initial policy data: invalid role: too large`)
}

func (s *sealSuite) testPassphraseProtectKeyWithTPM(c *C, params *PassphraseProtectKeyParams, passphrase string) {
	s.AddCleanup(MockSecbootNewKeyDataWithPassphrase(func(keyParams *secboot.KeyWithPassphraseParams, keyPassphrase string) (*secboot.KeyData, error) {
		c.Check(keyParams.Role, Equals, params.Role)
		c.Check(keyParams.PlatformName, Equals, "tpm2")
		c.Check(keyParams.KDFAlg, Equals, crypto.SHA256)
		c.Check(keyParams.KDFOptions, DeepEquals, params.KDFOptions)
		c.Check(keyParams.AuthKeySize, Equals, 32)
		c.Check(keyPassphrase, Equals, passphrase)

		// TODO: Check EncryptedPayload and Handle fields

		return secboot.NewKeyDataWithPassphrase(keyParams, keyPassphrase)
	}))

	k, primaryKey, unlockKey, err := NewTPMPassphraseProtectedKey(s.TPM(), params, passphrase)
	c.Assert(err, IsNil)

	c.Check(k.AuthMode(), Equals, secboot.AuthModePassphrase)

	skd, err := NewSealedKeyData(k)
	c.Assert(err, IsNil)
	c.Check(skd.Validate(s.TPM().TPMContext, primaryKey), IsNil)

	c.Check(skd.Version(), Equals, uint32(3))
	c.Check(skd.PCRPolicyCounterHandle(), Equals, params.PCRPolicyCounterHandle)

	policyAuthPublicKey, err := NewPolicyAuthPublicKey(primaryKey)
	c.Assert(err, IsNil)

	var pcrPolicyCounterPub *tpm2.NVPublic
	if params.PCRPolicyCounterHandle != tpm2.HandleNull {
		index, err := s.TPM().CreateResourceContextFromTPM(params.PCRPolicyCounterHandle)
		c.Assert(err, IsNil)

		pcrPolicyCounterPub, _, err = s.TPM().NVReadPublic(index)
		c.Check(err, IsNil)

	}

	expectedPolicyData, expectedPolicyDigest, err := NewKeyDataPolicy(tpm2.HashAlgorithmSHA256, policyAuthPublicKey, params.Role, pcrPolicyCounterPub, true)
	c.Assert(err, IsNil)

	c.Check(skd.Data().Public().NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(skd.Data().Public().Attrs, Equals, tpm2.AttrFixedTPM|tpm2.AttrFixedParent)
	c.Check(skd.Data().Public().AuthPolicy, DeepEquals, expectedPolicyDigest)
	c.Check(skd.Data().Policy().(*KeyDataPolicy_v3).StaticData, tpm2_testutil.TPMValueDeepEquals, expectedPolicyData.(*KeyDataPolicy_v3).StaticData)

	if params.PrimaryKey != nil {
		c.Check(primaryKey, DeepEquals, params.PrimaryKey)
	}

	s.AddCleanup(s.CloseMockConnection(c))

	unlockKeyUnsealed, primaryKeyUnsealed, err := k.RecoverKeysWithPassphrase(passphrase)
	c.Check(err, IsNil)
	c.Check(unlockKeyUnsealed, DeepEquals, unlockKey)
	c.Check(primaryKeyUnsealed, DeepEquals, primaryKey)

	if params.PCRProfile != nil {
		// Verify that the key is sealed with the supplied PCR profile by changing
		// the PCR values.
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
		c.Check(err, IsNil)
		_, _, err = k.RecoverKeysWithPassphrase(passphrase)
		c.Check(err, ErrorMatches, "incompatible key data role params: invalid PCR policy data: cannot complete authorization "+
			"policy assertions: cannot execute PCR assertions: cannot execute PolicyOR assertions: current session digest not found in policy data")
	}

	if params.PCRPolicyCounterHandle != tpm2.HandleNull {
		c.Check(s.TPM().DoesHandleExist(params.PCRPolicyCounterHandle), testutil.IsTrue)
	}
}

func (s *sealSuite) TestPassphraseProtectKeyWithTPM(c *C) {
	s.testPassphraseProtectKeyWithTPM(c, &PassphraseProtectKeyParams{
		ProtectKeyParams: ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			Role:                   "foo",
		},
	}, "Jg4zg4GF9WGL")
}

func (s *sealSuite) TestPassphraseProtectKeyWithTPMSuppliedKDFOptions(c *C) {
	s.testPassphraseProtectKeyWithTPM(c, &PassphraseProtectKeyParams{
		ProtectKeyParams: ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			Role:                   "foo",
		},
		KDFOptions: &secboot.Argon2Options{
			Mode:            secboot.Argon2id,
			MemoryKiB:       32 * 1024,
			ForceIterations: 4,
			Parallel:        4,
		},
	}, "Jg4zg4GF9WGL")
}

func (s *sealSuite) TestPassphraseProtectKeyWithTPMDifferentSuppliedKDFOptions(c *C) {
	s.testPassphraseProtectKeyWithTPM(c, &PassphraseProtectKeyParams{
		ProtectKeyParams: ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			Role:                   "foo",
		},
		KDFOptions: &secboot.PBKDF2Options{
			ForceIterations: 100000,
			HashAlg:         crypto.SHA256,
		},
	}, "Jg4zg4GF9WGL")
}

func (s *sealSuite) TestPassphraseProtectKeyWithTPMDifferentPassphrase(c *C) {
	s.testPassphraseProtectKeyWithTPM(c, &PassphraseProtectKeyParams{
		ProtectKeyParams: ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			Role:                   "foo",
		},
	}, "uWjzz3MURKUS")
}

func makePIN(c *C, in string) secboot.PIN {
	out, err := secboot.ParsePIN(in)
	c.Assert(err, IsNil)
	return out
}

func (s *sealSuite) testPINProtectKeyWithTPM(c *C, params *PINProtectKeyParams, pin secboot.PIN) {
	s.AddCleanup(MockSecbootNewKeyDataWithPIN(func(keyParams *secboot.KeyWithPINParams, keyPIN secboot.PIN) (*secboot.KeyData, error) {
		c.Check(keyParams.Role, Equals, params.Role)
		c.Check(keyParams.PlatformName, Equals, "tpm2")
		c.Check(keyParams.KDFAlg, Equals, crypto.SHA256)
		c.Check(keyParams.KDFOptions, DeepEquals, params.KDFOptions)
		c.Check(keyParams.AuthKeySize, Equals, 32)
		c.Check(keyPIN, DeepEquals, pin)

		// TODO: Check EncryptedPayload and Handle fields

		return secboot.NewKeyDataWithPIN(keyParams, keyPIN)
	}))

	k, primaryKey, unlockKey, err := NewTPMPINProtectedKey(s.TPM(), params, pin)
	c.Assert(err, IsNil)

	c.Check(k.AuthMode(), Equals, secboot.AuthModePIN)

	skd, err := NewSealedKeyData(k)
	c.Assert(err, IsNil)
	c.Check(skd.Validate(s.TPM().TPMContext, primaryKey), IsNil)

	c.Check(skd.Version(), Equals, uint32(3))
	c.Check(skd.PCRPolicyCounterHandle(), Equals, params.PCRPolicyCounterHandle)

	policyAuthPublicKey, err := NewPolicyAuthPublicKey(primaryKey)
	c.Assert(err, IsNil)

	var pcrPolicyCounterPub *tpm2.NVPublic
	if params.PCRPolicyCounterHandle != tpm2.HandleNull {
		index, err := s.TPM().CreateResourceContextFromTPM(params.PCRPolicyCounterHandle)
		c.Assert(err, IsNil)

		pcrPolicyCounterPub, _, err = s.TPM().NVReadPublic(index)
		c.Check(err, IsNil)

	}

	expectedPolicyData, expectedPolicyDigest, err := NewKeyDataPolicy(tpm2.HashAlgorithmSHA256, policyAuthPublicKey, params.Role, pcrPolicyCounterPub, true)
	c.Assert(err, IsNil)

	c.Check(skd.Data().Public().NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(skd.Data().Public().Attrs, Equals, tpm2.AttrFixedTPM|tpm2.AttrFixedParent)
	c.Check(skd.Data().Public().AuthPolicy, DeepEquals, expectedPolicyDigest)
	c.Check(skd.Data().Policy().(*KeyDataPolicy_v3).StaticData, tpm2_testutil.TPMValueDeepEquals, expectedPolicyData.(*KeyDataPolicy_v3).StaticData)

	if params.PrimaryKey != nil {
		c.Check(primaryKey, DeepEquals, params.PrimaryKey)
	}

	s.AddCleanup(s.CloseMockConnection(c))

	unlockKeyUnsealed, primaryKeyUnsealed, err := k.RecoverKeysWithPIN(pin)
	c.Check(err, IsNil)
	c.Check(unlockKeyUnsealed, DeepEquals, unlockKey)
	c.Check(primaryKeyUnsealed, DeepEquals, primaryKey)

	if params.PCRProfile != nil {
		// Verify that the key is sealed with the supplied PCR profile by changing
		// the PCR values.
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
		c.Check(err, IsNil)
		_, _, err = k.RecoverKeysWithPIN(pin)
		c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
			"cannot execute PolicyOR assertions: current session digest not found in policy data")
	}

	if params.PCRPolicyCounterHandle != tpm2.HandleNull {
		c.Check(s.TPM().DoesHandleExist(params.PCRPolicyCounterHandle), testutil.IsTrue)
	}
}

func (s *sealSuite) TestPINProtectKeyWithTPM(c *C) {
	s.testPINProtectKeyWithTPM(c, &PINProtectKeyParams{
		ProtectKeyParams: ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			Role:                   "foo",
		},
	}, makePIN(c, "1234"))
}

func (s *sealSuite) TestPINProtectKeyWithTPMSuppliedKDFOptions(c *C) {
	s.testPINProtectKeyWithTPM(c, &PINProtectKeyParams{
		ProtectKeyParams: ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			Role:                   "foo",
		},
		KDFOptions: &secboot.PBKDF2Options{
			ForceIterations: 50000,
			HashAlg:         crypto.SHA256,
		},
	}, makePIN(c, "1234"))
}

func (s *sealSuite) TestPINProtectKeyWithTPMDifferentSuppliedKDFOptions(c *C) {
	s.testPINProtectKeyWithTPM(c, &PINProtectKeyParams{
		ProtectKeyParams: ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			Role:                   "foo",
		},
		KDFOptions: &secboot.PBKDF2Options{
			ForceIterations: 100000,
			HashAlg:         crypto.SHA384,
		},
	}, makePIN(c, "1234"))
}

func (s *sealSuite) TestPINProtectKeyWithTPMDifferentPIN(c *C) {
	s.testPINProtectKeyWithTPM(c, &PINProtectKeyParams{
		ProtectKeyParams: ProtectKeyParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			Role:                   "foo",
		},
	}, makePIN(c, "87654321"))
}

func (s *sealSuite) testProtectKeyWithExternalStorageKey(c *C, params *ProtectKeyParams) {
	srk, err := s.TPM().NewResourceContext(tcg.SRKHandle)
	c.Assert(err, IsNil)

	srkPub, _, _, err := s.TPM().ReadPublic(srk)
	c.Assert(err, IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	k, primaryKey, unlockKey, err := NewExternalTPMProtectedKey(srkPub, params)
	c.Assert(err, IsNil)

	skd, err := NewSealedKeyData(k)
	c.Assert(err, IsNil)
	c.Check(skd.Validate(s.TPM().TPMContext, primaryKey), IsNil)

	c.Check(skd.Version(), Equals, uint32(3))
	c.Check(skd.PCRPolicyCounterHandle(), Equals, tpm2.HandleNull)

	policyAuthPublicKey, err := NewPolicyAuthPublicKey(primaryKey)
	c.Assert(err, IsNil)

	expectedPolicyData, expectedPolicyDigest, err := NewKeyDataPolicy(tpm2.HashAlgorithmSHA256, policyAuthPublicKey, "", nil, false)
	c.Assert(err, IsNil)

	c.Check(skd.Data().Public().NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(skd.Data().Public().AuthPolicy, DeepEquals, expectedPolicyDigest)
	c.Check(skd.Data().Policy().(*KeyDataPolicy_v3).StaticData, tpm2_testutil.TPMValueDeepEquals, expectedPolicyData.(*KeyDataPolicy_v3).StaticData)

	if params.PrimaryKey != nil {
		c.Check(primaryKey, DeepEquals, params.PrimaryKey)
	}

	s.AddCleanup(s.CloseMockConnection(c))

	unlockKeyUnsealed, primaryKeyUnsealed, err := k.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(unlockKeyUnsealed, DeepEquals, unlockKey)
	c.Check(primaryKeyUnsealed, DeepEquals, primaryKey)

	if params.PCRProfile != nil {
		// Verify that the key is sealed with the supplied PCR profile by changing
		// the PCR values.
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
		c.Check(err, IsNil)
		_, _, err = k.RecoverKeys()
		c.Check(err, ErrorMatches, "incompatible key data role params: invalid PCR policy data: cannot complete authorization "+
			"policy assertions: cannot execute PCR assertions: cannot execute PolicyOR assertions: current session digest not found in policy data")
	}
}

func (s *sealSuite) TestProtectKeyWithExternalStorageKey(c *C) {
	s.testProtectKeyWithExternalStorageKey(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
	})
}

func (s *sealSuite) TestProtectKeyWithExternalStorageKeyNilPCRProfileAndNoAuthorizedSnapModels(c *C) {
	s.testProtectKeyWithExternalStorageKey(c, &ProtectKeyParams{
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *sealSuite) TestProtectKeyWithExternalStorageKeyWithProvidedPrimaryKey(c *C) {
	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)

	s.testProtectKeyWithExternalStorageKey(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
		PrimaryKey:             primaryKey})
}

func (s *sealSuite) testProtectKeyWithExternalStorageKeyErrorHandling(c *C, params *ProtectKeyParams) error {
	srk, err := s.TPM().NewResourceContext(tcg.SRKHandle)
	c.Assert(err, IsNil)

	srkPub, _, _, err := s.TPM().ReadPublic(srk)
	c.Assert(err, IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	_, _, _, sealErr := NewExternalTPMProtectedKey(srkPub, params)
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

type mockKeySealer struct {
	called bool
}

func (s *mockKeySealer) CreateSealedObject(data []byte, nameAlg tpm2.HashAlgorithmId, policy tpm2.Digest, noDA bool) (tpm2.Private, *tpm2.Public, tpm2.EncryptedSecret, error) {
	if s.called {
		return nil, nil, nil, errors.New("called more than once")
	}

	pub := objectutil.NewSealedObjectTemplate(objectutil.WithNameAlg(nameAlg))
	pub.AuthPolicy = policy

	var noDAByte byte = 0
	if noDA {
		noDAByte = 1
	}
	return append(tpm2.Private(data), noDAByte), pub, nil, nil
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
	s.AddCleanup(MockNewPolicyAuthPublicKey(func(primaryKey secboot.PrimaryKey) (*tpm2.Public, error) {
		s.lastAuthKey = primaryKey

		pub, err := NewPolicyAuthPublicKey(primaryKey)
		s.lastAuthKeyPublic = pub
		return pub, err
	}))

}

var _ = Suite(&sealSuiteNoTPM{})

type testMakeSealedKeyDataData struct {
	PCRProfile             *PCRProtectionProfile
	Role                   string
	PCRPolicyCounterHandle tpm2.Handle
	PrimaryKey             secboot.PrimaryKey
}

func (s *sealSuiteNoTPM) testMakeSealedKeyData(c *C, data *testMakeSealedKeyDataData) {
	var mockTpm *tpm2.TPMContext
	var mockSession tpm2.SessionContext
	if data.PCRPolicyCounterHandle != tpm2.HandleNull {
		mockTpm = new(tpm2.TPMContext)
		mockSession = new(mockSessionContext)
	}

	var mockPcrPolicyCounterPub *tpm2.NVPublic
	restore := MockEnsurePcrPolicyCounter(func(tpm *tpm2.TPMContext, handle tpm2.Handle, pub *tpm2.Public, session tpm2.SessionContext) (*tpm2.NVPublic, error) {
		c.Assert(mockTpm, NotNil)

		c.Check(tpm, Equals, mockTpm)
		c.Check(handle, Equals, data.PCRPolicyCounterHandle)
		c.Check(pub, Equals, s.lastAuthKeyPublic)
		c.Check(session, Equals, mockSession)

		mockPcrPolicyCounterPub = &tpm2.NVPublic{
			Index:      handle,
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVPolicyWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVNoDA),
			AuthPolicy: make([]byte, 32),
			Size:       8}

		return mockPcrPolicyCounterPub, nil
	})
	defer restore()

	var mockPolicyData *KeyDataPolicy_v3
	var mockPolicyDigest tpm2.Digest
	restore = MockNewKeyDataPolicy(func(alg tpm2.HashAlgorithmId, key *tpm2.Public, role string, pcrPolicyCounterPub *tpm2.NVPublic, requireAuthValue bool) (KeyDataPolicy, tpm2.Digest, error) {
		c.Check(alg, Equals, tpm2.HashAlgorithmSHA256)
		c.Check(key, Equals, s.lastAuthKeyPublic)
		c.Check(pcrPolicyCounterPub, Equals, mockPcrPolicyCounterPub)
		c.Check(requireAuthValue, Equals, false)

		index := tpm2.HandleNull
		if pcrPolicyCounterPub != nil {
			index = pcrPolicyCounterPub.Index
		}

		mockPolicyData = &KeyDataPolicy_v3{
			StaticData: &StaticPolicyData_v3{
				AuthPublicKey:          key,
				PCRPolicyCounterHandle: index},
			PCRData: NewPcrPolicyData_v3(
				&PcrPolicyData_v2{
					AuthorizedPolicySignature: &tpm2.Signature{SigAlg: tpm2.SigSchemeAlgNull}})}

		mockPolicyDigest = make([]byte, alg.Size())
		rand.Read(mockPolicyDigest)

		return mockPolicyData, mockPolicyDigest, nil
	})
	defer restore()

	pcrPolicyInitialized := false
	restore = MockSkdbUpdatePCRProtectionPolicyNoValidate(func(skdb *SealedKeyDataBase, tpm *tpm2.TPMContext, primaryKey secboot.PrimaryKey, role string, counterPub *tpm2.NVPublic, profile *PCRProtectionProfile, policyVersionOption PcrPolicyVersionOption) error {
		c.Check(tpm, Equals, mockTpm)
		c.Check(primaryKey, DeepEquals, s.lastAuthKey)
		c.Check(role, Equals, data.Role)
		c.Check(counterPub, Equals, mockPcrPolicyCounterPub)
		c.Check(profile, NotNil)
		if data.PCRProfile != nil {
			c.Check(profile, Equals, data.PCRProfile)
		}
		c.Check(policyVersionOption, Equals, ResetPcrPolicyVersion)
		pcrPolicyInitialized = true
		return nil
	})
	defer restore()

	var sealer mockKeySealer

	primaryKey := make(secboot.PrimaryKey, 32)
	rand.Read(primaryKey)

	params := &MakeSealedKeyDataParams{
		PcrProfile:             data.PCRProfile,
		Role:                   data.Role,
		PcrPolicyCounterHandle: data.PCRPolicyCounterHandle,
		PrimaryKey:             primaryKey,
	}

	constructor := MakeKeyDataNoAuth

	kd, pk, _, err := MakeSealedKeyData(mockTpm, params, &sealer, constructor, mockSession)
	c.Assert(err, IsNil)

	c.Assert(s.lastAuthKey, NotNil)
	c.Assert(mockPolicyData, NotNil)
	c.Assert(pcrPolicyInitialized, testutil.IsTrue)

	c.Assert(s.lastKeyParams, NotNil)
	c.Check(s.lastKeyParams.PlatformName, Equals, "tpm2")
	c.Check(s.lastKeyParams.Role, Equals, data.Role)
	c.Check(s.lastKeyParams.KDFAlg, Equals, crypto.SHA256)

	c.Check(pk, DeepEquals, primaryKey)
	c.Check(kd.Role(), DeepEquals, data.Role)

	var skd *SealedKeyData
	c.Check(kd.UnmarshalPlatformHandle(&skd), IsNil)

	c.Check(skd.Data().Policy(), tpm2_testutil.TPMValueDeepEquals, mockPolicyData)
	c.Check(skd.Data().Public().NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(skd.Data().Public().AuthPolicy, DeepEquals, mockPolicyDigest)

	payload := make([]byte, len(s.lastKeyParams.EncryptedPayload))

	c.Assert(skd.Data().Private(), HasLen, 45)
	b, err := aes.NewCipher(skd.Data().Private()[:32])
	c.Assert(err, IsNil)

	aad, err := mu.MarshalToBytes(&AdditionalData_v3{
		Generation: uint32(kd.Generation()),
		Role:       []byte(data.Role),
		KDFAlg:     tpm2.HashAlgorithmSHA256,
		AuthMode:   kd.AuthMode(),
	})

	aead, err := cipher.NewGCM(b)
	c.Assert(err, IsNil)

	payload, err = aead.Open(nil, skd.Data().Private()[32:44], s.lastKeyParams.EncryptedPayload, aad)
	c.Assert(err, IsNil)

	keys, err := unmarshalProtectedKeys(payload)
	c.Check(err, IsNil)

	c.Check(keys.Primary, DeepEquals, primaryKey)

	c.Check(skd.Data().Policy().ValidateAuthKey(keys.Primary), IsNil)
}

func (s *sealSuiteNoTPM) TestMakeSealedKeyData(c *C) {
	s.testMakeSealedKeyData(c, &testMakeSealedKeyDataData{
		PCRProfile:             NewPCRProtectionProfile(),
		PCRPolicyCounterHandle: 0x01800000,
		Role:                   "",
	})
}

func (s *sealSuiteNoTPM) TestMakeSealedKeyData2(c *C) {
	s.testMakeSealedKeyData(c, &testMakeSealedKeyDataData{
		PCRProfile:             NewPCRProtectionProfile(),
		PCRPolicyCounterHandle: 0x01800000,
		Role:                   "test",
	})
}
