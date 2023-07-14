// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type sealLegacySuite struct {
	tpm2test.TPMTest
	primaryKeyMixin
}

func (s *sealLegacySuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeatureLockoutHierarchy | // Allow the test fixture to reset the DA counter
		tpm2test.TPMFeaturePCR |
		tpm2test.TPMFeatureNV
}

func (s *sealLegacySuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)

	s.primaryKeyMixin.tpmTest = &s.TPMTest.TPMTest
	c.Assert(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil),
		testutil.InSlice(Equals), []error{ErrTPMProvisioningRequiresLockout, nil})
}

var _ = Suite(&sealLegacySuite{})

func (s *sealLegacySuite) testSealKeyToTPM(c *C, params *KeyCreationParams) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	dir := c.MkDir()
	path := filepath.Join(dir, "key")

	authKey, err := SealKeyToTPM(s.TPM(), key, path, params)
	c.Check(err, IsNil)
	c.Check(ValidateKeyDataFile(s.TPM().TPMContext, path, authKey, s.TPM().HmacSession()), IsNil)

	k, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	c.Check(k.Version(), Equals, uint32(1))
	c.Check(k.PCRPolicyCounterHandle(), Equals, params.PCRPolicyCounterHandle)

	if params.AuthKey != nil {
		c.Check(authKey, DeepEquals, secboot.PrimaryKey(params.AuthKey.D.Bytes()))
	}

	keyUnsealed, authKeyUnsealed, err := k.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)

	if params.PCRProfile != nil {
		// Verify that the key is sealed with the supplied PCR profile by changing
		// the PCR values.
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
		c.Check(err, IsNil)
		_, _, err = k.UnsealFromTPM(s.TPM())
		c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
			"cannot execute PolicyOR assertions: current session digest not found in policy data")
	}
}

func (s *sealLegacySuite) TestSealKeyToTPM(c *C) {
	s.testSealKeyToTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
}

func (s *sealLegacySuite) TestSealKeyToTPMDifferentPCRPolicyCounterHandle(c *C) {
	s.testSealKeyToTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)})
}

func (s *sealLegacySuite) TestSealKeyToTPMWithNewConnection(c *C) {
	// SealKeyToTPM behaves slightly different if called immediately after
	// EnsureProvisioned with the same Connection
	s.ReinitTPMConnectionFromExisting(c)

	s.testSealKeyToTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
}

func (s *sealLegacySuite) TestSealKeyToTPMMissingSRK(c *C) {
	// Ensure that calling SealKeyToTPM recreates the SRK with the standard template
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

	s.ReinitTPMConnectionFromExisting(c)

	s.testSealKeyToTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})

	s.validateSRK(c)
}

func (s *sealLegacySuite) TestSealKeyToTPMMissingCustomSRK(c *C) {
	// Ensure that calling SealKeyToTPM recreates the SRK with the custom
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

	s.testSealKeyToTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})

	s.validatePrimaryKeyAgainstTemplate(c, tpm2.HandleOwner, tcg.SRKHandle, template)
}

func (s *sealLegacySuite) TestSealKeyToTPMMissingSRKWithInvalidCustomTemplate(c *C) {
	// Ensure that calling SealKeyToTPM recreates the SRK with the standard
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

	s.testSealKeyToTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})

	s.validateSRK(c)
}

func (s *sealLegacySuite) TestSealKeyToTPMNilPCRProfile(c *C) {
	s.testSealKeyToTPM(c, &KeyCreationParams{PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
}

func (s *sealLegacySuite) TestSealKeyToTPMNoPCRPolicyCounterHandle(c *C) {
	s.testSealKeyToTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *sealLegacySuite) TestSealKeyToTPMWithProvidedAuthKey(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Check(err, IsNil)

	s.testSealKeyToTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		AuthKey:                authKey})
}

type testSealKeyToTPMMultipleData struct {
	n      int
	params *KeyCreationParams
}

func (s *sealLegacySuite) testSealKeyToTPMMultiple(c *C, data *testSealKeyToTPMMultipleData) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	dir := c.MkDir()

	var requests []*SealKeyRequest
	for i := 0; i < data.n; i++ {
		requests = append(requests, &SealKeyRequest{Key: key, Path: filepath.Join(dir, fmt.Sprintf("key%d", i))})
	}

	authKey, err := SealKeyToTPMMultiple(s.TPM(), requests, data.params)
	c.Check(err, IsNil)
	for _, r := range requests {
		c.Check(ValidateKeyDataFile(s.TPM().TPMContext, r.Path, authKey, s.TPM().HmacSession()), IsNil)

		k, err := ReadSealedKeyObjectFromFile(r.Path)
		c.Assert(err, IsNil)

		c.Check(k.Version(), Equals, uint32(1))
		c.Check(k.PCRPolicyCounterHandle(), Equals, data.params.PCRPolicyCounterHandle)

		keyUnsealed, authKeyUnsealed, err := k.UnsealFromTPM(s.TPM())
		c.Check(err, IsNil)
		c.Check(keyUnsealed, DeepEquals, key)
		c.Check(authKeyUnsealed, DeepEquals, authKey)
	}

	if data.params.AuthKey != nil {
		c.Check(authKey, DeepEquals, secboot.PrimaryKey(data.params.AuthKey.D.Bytes()))
	}

	if data.params.PCRProfile != nil {
		// Verify that the keys are sealed with the supplied PCR profile by changing
		// the PCR values.
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
		c.Check(err, IsNil)

		for _, r := range requests {
			k, err := ReadSealedKeyObjectFromFile(r.Path)
			c.Assert(err, IsNil)

			_, _, err = k.UnsealFromTPM(s.TPM())
			c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
				"cannot execute PolicyOR assertions: current session digest not found in policy data")
		}
	}
}

func (s *sealLegacySuite) TestSealKeyToTPMMultipleSingle(c *C) {
	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 1,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)}})
}

func (s *sealLegacySuite) TestSealKeyToTPMMultiple2Keys(c *C) {
	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 2,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)}})
}

func (s *sealLegacySuite) TestSealKeyToTPMMultipleDifferentPCRPolicyCounterHandle(c *C) {
	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 2,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}})
}

func (s *sealLegacySuite) TestSealKeyToTPMMultipleWithNewConnection(c *C) {
	// SealKeyToTPMMultiple behaves slightly different if called immediately
	// after EnsureProvisioned with the same Connection
	s.ReinitTPMConnectionFromExisting(c)

	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 2,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)}})
}

func (s *sealLegacySuite) TestSealKeyToTPMMultipleMissingSRK(c *C) {
	// Ensure that calling SealKeyToTPMMultiple recreates the SRK with the standard
	// template
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)
	s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

	s.ReinitTPMConnectionFromExisting(c)

	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 2,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)}})

	s.validateSRK(c)
}

func (s *sealLegacySuite) TestSealKeyToTPMMultipleNilPCRProfile(c *C) {
	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n:      1,
		params: &KeyCreationParams{PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)}})
}

func (s *sealLegacySuite) TestSealKeyToTPMMultipleNoPCRPolicyCounterHandle(c *C) {
	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 2,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: tpm2.HandleNull}})
}

func (s *sealLegacySuite) TestSealKeyToTPMMultipleWithProvidedAuthKey(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Check(err, IsNil)

	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 2,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			AuthKey:                authKey}})
}

func (s *sealLegacySuite) testSealKeyToTPMErrorHandling(c *C, params *KeyCreationParams) error {
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

	dir := c.MkDir()
	path := filepath.Join(dir, "key")

	_, sealErr := SealKeyToTPM(s.TPM(), key, path, params)

	_, err := os.Stat(path)
	c.Check(err, testutil.ErrorIs, os.ErrNotExist)

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

func (s *sealLegacySuite) TestSealKeyToTPMErrorHandlingNilParams(c *C) {
	c.Check(s.testSealKeyToTPMErrorHandling(c, nil), ErrorMatches, "no KeyCreationParams provided")
}

func (s *sealLegacySuite) TestSealKeyToTPMErrorHandlingOwnerAuthFail(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
	s.TPM().OwnerHandleContext().SetAuthValue(nil)

	err := s.testSealKeyToTPMErrorHandling(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Assert(err, testutil.ConvertibleTo, AuthFailError{})
	c.Check(err.(AuthFailError).Handle, Equals, tpm2.HandleOwner)
}

func (s *sealLegacySuite) TestSealKeyToTPMErrorHandlingPCRPolicyCounterExists(c *C) {
	public := tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181ffff),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead),
		Size:    0}
	s.NVDefineSpace(c, tpm2.HandleOwner, nil, &public)

	err := s.testSealKeyToTPMErrorHandling(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: public.Index})
	c.Assert(err, testutil.ConvertibleTo, TPMResourceExistsError{})
	c.Check(err.(TPMResourceExistsError).Handle, Equals, public.Index)
}

func (s *sealLegacySuite) TestSealKeyToTPMErrorHandlingInvalidPCRProfile(c *C) {
	err := s.testSealKeyToTPMErrorHandling(c, &KeyCreationParams{
		PCRProfile: tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}).
			AddProfileOR(
				NewPCRProtectionProfile(),
				NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 8)),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Check(err, ErrorMatches, "cannot create initial PCR policy: cannot compute PCR digests from protection profile: "+
		"not all branches contain values for the same sets of PCRs")
}

func (s *sealLegacySuite) TestSealKeyToTPMErrorHandlingInvalidPCRProfileSelection(c *C) {
	err := s.testSealKeyToTPMErrorHandling(c, &KeyCreationParams{
		PCRProfile:             NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 50, make([]byte, tpm2.HashAlgorithmSHA256.Size())),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Check(err, ErrorMatches, "cannot create initial PCR policy: PCR protection profile contains digests for unsupported PCRs")
}

func (s *sealLegacySuite) TestSealKeyToTPMErrorHandlingWrongCurve(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P384(), testutil.RandReader)
	c.Check(err, IsNil)

	err = s.testSealKeyToTPMErrorHandling(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		AuthKey:                authKey})
	c.Check(err, ErrorMatches, "provided AuthKey must be from elliptic.P256, no other curve is supported")
}

func (s *sealLegacySuite) testSealKeyToExternalTPMStorageKey(c *C, params *KeyCreationParams) {
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)

	srkPub, _, _, err := s.TPM().ReadPublic(srk)
	c.Assert(err, IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	dir := c.MkDir()
	path := filepath.Join(dir, "key")

	authKey, err := SealKeyToExternalTPMStorageKey(srkPub, key, path, params)
	c.Check(err, IsNil)
	c.Check(ValidateKeyDataFile(s.TPM().TPMContext, path, authKey, s.TPM().HmacSession()), IsNil)

	k, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	c.Check(k.Version(), Equals, uint32(2))
	c.Check(k.PCRPolicyCounterHandle(), Equals, params.PCRPolicyCounterHandle)

	if params.AuthKey != nil {
		c.Check(authKey, DeepEquals, secboot.PrimaryKey(params.AuthKey.D.Bytes()))
	}

	keyUnsealed, authKeyUnsealed, err := k.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)

	if params.PCRProfile != nil {
		// Verify that the key is sealed with the supplied PCR profile by changing
		// the PCR values.
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
		c.Check(err, IsNil)
		_, _, err = k.UnsealFromTPM(s.TPM())
		c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
			"cannot execute PolicyOR assertions: current session digest not found in policy data")
	}
}

func (s *sealLegacySuite) TestSealKeyToExternalTPMStorageKey(c *C) {
	s.testSealKeyToExternalTPMStorageKey(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *sealLegacySuite) TestSealKeyToExternalTPMStorageKeyNilPCRProfile(c *C) {
	s.testSealKeyToExternalTPMStorageKey(c, &KeyCreationParams{
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *sealLegacySuite) TestSealKeyToExternalTPMStorageKeyWithProvidedAuthKey(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Check(err, IsNil)

	s.testSealKeyToExternalTPMStorageKey(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
		AuthKey:                authKey})
}

func (s *sealLegacySuite) testSealKeyToExternalTPMStorageKeyErrorHandling(c *C, params *KeyCreationParams) error {
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)

	srkPub, _, _, err := s.TPM().ReadPublic(srk)
	c.Assert(err, IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	dir := c.MkDir()
	path := filepath.Join(dir, "key")

	_, sealErr := SealKeyToExternalTPMStorageKey(srkPub, key, path, params)

	_, err = os.Stat(path)
	c.Check(err, testutil.ErrorIs, os.ErrNotExist)

	return sealErr
}

func (s *sealLegacySuite) TestSealKeyToExternalTPMStorageKeyErrorHandlingNilParams(c *C) {
	c.Check(s.testSealKeyToExternalTPMStorageKeyErrorHandling(c, nil), ErrorMatches, "no KeyCreationParams provided")
}

func (s *sealLegacySuite) TestSealKeyToExternalTPMStorageKeyErrorHandlingInvalidPCRProfile(c *C) {
	err := s.testSealKeyToExternalTPMStorageKeyErrorHandling(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, ErrorMatches, "cannot create initial PCR policy: cannot compute PCR digests from protection profile: "+
		"cannot read current PCR values from TPM: no context")
}

func (s *sealLegacySuite) TestSealKeyToExternalTPMStorageKeyErrorHandlingInvalidPCRProfileSelection(c *C) {
	err := s.testSealKeyToExternalTPMStorageKeyErrorHandling(c, &KeyCreationParams{
		PCRProfile:             NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 50, make([]byte, tpm2.HashAlgorithmSHA256.Size())),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, ErrorMatches, "cannot create initial PCR policy: PCR protection profile contains digests for unsupported PCRs")
}

func (s *sealLegacySuite) TestSealKeyToExternalTPMStorageKeyErrorHandlingWrongCurve(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P384(), testutil.RandReader)
	c.Check(err, IsNil)

	err = s.testSealKeyToExternalTPMStorageKeyErrorHandling(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
		AuthKey:                authKey})
	c.Check(err, ErrorMatches, "provided AuthKey must be from elliptic.P256, no other curve is supported")
}

func (s *sealLegacySuite) TestSealKeyToExternalTPMStorageKeyErrorHandlingWithPCRPolicyCounter(c *C) {
	err := s.testSealKeyToExternalTPMStorageKeyErrorHandling(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Check(err, ErrorMatches, "PCRPolicyCounter must be tpm2.HandleNull when creating an importable sealed key")
}
