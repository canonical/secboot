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
		tpm2_testutil.InSlice(Equals), []error{ErrTPMProvisioningRequiresLockout, nil})
}

var _ = Suite(&sealSuite{})

func (s *sealSuite) testSealKeyToTPM(c *C, params *KeyCreationParams) {
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
		c.Check(authKey, DeepEquals, secboot.AuxiliaryKey(params.AuthKey.D.Bytes()))
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

func (s *sealSuite) TestSealKeyToTPM(c *C) {
	s.testSealKeyToTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
}

func (s *sealSuite) TestSealKeyToTPMDifferentPCRPolicyCounterHandle(c *C) {
	s.testSealKeyToTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)})
}

func (s *sealSuite) TestSealKeyToTPMWithNewConnection(c *C) {
	// SealKeyToTPM behaves slightly different if called immediately after
	// EnsureProvisioned with the same Connection
	s.ReinitTPMConnectionFromExisting(c)

	s.testSealKeyToTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
}

func (s *sealSuite) TestSealKeyToTPMMissingSRK(c *C) {
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

func (s *sealSuite) TestSealKeyToTPMMissingCustomSRK(c *C) {
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

func (s *sealSuite) TestSealKeyToTPMMissingSRKWithInvalidCustomTemplate(c *C) {
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

func (s *sealSuite) TestSealKeyToTPMNilPCRProfile(c *C) {
	s.testSealKeyToTPM(c, &KeyCreationParams{PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
}

func (s *sealSuite) TestSealKeyToTPMNoPCRPolicyCounterHandle(c *C) {
	s.testSealKeyToTPM(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *sealSuite) TestSealKeyToTPMWithProvidedAuthKey(c *C) {
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

func (s *sealSuite) testSealKeyToTPMMultiple(c *C, data *testSealKeyToTPMMultipleData) {
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
		c.Check(authKey, DeepEquals, secboot.AuxiliaryKey(data.params.AuthKey.D.Bytes()))
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

func (s *sealSuite) TestSealKeyToTPMMultipleSingle(c *C) {
	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 1,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)}})
}

func (s *sealSuite) TestSealKeyToTPMMultiple2Keys(c *C) {
	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 2,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)}})
}

func (s *sealSuite) TestSealKeyToTPMMultipleDifferentPCRPolicyCounterHandle(c *C) {
	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 2,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}})
}

func (s *sealSuite) TestSealKeyToTPMMultipleWithNewConnection(c *C) {
	// SealKeyToTPMMultiple behaves slightly different if called immediately
	// after EnsureProvisioned with the same Connection
	s.ReinitTPMConnectionFromExisting(c)

	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 2,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)}})
}

func (s *sealSuite) TestSealKeyToTPMMultipleMissingSRK(c *C) {
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

func (s *sealSuite) TestSealKeyToTPMMultipleNilPCRProfile(c *C) {
	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n:      1,
		params: &KeyCreationParams{PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)}})
}

func (s *sealSuite) TestSealKeyToTPMMultipleNoPCRPolicyCounterHandle(c *C) {
	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 2,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: tpm2.HandleNull}})
}

func (s *sealSuite) TestSealKeyToTPMMultipleWithProvidedAuthKey(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Check(err, IsNil)

	s.testSealKeyToTPMMultiple(c, &testSealKeyToTPMMultipleData{
		n: 2,
		params: &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
			AuthKey:                authKey}})
}

func (s *sealSuite) testSealKeyToTPMErrorHandling(c *C, params *KeyCreationParams) error {
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
	c.Check(err, tpm2_testutil.ErrorIs, os.ErrNotExist)

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

func (s *sealSuite) TestSealKeyToTPMErrorHandlingNilParams(c *C) {
	c.Check(s.testSealKeyToTPMErrorHandling(c, nil), ErrorMatches, "no KeyCreationParams provided")
}

func (s *sealSuite) TestSealKeyToTPMErrorHandlingOwnerAuthFail(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
	s.TPM().OwnerHandleContext().SetAuthValue(nil)

	err := s.testSealKeyToTPMErrorHandling(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Assert(err, tpm2_testutil.ConvertibleTo, AuthFailError{})
	c.Check(err.(AuthFailError).Handle, Equals, tpm2.HandleOwner)
}

func (s *sealSuite) TestSealKeyToTPMErrorHandlingPCRPolicyCounterExists(c *C) {
	public := tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181ffff),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead),
		Size:    0}
	s.NVDefineSpace(c, tpm2.HandleOwner, nil, &public)

	err := s.testSealKeyToTPMErrorHandling(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: public.Index})
	c.Assert(err, tpm2_testutil.ConvertibleTo, TPMResourceExistsError{})
	c.Check(err.(TPMResourceExistsError).Handle, Equals, public.Index)
}

func (s *sealSuite) TestSealKeyToTPMErrorHandlingInvalidPCRProfile(c *C) {
	err := s.testSealKeyToTPMErrorHandling(c, &KeyCreationParams{
		PCRProfile: tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}).
			AddProfileOR(
				NewPCRProtectionProfile(),
				NewPCRProtectionProfile().AddPCRValueFromTPM(tpm2.HashAlgorithmSHA256, 8)),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Check(err, ErrorMatches, "cannot create initial PCR policy: cannot compute PCR digests from protection profile: "+
		"not all branches contain values for the same sets of PCRs")
}

func (s *sealSuite) TestSealKeyToTPMErrorHandlingInvalidPCRProfileSelection(c *C) {
	err := s.testSealKeyToTPMErrorHandling(c, &KeyCreationParams{
		PCRProfile:             NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 50, make([]byte, tpm2.HashAlgorithmSHA256.Size())),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Check(err, ErrorMatches, "cannot create initial PCR policy: PCR protection profile contains digests for unsupported PCRs")
}

func (s *sealSuite) TestSealKeyToTPMErrorHandlingWrongCurve(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P384(), testutil.RandReader)
	c.Check(err, IsNil)

	err = s.testSealKeyToTPMErrorHandling(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		AuthKey:                authKey})
	c.Check(err, ErrorMatches, "provided AuthKey must be from elliptic.P256, no other curve is supported")
}

func (s *sealSuite) testSealKeyToExternalTPMStorageKey(c *C, params *KeyCreationParams) {
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
		c.Check(authKey, DeepEquals, secboot.AuxiliaryKey(params.AuthKey.D.Bytes()))
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

func (s *sealSuite) TestSealKeyToExternalTPMStorageKey(c *C) {
	s.testSealKeyToExternalTPMStorageKey(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *sealSuite) TestSealKeyToExternalTPMStorageKeyNilPCRProfile(c *C) {
	s.testSealKeyToExternalTPMStorageKey(c, &KeyCreationParams{
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *sealSuite) TestSealKeyToExternalTPMStorageKeyWithProvidedAuthKey(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Check(err, IsNil)

	s.testSealKeyToExternalTPMStorageKey(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
		AuthKey:                authKey})
}

func (s *sealSuite) testSealKeyToExternalTPMStorageKeyErrorHandling(c *C, params *KeyCreationParams) error {
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
	c.Check(err, tpm2_testutil.ErrorIs, os.ErrNotExist)

	return sealErr
}

func (s *sealSuite) TestSealKeyToExternalTPMStorageKeyErrorHandlingNilParams(c *C) {
	c.Check(s.testSealKeyToExternalTPMStorageKeyErrorHandling(c, nil), ErrorMatches, "no KeyCreationParams provided")
}

func (s *sealSuite) TestSealKeyToExternalTPMStorageKeyErrorHandlingInvalidPCRProfile(c *C) {
	err := s.testSealKeyToExternalTPMStorageKeyErrorHandling(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, ErrorMatches, "cannot create initial PCR policy: cannot compute PCR digests from protection profile: "+
		"cannot read current value of PCR 7 from bank TPM_ALG_SHA256: no TPM context")
}

func (s *sealSuite) TestSealKeyToExternalTPMStorageKeyErrorHandlingInvalidPCRProfileSelection(c *C) {
	err := s.testSealKeyToExternalTPMStorageKeyErrorHandling(c, &KeyCreationParams{
		PCRProfile:             NewPCRProtectionProfile().AddPCRValue(tpm2.HashAlgorithmSHA256, 50, make([]byte, tpm2.HashAlgorithmSHA256.Size())),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, ErrorMatches, "cannot create initial PCR policy: PCR protection profile contains digests for unsupported PCRs")
}

func (s *sealSuite) TestSealKeyToExternalTPMStorageKeyErrorHandlingWrongCurve(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P384(), testutil.RandReader)
	c.Check(err, IsNil)

	err = s.testSealKeyToExternalTPMStorageKeyErrorHandling(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
		AuthKey:                authKey})
	c.Check(err, ErrorMatches, "provided AuthKey must be from elliptic.P256, no other curve is supported")
}

func (s *sealSuite) TestSealKeyToExternalTPMStorageKeyErrorHandlingWithPCRPolicyCounter(c *C) {
	err := s.testSealKeyToExternalTPMStorageKeyErrorHandling(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Check(err, ErrorMatches, "PCRPolicyCounter must be tpm2.HandleNull when creating an importable sealed key")
}

func (s *sealSuite) testUpdatePCRProtectionPolicy(c *C, params *KeyCreationParams) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	dir := c.MkDir()
	path := filepath.Join(dir, "key")

	authKey, err := SealKeyToTPM(s.TPM(), key, path, params)
	c.Check(err, IsNil)

	k, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	c.Check(k.UpdatePCRProtectionPolicy(s.TPM(), authKey, tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23})), IsNil)

	_, _, err = k.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)

	_, err = s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)
	_, _, err = k.UnsealFromTPM(s.TPM())
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
		"cannot execute PolicyOR assertions: current session digest not found in policy data")
}

func (s *sealSuite) TestUpdatePCRProtectionPolicyWithPCRPolicyCounter(c *C) {
	s.testUpdatePCRProtectionPolicy(c, &KeyCreationParams{PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
}

func (s *sealSuite) TestUpdatePCRProtectionPolicyNoPCRPolicyCounter(c *C) {
	s.testUpdatePCRProtectionPolicy(c, &KeyCreationParams{PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *sealSuite) TestUpdatePCRProtectionPolicyWithProvidedAuthKey(c *C) {
	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Check(err, IsNil)

	s.testUpdatePCRProtectionPolicy(c, &KeyCreationParams{
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000),
		AuthKey:                authKey})
}

func (s *sealSuite) testRevokeOldPCRProtectionPolicies(c *C, params *KeyCreationParams) error {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	dir := c.MkDir()
	path := filepath.Join(dir, "key")

	authKey, err := SealKeyToTPM(s.TPM(), key, path, params)
	c.Check(err, IsNil)

	k2, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	c.Check(k2.UpdatePCRProtectionPolicy(s.TPM(), authKey, params.PCRProfile), IsNil)

	k1, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	_, _, err = k1.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)
	_, _, err = k2.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)

	c.Check(k1.RevokeOldPCRProtectionPolicies(s.TPM(), authKey), IsNil)

	_, _, err = k1.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)
	_, _, err = k2.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)

	c.Check(k2.RevokeOldPCRProtectionPolicies(s.TPM(), authKey), IsNil)

	_, _, err = k2.UnsealFromTPM(s.TPM())
	c.Check(err, IsNil)
	_, _, err = k1.UnsealFromTPM(s.TPM())
	return err
}

func (s *sealSuite) TestRevokeOldPCRProtectionPoliciesWithPCRPolicyCounter(c *C) {
	err := s.testRevokeOldPCRProtectionPolicies(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: the PCR policy has been revoked")
}

func (s *sealSuite) TestRevokeOldPCRProtectionPoliciesWithoutPCRPolicyCounter(c *C) {
	err := s.testRevokeOldPCRProtectionPolicies(c, &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)
}

func (s *sealSuite) TestUpdateKeyPCRProtectionPolicyMultiple(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	dir := c.MkDir()

	var requests []*SealKeyRequest
	for i := 0; i < 2; i++ {
		requests = append(requests, &SealKeyRequest{Key: key, Path: filepath.Join(dir, fmt.Sprintf("key%d", i))})
	}

	authKey, err := SealKeyToTPMMultiple(s.TPM(), requests, &KeyCreationParams{PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000)})
	c.Check(err, IsNil)

	var keys []*SealedKeyObject
	for _, r := range requests {
		k, err := ReadSealedKeyObjectFromFile(r.Path)
		c.Assert(err, IsNil)
		keys = append(keys, k)
	}

	c.Check(UpdateKeyPCRProtectionPolicyMultiple(s.TPM(), keys, authKey, tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23})), IsNil)

	for _, k := range keys {
		_, _, err := k.UnsealFromTPM(s.TPM())
		c.Check(err, IsNil)
	}

	_, err = s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	for _, k := range keys {
		_, _, err = k.UnsealFromTPM(s.TPM())
		c.Check(err, ErrorMatches, "invalid key data: cannot complete authorization policy assertions: cannot execute PCR assertions: "+
			"cannot execute PolicyOR assertions: current session digest not found in policy data")
	}
}

func (s *sealSuite) TestUpdateKeyPCRProtectionPolicyMultipleUnrelated1(c *C) {
	// Test that UpdateKeyPCRProtectionPolicyMultiple rejects keys that have the
	// same auth key, but different policies because they use independent PCR policy
	// counters.
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	authKey, err := ecdsa.GenerateKey(elliptic.P256(), testutil.RandReader)
	c.Assert(err, IsNil)

	dir := c.MkDir()

	var keys []*SealedKeyObject
	for i := 0; i < 3; i++ {
		path := filepath.Join(dir, fmt.Sprintf("key%d", i))
		params := &KeyCreationParams{
			PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
			PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x01810000+tpm2.Handle(i)),
			AuthKey:                authKey}
		_, err := SealKeyToTPM(s.TPM(), key, path, params)
		c.Check(err, IsNil)

		k, err := ReadSealedKeyObjectFromFile(path)
		c.Assert(err, IsNil)

		keys = append(keys, k)
	}

	err = UpdateKeyPCRProtectionPolicyMultiple(s.TPM(), keys, authKey.D.Bytes(), nil)
	c.Check(err, ErrorMatches, "invalid key data: key data at index 0 is not related to the primary key data")
}

func (s *sealSuite) TestUpdateKeyPCRProtectionPolicyMultipleUnrelated2(c *C) {
	// Test that UpdateKeyPCRProtectionPolicyMultiple rejects keys that use different
	// auth keys.
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	dir := c.MkDir()

	var keys []*SealedKeyObject

	path := filepath.Join(dir, "key")
	params := &KeyCreationParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull}
	authKey, err := SealKeyToTPM(s.TPM(), key, path, params)
	c.Check(err, IsNil)

	k, err := ReadSealedKeyObjectFromFile(path)
	c.Assert(err, IsNil)

	keys = append(keys, k)

	for i := 0; i < 2; i++ {
		path := filepath.Join(dir, fmt.Sprintf("key%d", i))
		_, err := SealKeyToTPM(s.TPM(), key, path, params)
		c.Check(err, IsNil)

		k, err := ReadSealedKeyObjectFromFile(path)
		c.Assert(err, IsNil)

		keys = append(keys, k)
	}

	err = UpdateKeyPCRProtectionPolicyMultiple(s.TPM(), keys, authKey, nil)
	c.Check(err, ErrorMatches, "invalid key data: key data at index 0 is not related to the primary key data")
}
