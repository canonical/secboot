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
	"encoding/json"
	gohash "hash"
	"io"
	"math/rand"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/policyutil"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2_device"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type platformSuite struct {
	tpm2test.TPMTest

	lastEncryptedPayload []byte
}

func (s *platformSuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureOwnerHierarchy |
		tpm2test.TPMFeatureEndorsementHierarchy |
		tpm2test.TPMFeatureLockoutHierarchy |
		tpm2test.TPMFeaturePCR |
		tpm2test.TPMFeatureNV
}

func (s *platformSuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)

	c.Check(s.TPM().EnsureProvisioned(ProvisionModeWithoutLockout, nil), Equals, ErrTPMProvisioningRequiresLockout)

	s.lastEncryptedPayload = nil
	s.AddCleanup(MockSecbootNewKeyData(func(params *secboot.KeyParams) (*secboot.KeyData, error) {
		s.lastEncryptedPayload = params.EncryptedPayload
		return secboot.NewKeyData(params)
	}))
	origKdf := secboot.SetArgon2KDF(&testutil.MockArgon2KDF{})
	s.AddCleanup(func() { secboot.SetArgon2KDF(origKdf) })
}

var _ = Suite(&platformSuite{})

func (s *platformSuite) TestRecoverKeysIntegrated(c *C) {
	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	}

	k, primaryKey, unlockKey, err := NewTPMProtectedKey(s.TPM(), params)
	c.Assert(err, IsNil)

	s.AddCleanup(s.CloseMockConnection(c))

	unlockKeyUnsealed, primaryKeyUnsealed, err := k.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(unlockKeyUnsealed, DeepEquals, unlockKey)
	c.Check(primaryKeyUnsealed, DeepEquals, primaryKey)
}

func (s *platformSuite) TestRecoverKeysWithPassphraseIntegrated(c *C) {
	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	}

	passphraseParams := &PassphraseProtectKeyParams{
		ProtectKeyParams: *params,
	}

	k, primaryKey, unlockKey, err := NewTPMPassphraseProtectedKey(s.TPM(), passphraseParams, "passphrase")
	c.Assert(err, IsNil)

	s.AddCleanup(s.CloseMockConnection(c))

	unlockKeyUnsealed, primaryKeyUnsealed, err := k.RecoverKeysWithPassphrase("passphrase")
	c.Check(err, IsNil)
	c.Check(unlockKeyUnsealed, DeepEquals, unlockKey)
	c.Check(primaryKeyUnsealed, DeepEquals, primaryKey)
}

func (s *platformSuite) TestRecoverKeysWithPassphraseIntegratedPBKDF2(c *C) {
	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	}

	passphraseParams := &PassphraseProtectKeyParams{
		ProtectKeyParams: *params,
		KDFOptions:       new(secboot.PBKDF2Options),
	}

	k, primaryKey, unlockKey, err := NewTPMPassphraseProtectedKey(s.TPM(), passphraseParams, "passphrase")
	c.Assert(err, IsNil)

	s.AddCleanup(s.CloseMockConnection(c))

	unlockKeyUnsealed, primaryKeyUnsealed, err := k.RecoverKeysWithPassphrase("passphrase")
	c.Check(err, IsNil)
	c.Check(unlockKeyUnsealed, DeepEquals, unlockKey)
	c.Check(primaryKeyUnsealed, DeepEquals, primaryKey)
}

func (s *platformSuite) TestRecoverKeysWithBadPassphraseIntegrated(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	}

	passphraseParams := &PassphraseProtectKeyParams{
		ProtectKeyParams: *params,
	}

	k, _, _, err := NewTPMPassphraseProtectedKey(s.TPM(), passphraseParams, "passphrase")
	c.Assert(err, IsNil)

	s.AddCleanup(s.CloseMockConnection(c))

	_, _, err = k.RecoverKeysWithPassphrase("1234")
	c.Check(err, Equals, secboot.ErrInvalidPassphrase)
}

func (s *platformSuite) TestChangePassphraseIntegrated(c *C) {
	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	}

	passphraseParams := &PassphraseProtectKeyParams{
		ProtectKeyParams: *params,
	}

	k, primaryKey, unlockKey, err := NewTPMPassphraseProtectedKey(s.TPM(), passphraseParams, "passphrase")
	c.Assert(err, IsNil)

	s.AddCleanup(s.CloseMockConnection(c))

	c.Check(k.ChangePassphrase("passphrase", "1234"), IsNil)

	unlockKeyUnsealed, primaryKeyUnsealed, err := k.RecoverKeysWithPassphrase("1234")
	c.Check(err, IsNil)
	c.Check(unlockKeyUnsealed, DeepEquals, unlockKey)
	c.Check(primaryKeyUnsealed, DeepEquals, primaryKey)
}

func (s *platformSuite) TestChangePassphraseWithBadPassphraseIntegrated(c *C) {
	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	}

	passphraseParams := &PassphraseProtectKeyParams{
		ProtectKeyParams: *params,
	}

	k, primaryKey, unlockKey, err := NewTPMPassphraseProtectedKey(s.TPM(), passphraseParams, "passphrase")
	c.Assert(err, IsNil)

	s.AddCleanup(s.CloseMockConnection(c))

	c.Check(k.ChangePassphrase("1234", "1234"), Equals, secboot.ErrInvalidPassphrase)

	unlockKeyUnsealed, primaryKeyUnsealed, err := k.RecoverKeysWithPassphrase("passphrase")
	c.Check(err, IsNil)
	c.Check(unlockKeyUnsealed, DeepEquals, unlockKey)
	c.Check(primaryKeyUnsealed, DeepEquals, primaryKey)
}

func (s *platformSuite) verifyASN1(c *C, data []byte) (primaryKey, unique []byte) {
	d := cryptobyte.String(data)
	c.Assert(d.ReadASN1(&d, cryptobyte_asn1.SEQUENCE), Equals, true)

	primaryKey = make([]byte, 32)
	unique = make([]byte, 32)

	c.Assert(d.ReadASN1Bytes(&primaryKey, cryptobyte_asn1.OCTET_STRING), Equals, true)
	c.Assert(d.ReadASN1Bytes(&unique, cryptobyte_asn1.OCTET_STRING), Equals, true)

	return primaryKey, unique
}

func (s *platformSuite) testRecoverKeys(c *C, params *ProtectKeyParams) {
	k, primaryKey, unlockKey, err := NewTPMProtectedKey(s.TPM(), params)
	c.Assert(err, IsNil)

	s.AddCleanup(s.CloseMockConnection(c))

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	platformKeyData := &secboot.PlatformKeyData{
		Generation:    k.Generation(),
		EncodedHandle: platformHandle,
		KDFAlg:        crypto.Hash(crypto.SHA256),
		AuthMode:      k.AuthMode(),
	}

	var handler PlatformKeyDataHandler
	payload, err := handler.RecoverKeys(platformKeyData, s.lastEncryptedPayload)
	c.Assert(err, IsNil)

	pk, u := s.verifyASN1(c, payload)
	c.Check(primaryKey, DeepEquals, secboot.PrimaryKey(pk))

	uk := make([]byte, len(pk))
	r := hkdf.New(func() gohash.Hash { return crypto.SHA256.New() }, pk, u, []byte("UNLOCK"))
	_, err = io.ReadFull(r, uk)
	c.Assert(err, IsNil)
	c.Check(unlockKey, DeepEquals, secboot.DiskUnlockKey(uk))
}

func (s *platformSuite) TestRecoverKeysSimplePCRProfile(c *C) {
	s.testRecoverKeys(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	})
}

func (s *platformSuite) TestRecoverKeysNilPCRProfile(c *C) {
	s.testRecoverKeys(c, &ProtectKeyParams{
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)})
}

func (s *platformSuite) TestRecoverKeysNoPCRPolicyCounter(c *C) {
	s.testRecoverKeys(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *platformSuite) TestRecoverKeysTPMLockout(c *C) {
	// Put the TPM in DA lockout mode. Keys without user auth should still be recoverable.
	c.Check(s.TPM().DictionaryAttackParameters(s.TPM().LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)

	s.testRecoverKeys(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	})
}

func (s *platformSuite) testRecoverKeysNoValidSRK(c *C, prepareSrk func()) {
	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	}

	k, primaryKey, unlockKey, err := NewTPMProtectedKey(s.TPM(), params)
	c.Assert(err, IsNil)

	prepareSrk()

	s.AddCleanup(s.CloseMockConnection(c))

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	var handler PlatformKeyDataHandler
	payload, err := handler.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    k.Generation(),
		EncodedHandle: platformHandle,
		KDFAlg:        crypto.Hash(crypto.SHA256)},
		s.lastEncryptedPayload)

	pk, u := s.verifyASN1(c, payload)
	c.Check(primaryKey, DeepEquals, secboot.PrimaryKey(pk))

	uk := make([]byte, len(pk))
	r := hkdf.New(func() gohash.Hash { return crypto.SHA256.New() }, pk, u, []byte("UNLOCK"))
	_, err = io.ReadFull(r, uk)
	c.Assert(err, IsNil)
	c.Check(unlockKey, DeepEquals, secboot.DiskUnlockKey(uk))
}

func (s *platformSuite) TestRecoverKeysMissingSRK(c *C) {
	s.testRecoverKeysNoValidSRK(c, func() {
		srk, err := s.TPM().NewResourceContext(tcg.SRKHandle)
		c.Assert(err, IsNil)
		s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())
	})
}

func (s *platformSuite) TestRecoverKeysWrongSRK(c *C) {
	s.testRecoverKeysNoValidSRK(c, func() {
		srk, err := s.TPM().NewResourceContext(tcg.SRKHandle)
		c.Assert(err, IsNil)
		s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

		srkTemplate := tcg.MakeDefaultSRKTemplate()
		srkTemplate.Unique.RSA = nil
		srk = s.CreatePrimary(c, tpm2.HandleOwner, srkTemplate)
		s.EvictControl(c, tpm2.HandleOwner, srk, tcg.SRKHandle)
	})
}

func (s *platformSuite) testRecoverKeysImportable(c *C, params *ProtectKeyParams) {
	srk, err := s.TPM().NewResourceContext(tcg.SRKHandle)
	c.Assert(err, IsNil)

	srkPub, _, _, err := s.TPM().ReadPublic(srk)
	c.Assert(err, IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	k, primaryKey, unlockKey, err := NewExternalTPMProtectedKey(srkPub, params)
	c.Assert(err, IsNil)

	s.AddCleanup(s.CloseMockConnection(c))

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	var handler PlatformKeyDataHandler
	payload, err := handler.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    k.Generation(),
		EncodedHandle: platformHandle,
		KDFAlg:        crypto.Hash(crypto.SHA256)},
		s.lastEncryptedPayload)
	c.Assert(err, IsNil)

	pk, u := s.verifyASN1(c, payload)
	c.Check(primaryKey, DeepEquals, secboot.PrimaryKey(pk))

	uk := make([]byte, len(pk))
	r := hkdf.New(func() gohash.Hash { return crypto.SHA256.New() }, pk, u, []byte("UNLOCK"))
	_, err = io.ReadFull(r, uk)
	c.Assert(err, IsNil)
	c.Check(unlockKey, DeepEquals, secboot.DiskUnlockKey(uk))
}

func (s *platformSuite) TestRecoverKeysImportableSimplePCRProfile(c *C) {
	s.testRecoverKeysImportable(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *platformSuite) TestRecoverKeysImportableNilPCRProfile(c *C) {
	s.testRecoverKeysImportable(c, &ProtectKeyParams{
		PCRPolicyCounterHandle: tpm2.HandleNull,
		Role:                   ""})
}

func (s *platformSuite) TestRecoverKeysNoTPMConnection(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	k, _, _, err := NewTPMProtectedKey(s.TPM(), &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull,
		Role:                   "",
	})
	c.Check(err, IsNil)

	restore := tpm2test.MockDefaultDeviceFn(func(tpm2_device.DeviceMode) (tpm2_device.TPMDevice, error) {
		return nil, tpm2_device.ErrNoTPM2Device
	})
	s.AddCleanup(restore)

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	var handler PlatformKeyDataHandler
	_, err = handler.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    k.Generation(),
		EncodedHandle: platformHandle,
		KDFAlg:        crypto.Hash(crypto.SHA256)},
		s.lastEncryptedPayload)
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorUnavailable)
	c.Check(err, testutil.ErrorIs, ErrNoTPM2Device)
	c.Check(err, ErrorMatches, "no TPM2 device is available")
}

func (s *platformSuite) testRecoverKeysUnsealErrorHandling(c *C, prepare func(*secboot.KeyData, secboot.PrimaryKey)) error {
	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	k, primaryKey, _, err := NewTPMProtectedKey(s.TPM(), params)
	c.Assert(err, IsNil)

	prepare(k, primaryKey)

	s.AddCleanup(s.CloseMockConnection(c))

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	var handler PlatformKeyDataHandler
	_, err = handler.RecoverKeys(&secboot.PlatformKeyData{
		Generation:    k.Generation(),
		AuthMode:      secboot.AuthModeNone,
		Role:          "",
		KDFAlg:        crypto.Hash(crypto.SHA256),
		EncodedHandle: platformHandle},
		s.lastEncryptedPayload)
	return err
}

func (s *platformSuite) TestRecoverKeysUnsealErrorHandlingInvalidPCRProfile(c *C) {
	err := s.testRecoverKeysUnsealErrorHandling(c, func(_ *secboot.KeyData, _ secboot.PrimaryKey) {
		_, err := s.TPM().PCREvent(s.TPM().PCRHandleContext(23), []byte("foo"), nil)
		c.Check(err, IsNil)
	})
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorInvalidData)
	c.Check(err, ErrorMatches, "cannot complete authorization policy assertions: "+
		"cannot execute PCR assertions: cannot execute PolicyOR assertions: current session digest not found in policy data")
}

func (s *platformSuite) TestRecoverKeysUnsealErrorHandlingRevokedPolicy(c *C) {
	err := s.testRecoverKeysUnsealErrorHandling(c, func(k *secboot.KeyData, primaryKey secboot.PrimaryKey) {
		w := newMockKeyDataWriter()
		c.Check(k.WriteAtomic(w), IsNil)

		k2, err := secboot.ReadKeyData(w.Reader())
		c.Assert(err, IsNil)
		skd, err := NewSealedKeyData(k2)
		c.Assert(err, IsNil)

		// Increment NV counter
		c.Check(skd.UpdatePCRProtectionPolicy(s.TPM(), primaryKey, nil, NewPCRPolicyVersion), IsNil)
		c.Check(skd.RevokeOldPCRProtectionPolicies(s.TPM(), primaryKey), IsNil)
	})
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorInvalidData)
	c.Check(err, ErrorMatches, "cannot complete authorization policy assertions: "+
		"the PCR policy has been revoked")
}

func (s *platformSuite) TestRecoverKeysUnsealErrorHandlingSealedKeyAccessLocked(c *C) {
	err := s.testRecoverKeysUnsealErrorHandling(c, func(_ *secboot.KeyData, _ secboot.PrimaryKey) {
		c.Check(BlockPCRProtectionPolicies(s.TPM(), []int{23}), IsNil)
	})
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorInvalidData)
	c.Check(err, ErrorMatches, "cannot complete authorization policy assertions: "+
		"cannot execute PCR assertions: cannot execute PolicyOR assertions: current session digest not found in policy data")
}

func (s *platformSuite) TestRecoverKeysUnsealErrorHandlingProvisioningError(c *C) {
	err := s.testRecoverKeysUnsealErrorHandling(c, func(_ *secboot.KeyData, _ secboot.PrimaryKey) {
		srk, err := s.TPM().NewResourceContext(tcg.SRKHandle)
		c.Assert(err, IsNil)
		s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

		s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
	})
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorUninitialized)
	c.Check(err, ErrorMatches, "the TPM is not correctly provisioned")
}

type daKeySealer struct {
	orig KeySealer
}

func (s *daKeySealer) CreateSealedObject(data []byte, nameAlg tpm2.HashAlgorithmId, policy tpm2.Digest, noDA bool) (tpm2.Private, *tpm2.Public, tpm2.EncryptedSecret, error) {
	return s.orig.CreateSealedObject(data, nameAlg, policy, false)
}

func (s *platformSuite) TestRecoverKeysWithAuthKey(c *C) {
	// Need to mock newKeyDataPolicy to force require an auth value when using NewTPMProtectedKey so that we don't
	// have to use the passphrase APIs.
	makeSealedKeyDataOrig := MakeSealedKeyData
	restore := MockMakeSealedKeyData(func(tpm *tpm2.TPMContext, params *MakeSealedKeyDataParams, sealer KeySealer, constructor KeyDataConstructor, session tpm2.SessionContext) (*secboot.KeyData, secboot.PrimaryKey, secboot.DiskUnlockKey, error) {
		sealer = &daKeySealer{sealer}
		return makeSealedKeyDataOrig(tpm, params, sealer, constructor, session)
	})
	defer restore()

	restore = MockNewKeyDataPolicy(func(alg tpm2.HashAlgorithmId, key *tpm2.Public, role string, pcrPolicyCounterPub *tpm2.NVPublic, requireAuthValue bool) (KeyDataPolicy, tpm2.Digest, error) {
		index := tpm2.HandleNull
		var indexName tpm2.Name
		if pcrPolicyCounterPub != nil {
			index = pcrPolicyCounterPub.Index
			indexName = pcrPolicyCounterPub.Name()
		}

		pcrPolicyRef := ComputeV3PcrPolicyRef(key.NameAlg, []byte(role), indexName)

		builder := policyutil.NewPolicyBuilder(alg)
		builder.RootBranch().PolicyAuthorize(pcrPolicyRef, key)
		builder.RootBranch().PolicyAuthValue()

		mockPolicyData := &KeyDataPolicy_v3{
			StaticData: &StaticPolicyData_v3{
				AuthPublicKey:          key,
				PCRPolicyRef:           pcrPolicyRef,
				PCRPolicyCounterHandle: index,
				RequireAuthValue:       true},
			PCRData: &PcrPolicyData_v3{
				AuthorizedPolicySignature: &tpm2.Signature{SigAlg: tpm2.SigSchemeAlgNull},
			}}

		mockPolicyDigest, err := builder.Digest()
		c.Assert(err, IsNil)

		return mockPolicyData, mockPolicyDigest, nil
	})
	defer restore()

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	}

	k, primaryKey, unlockKey, err := NewTPMProtectedKey(s.TPM(), params)
	c.Assert(err, IsNil)

	s.AddCleanup(s.CloseMockConnection(c))

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	platformKeyData := &secboot.PlatformKeyData{
		Generation:    k.Generation(),
		EncodedHandle: platformHandle,
		KDFAlg:        crypto.Hash(crypto.SHA256),
		AuthMode:      k.AuthMode(),
	}

	var handler PlatformKeyDataHandler
	newHandle, err := handler.ChangeAuthKey(platformKeyData, nil, []byte{1, 2, 3, 4}, nil)
	c.Check(err, IsNil)

	newPlatformKeyData := &secboot.PlatformKeyData{
		Generation:    k.Generation(),
		EncodedHandle: newHandle,
		KDFAlg:        crypto.Hash(crypto.SHA256),
		AuthMode:      k.AuthMode(),
	}

	payload, err := handler.RecoverKeysWithAuthKey(newPlatformKeyData, s.lastEncryptedPayload, []byte{1, 2, 3, 4})
	c.Check(err, IsNil)

	pk, u := s.verifyASN1(c, payload)
	c.Check(primaryKey, DeepEquals, secboot.PrimaryKey(pk))

	uk := make([]byte, len(pk))
	r := hkdf.New(func() gohash.Hash { return crypto.SHA256.New() }, pk, u, []byte("UNLOCK"))
	_, err = io.ReadFull(r, uk)
	c.Assert(err, IsNil)
	c.Check(unlockKey, DeepEquals, secboot.DiskUnlockKey(uk))
}

func (s *platformSuite) TestRecoverKeysWithIncorrectAuthKey(c *C) {
	// Need to mock newKeyDataPolicy to force require an auth value when using NewTPMProtectedKey so that we don't
	// have to use the passphrase APIs.
	makeSealedKeyDataOrig := MakeSealedKeyData
	restore := MockMakeSealedKeyData(func(tpm *tpm2.TPMContext, params *MakeSealedKeyDataParams, sealer KeySealer, constructor KeyDataConstructor, session tpm2.SessionContext) (*secboot.KeyData, secboot.PrimaryKey, secboot.DiskUnlockKey, error) {
		sealer = &daKeySealer{sealer}
		return makeSealedKeyDataOrig(tpm, params, sealer, constructor, session)
	})
	defer restore()

	restore = MockNewKeyDataPolicy(func(alg tpm2.HashAlgorithmId, key *tpm2.Public, role string, pcrPolicyCounterPub *tpm2.NVPublic, requireAuthValue bool) (KeyDataPolicy, tpm2.Digest, error) {
		index := tpm2.HandleNull
		var indexName tpm2.Name
		if pcrPolicyCounterPub != nil {
			index = pcrPolicyCounterPub.Index
			indexName = pcrPolicyCounterPub.Name()
		}

		pcrPolicyRef := ComputeV3PcrPolicyRef(key.NameAlg, []byte(role), indexName)

		builder := policyutil.NewPolicyBuilder(alg)
		builder.RootBranch().PolicyAuthorize(pcrPolicyRef, key)
		builder.RootBranch().PolicyAuthValue()

		mockPolicyData := &KeyDataPolicy_v3{
			StaticData: &StaticPolicyData_v3{
				AuthPublicKey:          key,
				PCRPolicyRef:           pcrPolicyRef,
				PCRPolicyCounterHandle: index,
				RequireAuthValue:       true},
			PCRData: &PcrPolicyData_v3{
				AuthorizedPolicySignature: &tpm2.Signature{SigAlg: tpm2.SigSchemeAlgNull},
			}}

		mockPolicyDigest, err := builder.Digest()
		c.Assert(err, IsNil)

		return mockPolicyData, mockPolicyDigest, nil
	})
	defer restore()

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	}

	k, _, _, err := NewTPMProtectedKey(s.TPM(), params)
	c.Assert(err, IsNil)

	s.AddCleanup(s.CloseMockConnection(c))

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	platformKeyData := &secboot.PlatformKeyData{
		Generation:    k.Generation(),
		EncodedHandle: platformHandle,
		KDFAlg:        crypto.Hash(crypto.SHA256),
		AuthMode:      k.AuthMode(),
	}

	var handler PlatformKeyDataHandler
	newHandle, err := handler.ChangeAuthKey(platformKeyData, nil, []byte{1, 2, 3, 4}, nil)
	c.Check(err, IsNil)

	newPlatformKeyData := &secboot.PlatformKeyData{
		Generation:    k.Generation(),
		EncodedHandle: newHandle,
		KDFAlg:        crypto.Hash(crypto.SHA256),
		// AuthMode:      k.AuthMode(),
		AuthMode: secboot.AuthModePassphrase,
	}

	_, err = handler.RecoverKeysWithAuthKey(newPlatformKeyData, s.lastEncryptedPayload, []byte{5, 6, 7, 8})
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorInvalidAuthKey)
	c.Check(err, ErrorMatches, "cannot unseal key: TPM returned an error for session 1 whilst executing command TPM_CC_Unseal: "+
		"TPM_RC_AUTH_FAIL \\(the authorization HMAC check failed and DA counter incremented\\)")
}

func (s *platformSuite) TestChangeAuthKeyWithIncorrectAuthKey(c *C) {
	// Need to mock newKeyDataPolicy to force require an auth value when using NewTPMProtectedKey so that we don't
	// have to use the passphrase APIs.
	makeSealedKeyDataOrig := MakeSealedKeyData
	restore := MockMakeSealedKeyData(func(tpm *tpm2.TPMContext, params *MakeSealedKeyDataParams, sealer KeySealer, constructor KeyDataConstructor, session tpm2.SessionContext) (*secboot.KeyData, secboot.PrimaryKey, secboot.DiskUnlockKey, error) {
		sealer = &daKeySealer{sealer}
		return makeSealedKeyDataOrig(tpm, params, sealer, constructor, session)
	})
	defer restore()

	restore = MockNewKeyDataPolicy(func(alg tpm2.HashAlgorithmId, key *tpm2.Public, role string, pcrPolicyCounterPub *tpm2.NVPublic, requireAuthValue bool) (KeyDataPolicy, tpm2.Digest, error) {
		index := tpm2.HandleNull
		var indexName tpm2.Name
		if pcrPolicyCounterPub != nil {
			index = pcrPolicyCounterPub.Index
			indexName = pcrPolicyCounterPub.Name()
		}

		pcrPolicyRef := ComputeV3PcrPolicyRef(key.NameAlg, []byte(role), indexName)

		builder := policyutil.NewPolicyBuilder(alg)
		builder.RootBranch().PolicyAuthorize(pcrPolicyRef, key)
		builder.RootBranch().PolicyAuthValue()

		mockPolicyData := &KeyDataPolicy_v3{
			StaticData: &StaticPolicyData_v3{
				AuthPublicKey:          key,
				PCRPolicyRef:           pcrPolicyRef,
				PCRPolicyCounterHandle: index,
				RequireAuthValue:       true},
			PCRData: &PcrPolicyData_v3{
				AuthorizedPolicySignature: &tpm2.Signature{SigAlg: tpm2.SigSchemeAlgNull},
			}}

		mockPolicyDigest, err := builder.Digest()
		c.Assert(err, IsNil)

		return mockPolicyData, mockPolicyDigest, nil
	})
	defer restore()

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	}

	k, _, _, err := NewTPMProtectedKey(s.TPM(), params)
	c.Assert(err, IsNil)

	s.AddCleanup(s.CloseMockConnection(c))

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	platformKeyData := &secboot.PlatformKeyData{
		Generation:    k.Generation(),
		EncodedHandle: platformHandle,
		KDFAlg:        crypto.Hash(crypto.SHA256),
		AuthMode:      k.AuthMode(),
	}

	var handler PlatformKeyDataHandler
	newHandle, err := handler.ChangeAuthKey(platformKeyData, nil, []byte{1, 2, 3, 4}, nil)
	c.Check(err, IsNil)

	newPlatformKeyData := &secboot.PlatformKeyData{
		Generation:    k.Generation(),
		EncodedHandle: newHandle,
		KDFAlg:        crypto.Hash(crypto.SHA256),
		AuthMode:      k.AuthMode(),
	}

	_, err = handler.ChangeAuthKey(newPlatformKeyData, nil, []byte{5, 6, 7, 8}, nil)
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorInvalidAuthKey)
	c.Check(err, ErrorMatches, "TPM returned an error for session 1 whilst executing command TPM_CC_ObjectChangeAuth: "+
		"TPM_RC_AUTH_FAIL \\(the authorization HMAC check failed and DA counter incremented\\)")
}

func (s *platformSuite) TestRecoverKeysWithAuthKeyTPMLockout(c *C) {
	// Put the TPM in DA lockout mode
	c.Check(s.TPM().DictionaryAttackParameters(s.TPM().LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)

	// Need to mock newKeyDataPolicy to force require an auth value when using NewTPMProtectedKey so that we don't
	// have to use the passphrase APIs.
	makeSealedKeyDataOrig := MakeSealedKeyData
	restore := MockMakeSealedKeyData(func(tpm *tpm2.TPMContext, params *MakeSealedKeyDataParams, sealer KeySealer, constructor KeyDataConstructor, session tpm2.SessionContext) (*secboot.KeyData, secboot.PrimaryKey, secboot.DiskUnlockKey, error) {
		sealer = &daKeySealer{sealer}
		return makeSealedKeyDataOrig(tpm, params, sealer, constructor, session)
	})
	defer restore()

	restore = MockNewKeyDataPolicy(func(alg tpm2.HashAlgorithmId, key *tpm2.Public, role string, pcrPolicyCounterPub *tpm2.NVPublic, requireAuthValue bool) (KeyDataPolicy, tpm2.Digest, error) {
		index := tpm2.HandleNull
		var indexName tpm2.Name
		if pcrPolicyCounterPub != nil {
			index = pcrPolicyCounterPub.Index
			indexName = pcrPolicyCounterPub.Name()
		}

		pcrPolicyRef := ComputeV3PcrPolicyRef(key.NameAlg, []byte(role), indexName)

		builder := policyutil.NewPolicyBuilder(alg)
		builder.RootBranch().PolicyAuthorize(pcrPolicyRef, key)
		builder.RootBranch().PolicyAuthValue()

		mockPolicyData := &KeyDataPolicy_v3{
			StaticData: &StaticPolicyData_v3{
				AuthPublicKey:          key,
				PCRPolicyRef:           pcrPolicyRef,
				PCRPolicyCounterHandle: index,
				RequireAuthValue:       true},
			PCRData: &PcrPolicyData_v3{
				AuthorizedPolicySignature: &tpm2.Signature{SigAlg: tpm2.SigSchemeAlgNull},
			}}

		mockPolicyDigest, err := builder.Digest()
		c.Assert(err, IsNil)

		return mockPolicyData, mockPolicyDigest, nil
	})
	defer restore()

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0),
		Role:                   "",
	}

	k, _, _, err := NewTPMProtectedKey(s.TPM(), params)
	c.Assert(err, IsNil)

	s.AddCleanup(s.CloseMockConnection(c))

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	platformKeyData := &secboot.PlatformKeyData{
		Generation:    k.Generation(),
		EncodedHandle: platformHandle,
		KDFAlg:        crypto.Hash(crypto.SHA256),
		AuthMode:      k.AuthMode(),
	}

	var handler PlatformKeyDataHandler
	_, err = handler.RecoverKeysWithAuthKey(platformKeyData, s.lastEncryptedPayload, []byte{})
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorUnavailable)
	c.Check(err, testutil.ErrorIs, ErrTPMLockout)
	c.Check(err, ErrorMatches, `the TPM is in DA lockout mode`)
}
