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
	"encoding/json"
	"math/rand"
	"os"
	"syscall"

	"github.com/canonical/go-tpm2"

	. "gopkg.in/check.v1"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/tcg"
	"github.com/snapcore/secboot/internal/testutil"
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
}

var _ = Suite(&platformSuite{})

func (s *platformSuite) TestDeriveAuthValue(c *C) {
	key := testutil.DecodeHexString(c, "eb3df724b267220a2ebf1ad93ca05c7ba7ab2b321f2e7fddbc9741882b274433290973b9f9ecb6a64396da33d717f7af")
	expected := testutil.DecodeHexString(c, "874fcd20ed7c7071f6fd1d9ccb8ebc088c902712ba6cad7a14d7db71d75673b8")

	value, err := DeriveAuthValue(key, 32)
	c.Check(err, IsNil)
	c.Check(value, DeepEquals, expected)
	c.Logf("%x", value)
}

func (s *platformSuite) TestDeriveAuthValueDifferentLen(c *C) {
	key := testutil.DecodeHexString(c, "eb3df724b267220a2ebf1ad93ca05c7ba7ab2b321f2e7fddbc9741882b274433290973b9f9ecb6a64396da33d717f7af")
	expected := testutil.DecodeHexString(c, "874fcd20ed7c7071f6fd1d9ccb8ebc088c902712")

	value, err := DeriveAuthValue(key, 20)
	c.Check(err, IsNil)
	c.Check(value, DeepEquals, expected)
	c.Logf("%x", value)
}

func (s *platformSuite) TestDeriveAuthValueDifferentKey(c *C) {
	key := testutil.DecodeHexString(c, "7facbeb6f2a7f233f68059da3f1d9c9706530eced4cca76ba1e1551f0e814c40ac2a076e208880ab6d2afe31f04e096a")
	expected := testutil.DecodeHexString(c, "fc69c90fe401ed40906698fe290e6be07b8c7b8b5b42b6166044cf9e32b8e300")

	value, err := DeriveAuthValue(key, 32)
	c.Check(err, IsNil)
	c.Check(value, DeepEquals, expected)
	c.Logf("%x", value)
}

func (s *platformSuite) TestRecoverKeysIntegrated(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	k, authKey, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	keyUnsealed, authKeyUnsealed, err := k.RecoverKeys()
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)
}

func (s *platformSuite) TestRecoverKeysWithPassphraseIntegrated(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	k, authKey, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	var kdf testutil.MockKDF
	c.Check(k.SetPassphrase("passphrase", nil, &kdf), IsNil)

	keyUnsealed, authKeyUnsealed, err := k.RecoverKeysWithPassphrase("passphrase", &kdf)
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)
}

func (s *platformSuite) TestRecoverKeysWithBadPassphraseIntegrated(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	k, _, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	var kdf testutil.MockKDF
	c.Check(k.SetPassphrase("passphrase", nil, &kdf), IsNil)

	_, _, err = k.RecoverKeysWithPassphrase("1234", &kdf)
	c.Check(err, Equals, secboot.ErrInvalidPassphrase)
}

func (s *platformSuite) TestChangePassphraseIntegrated(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	k, authKey, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	var kdf testutil.MockKDF
	c.Check(k.SetPassphrase("passphrase", nil, &kdf), IsNil)

	c.Check(k.ChangePassphrase("passphrase", "1234", nil, &kdf), IsNil)

	keyUnsealed, authKeyUnsealed, err := k.RecoverKeysWithPassphrase("1234", &kdf)
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)
}

func (s *platformSuite) TestChangePassphraseWithBadPassphraseIntegrated(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	k, authKey, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	var kdf testutil.MockKDF
	c.Check(k.SetPassphrase("passphrase", nil, &kdf), IsNil)

	c.Check(k.ChangePassphrase("1234", "1234", nil, &kdf), Equals, secboot.ErrInvalidPassphrase)

	keyUnsealed, authKeyUnsealed, err := k.RecoverKeysWithPassphrase("passphrase", &kdf)
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)
}

func (s *platformSuite) testRecoverKeys(c *C, params *ProtectKeyParams) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	k, authKey, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	var handler PlatformKeyDataHandler
	payload, err := handler.RecoverKeys(&secboot.PlatformKeyData{
		EncodedHandle:    platformHandle,
		EncryptedPayload: s.lastEncryptedPayload})

	keyUnsealed, authKeyUnsealed, err := payload.Unmarshal()
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)
}

func (s *platformSuite) TestRecoverKeysSimplePCRProfile(c *C) {
	s.testRecoverKeys(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)})
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

func (s *platformSuite) testRecoverKeysNoValidSRK(c *C, prepareSrk func()) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	k, authKey, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	prepareSrk()

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	var handler PlatformKeyDataHandler
	payload, err := handler.RecoverKeys(&secboot.PlatformKeyData{
		EncodedHandle:    platformHandle,
		EncryptedPayload: s.lastEncryptedPayload})

	keyUnsealed, authKeyUnsealed, err := payload.Unmarshal()
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)
}

func (s *platformSuite) TestRecoverKeysMissingSRK(c *C) {
	s.testRecoverKeysNoValidSRK(c, func() {
		srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
		c.Assert(err, IsNil)
		s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())
	})
}

func (s *platformSuite) TestRecoverKeysWrongSRK(c *C) {
	s.testRecoverKeysNoValidSRK(c, func() {
		srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
		c.Assert(err, IsNil)
		s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

		srkTemplate := tcg.MakeDefaultSRKTemplate()
		srkTemplate.Unique.RSA = nil
		srk = s.CreatePrimary(c, tpm2.HandleOwner, srkTemplate)
		s.EvictControl(c, tpm2.HandleOwner, srk, tcg.SRKHandle)
	})
}

func (s *platformSuite) testRecoverKeysImportable(c *C, params *ProtectKeyParams) {
	srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
	c.Assert(err, IsNil)

	srkPub, _, _, err := s.TPM().ReadPublic(srk)
	c.Assert(err, IsNil)

	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	k, authKey, err := ProtectKeyWithExternalStorageKey(srkPub, key, params)
	c.Assert(err, IsNil)

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	var handler PlatformKeyDataHandler
	payload, err := handler.RecoverKeys(&secboot.PlatformKeyData{
		EncodedHandle:    platformHandle,
		EncryptedPayload: s.lastEncryptedPayload})

	keyUnsealed, authKeyUnsealed, err := payload.Unmarshal()
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)
}

func (s *platformSuite) TestRecoverKeysImportableSimplePCRProfile(c *C) {
	s.testRecoverKeysImportable(c, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewResolvedPCRProfileFromCurrentValues(c, s.TPM().TPMContext, tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *platformSuite) TestRecoverKeysImportableNilPCRProfile(c *C) {
	s.testRecoverKeysImportable(c, &ProtectKeyParams{
		PCRPolicyCounterHandle: tpm2.HandleNull})
}

func (s *platformSuite) TestRecoverKeysNoTPMConnection(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	k, _, err := ProtectKeyWithTPM(s.TPM(), key, &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: tpm2.HandleNull})
	c.Check(err, IsNil)

	restore := tpm2test.MockOpenDefaultTctiFn(func() (tpm2.TCTI, error) {
		return nil, &os.PathError{Op: "open", Path: "/dev/tpm0", Err: syscall.ENOENT}
	})
	s.AddCleanup(restore)

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	var handler PlatformKeyDataHandler
	_, err = handler.RecoverKeys(&secboot.PlatformKeyData{
		EncodedHandle:    platformHandle,
		EncryptedPayload: s.lastEncryptedPayload})
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorUnavailable)
	c.Check(err, testutil.ErrorIs, ErrNoTPM2Device)
	c.Check(err, ErrorMatches, "no TPM2 device is available")
}

func (s *platformSuite) testRecoverKeysUnsealErrorHandling(c *C, prepare func(*secboot.KeyData, secboot.PrimaryKey)) error {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7, 23}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	k, authKey, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	prepare(k, authKey)

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	var handler PlatformKeyDataHandler
	_, err = handler.RecoverKeys(&secboot.PlatformKeyData{
		EncodedHandle:    platformHandle,
		EncryptedPayload: s.lastEncryptedPayload})
	return err
}

func (s *platformSuite) TestRecoverKeysUnsealErrorHandlingLockout(c *C) {
	err := s.testRecoverKeysUnsealErrorHandling(c, func(_ *secboot.KeyData, _ secboot.PrimaryKey) {
		// Put the TPM in DA lockout mode
		c.Check(s.TPM().DictionaryAttackParameters(s.TPM().LockoutHandleContext(), 0, 7200, 86400, nil), IsNil)
	})
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorUnavailable)
	c.Check(err, testutil.ErrorIs, ErrTPMLockout)
	c.Check(err, ErrorMatches, "the TPM is in DA lockout mode")
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
	err := s.testRecoverKeysUnsealErrorHandling(c, func(k *secboot.KeyData, authKey secboot.PrimaryKey) {
		w := newMockKeyDataWriter()
		c.Check(k.WriteAtomic(w), IsNil)

		k2, err := secboot.ReadKeyData(w.Reader())
		c.Assert(err, IsNil)
		skd, err := NewSealedKeyData(k2)
		c.Assert(err, IsNil)

		c.Check(skd.UpdatePCRProtectionPolicy(s.TPM(), authKey, nil), IsNil)
		c.Check(skd.RevokeOldPCRProtectionPolicies(s.TPM(), authKey), IsNil)
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
		srk, err := s.TPM().CreateResourceContextFromTPM(tcg.SRKHandle)
		c.Assert(err, IsNil)
		s.EvictControl(c, tpm2.HandleOwner, srk, srk.Handle())

		s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("1234"))
	})
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorUninitialized)
	c.Check(err, ErrorMatches, "the TPM is not correctly provisioned")
}

func (s *platformSuite) TestRecoverKeysWithAuthKey(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	k, authKey, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	var handler PlatformKeyDataHandler
	platformHandle, err = handler.ChangeAuthKey(platformHandle, nil, []byte{1, 2, 3, 4})
	c.Check(err, IsNil)

	payload, err := handler.RecoverKeysWithAuthKey(&secboot.PlatformKeyData{
		EncodedHandle:    platformHandle,
		EncryptedPayload: s.lastEncryptedPayload}, []byte{1, 2, 3, 4})

	keyUnsealed, authKeyUnsealed, err := payload.Unmarshal()
	c.Check(err, IsNil)
	c.Check(keyUnsealed, DeepEquals, key)
	c.Check(authKeyUnsealed, DeepEquals, authKey)
}

func (s *platformSuite) TestRecoverKeysWithIncorrectAuthKey(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	k, _, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	var handler PlatformKeyDataHandler
	platformHandle, err = handler.ChangeAuthKey(platformHandle, nil, []byte{1, 2, 3, 4})
	c.Check(err, IsNil)

	_, err = handler.RecoverKeysWithAuthKey(&secboot.PlatformKeyData{
		EncodedHandle:    platformHandle,
		EncryptedPayload: s.lastEncryptedPayload}, []byte{5, 6, 7, 8})
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorInvalidAuthKey)
	c.Check(err, ErrorMatches, "cannot unseal key: TPM returned an error for session 1 whilst executing command TPM_CC_Unseal: "+
		"TPM_RC_AUTH_FAIL \\(the authorization HMAC check failed and DA counter incremented\\)")
}

func (s *platformSuite) TestChangeAuthKeyWithIncorrectAuthKey(c *C) {
	key := make(secboot.DiskUnlockKey, 32)
	rand.Read(key)

	params := &ProtectKeyParams{
		PCRProfile:             tpm2test.NewPCRProfileFromCurrentValues(tpm2.HashAlgorithmSHA256, []int{7}),
		PCRPolicyCounterHandle: s.NextAvailableHandle(c, 0x0181fff0)}

	k, _, err := ProtectKeyWithTPM(s.TPM(), key, params)
	c.Assert(err, IsNil)

	var platformHandle json.RawMessage
	c.Check(k.UnmarshalPlatformHandle(&platformHandle), IsNil)

	var handler PlatformKeyDataHandler
	platformHandle, err = handler.ChangeAuthKey(platformHandle, nil, []byte{1, 2, 3, 4})
	c.Check(err, IsNil)

	_, err = handler.ChangeAuthKey(platformHandle, nil, []byte{5, 6, 7, 8})
	c.Assert(err, testutil.ConvertibleTo, &secboot.PlatformHandlerError{})
	c.Check(err.(*secboot.PlatformHandlerError).Type, Equals, secboot.PlatformHandlerErrorInvalidAuthKey)
	c.Check(err, ErrorMatches, "TPM returned an error for session 1 whilst executing command TPM_CC_ObjectChangeAuth: "+
		"TPM_RC_AUTH_FAIL \\(the authorization HMAC check failed and DA counter incremented\\)")
}
