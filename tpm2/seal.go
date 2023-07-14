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

package tpm2

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
)

var (
	secbootNewKeyData = secboot.NewKeyData
)

// ProtectKeyParams provides arguments for the ProtectKey* APIs.
type ProtectKeyParams struct {
	// PCRProfile defines the profile used to generate the initial PCR protection
	// policy for the newly created sealed key data. This can be updated later on
	// by calling SealedKeyData.UpdatePCRProtectionPolicy.
	PCRProfile *PCRProtectionProfile

	// PCRPolicyCounterHandle is the handle at which to create a NV index for PCR
	// authorization policy revocation support. The handle must either be tpm2.HandleNull
	// (in which case, no NV index will be created and the sealed key will not benefit
	// from PCR authorization policy revocation support), or it must be a valid NV index
	// handle (MSO == 0x01). The choice of handle should take in to consideration the
	// reserved indices from the "Registry of reserved TPM 2.0 handles and localities"
	// specification. It is recommended that the handle is in the block reserved for
	// owner objects (0x01800000 - 0x01bfffff).
	PCRPolicyCounterHandle tpm2.Handle

	// AuthKey is the key used to authorize changes to the newly create key,
	// via the SealedKeyObject.UpdatePCRProtectionPolicy and
	// secboot.KeyData.SetAuthorizedSnapModels APIs. If set, this should be a
	// random 32-byte number.
	// If not set, one is generated automatically.
	AuthKey secboot.PrimaryKey

	// AuthorizedSnapModels is a list of models initially authorized to access
	// the data protected by the newly created key. These can be updated later
	// on by calling secboot.KeyData.SetAuthorizedSnapModels.
	AuthorizedSnapModels []secboot.SnapModel
}

// makeKeyDataWithPolicy protects the supplied keys using the supplied keySealer and
// policy data. This can be called multiple times to protect an arbitary number of
// keys with an identical policy.
func makeKeyDataWithPolicy(key secboot.DiskUnlockKey, authKey secboot.PrimaryKey, policy *keyDataPolicyParams, sealer keySealer) (*secboot.KeyData, error) {
	var symKey [32 + aes.BlockSize]byte
	if _, err := rand.Read(symKey[:]); err != nil {
		return nil, xerrors.Errorf("cannot create symmetric key: %w", err)
	}

	priv, pub, importSymSeed, err := sealer.CreateSealedObject(symKey[:], policy.Alg, policy.AuthPolicy)
	if err != nil {
		return nil, err
	}

	// Create a new SealedKeyObject.
	data, err := newKeyData(priv, pub, importSymSeed, policy.PolicyData)
	if err != nil {
		return nil, xerrors.Errorf("cannot create key data: %w", err)
	}
	skd := &SealedKeyData{sealedKeyDataBase: sealedKeyDataBase{data: data}}

	// Create encrypted payload
	payload := secboot.MarshalKeys(key, authKey)

	b, err := aes.NewCipher(symKey[:32])
	if err != nil {
		return nil, xerrors.Errorf("cannot create new cipher: %w", err)
	}
	stream := cipher.NewCFBEncrypter(b, symKey[32:])
	stream.XORKeyStream(payload, payload)

	kd, err := secbootNewKeyData(&secboot.KeyParams{
		Handle:           skd,
		EncryptedPayload: payload,
		PlatformName:     platformName,
		PrimaryKey:       authKey,
		// Hardcode SHA-256 here. We already hardcode this as the name algorithm
		// for the sealed object and elliptic key.
		SnapModelAuthHash: crypto.SHA256})
	if err != nil {
		return nil, xerrors.Errorf("cannot create key data object: %w", err)
	}

	return kd, nil
}

type createdPcrPolicyCounter struct {
	tpm     *tpm2.TPMContext
	session tpm2.SessionContext
	pub     *tpm2.NVPublic
}

func (c *createdPcrPolicyCounter) Pub() *tpm2.NVPublic {
	if c == nil {
		return nil
	}
	return c.pub
}

func (c *createdPcrPolicyCounter) undefineOnError(err error) {
	if c == nil {
		return
	}

	if err == nil {
		return
	}

	index, err := tpm2.CreateNVIndexResourceContextFromPublic(c.pub)
	if err != nil {
		return
	}
	c.tpm.NVUndefineSpace(c.tpm.OwnerHandleContext(), index, c.session)
}

// keyDataPolicyParams corresponds to the parameters of a key's computed authorization
// policy, consisting of the digest algorithm, the policy digest and the associated policy
// data.
type keyDataPolicyParams struct {
	Alg        tpm2.HashAlgorithmId
	PolicyData keyDataPolicy
	AuthPolicy tpm2.Digest
}

// makeKeyDataPolicy creates the policy data required to seal a key with makeKeyDataWithPolicy
// and creates a PCR policy counter if required.
func makeKeyDataPolicy(tpm *tpm2.TPMContext, pcrPolicyCounterHandle tpm2.Handle, authKey secboot.PrimaryKey,
	session tpm2.SessionContext) (data *keyDataPolicyParams, pcrPolicyCounterOut *createdPcrPolicyCounter,
	authKeyOut secboot.PrimaryKey, err error) {
	// Create an auth key.
	if authKey == nil {
		authKey = make(secboot.PrimaryKey, 32)
		if _, err := rand.Read(authKey); err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot create key for signing dynamic authorization policies: %w", err)
		}
	}
	authPublicKey, err := newPolicyAuthPublicKey(authKey)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot derive public area of key for signing dynamic authorization policies: %w", err)
	}

	// Create PCR policy counter, if requested.
	var pcrPolicyCount uint64
	var pcrPolicyCounter *createdPcrPolicyCounter
	if pcrPolicyCounterHandle != tpm2.HandleNull {
		if tpm == nil {
			return nil, nil, nil, errors.New("cannot create a PCR policy counter without a TPM connection")
		}

		var pub *tpm2.NVPublic
		pub, pcrPolicyCount, err = createPcrPolicyCounter(tpm, pcrPolicyCounterHandle, authPublicKey, session)
		switch {
		case tpm2.IsTPMError(err, tpm2.ErrorNVDefined, tpm2.CommandNVDefineSpace):
			return nil, nil, nil, TPMResourceExistsError{pcrPolicyCounterHandle}
		case isAuthFailError(err, tpm2.CommandNVDefineSpace, 1):
			return nil, nil, nil, AuthFailError{tpm2.HandleOwner}
		case err != nil:
			return nil, nil, nil, xerrors.Errorf("cannot create new PCR policy counter: %w", err)
		}

		pcrPolicyCounter = &createdPcrPolicyCounter{
			tpm:     tpm,
			session: session,
			pub:     pub}

		defer func() { pcrPolicyCounter.undefineOnError(err) }()
	}

	alg := tpm2.HashAlgorithmSHA256

	// Create the initial policy data
	policyData, authPolicy, err := newKeyDataPolicy(alg, authPublicKey, pcrPolicyCounter.Pub(), pcrPolicyCount)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create initial policy data: %w", err)
	}

	return &keyDataPolicyParams{
		Alg:        alg,
		PolicyData: policyData,
		AuthPolicy: authPolicy}, pcrPolicyCounter, authKey, nil
}

// keyDataParams contains the parameters required to seal a new key with makeKeyData.
type keyDataParams struct {
	PCRPolicyCounterHandle tpm2.Handle
	PCRProfile             *PCRProtectionProfile
}

// makeKeyData protects the supplied keys using the supplied keySealer and
// parameters. If required, a PCR policy counter is created. The returned key
// will have an initial PCR policy as specified via the supplied parameters.
func makeKeyData(tpm *tpm2.TPMContext, key secboot.DiskUnlockKey, authKey secboot.PrimaryKey, params *keyDataParams,
	sealer keySealer, session tpm2.SessionContext) (protectedKey *secboot.KeyData, authKeyOut secboot.PrimaryKey,
	pcrPolicyCounterOut *createdPcrPolicyCounter, err error) {
	policy, pcrPolicyCounter, authKey, err := makeKeyDataPolicy(tpm, params.PCRPolicyCounterHandle, authKey, session)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { pcrPolicyCounter.undefineOnError(err) }()

	protectedKey, err = makeKeyDataWithPolicy(key, authKey, policy, sealer)
	if err != nil {
		return nil, nil, nil, err
	}

	skd, err := NewSealedKeyData(protectedKey)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot obtain SealedKeyObject from KeyData: %w", err)
	}

	pcrProfile := params.PCRProfile
	if pcrProfile == nil {
		pcrProfile = NewPCRProtectionProfile()
	}
	if err := skdbUpdatePCRProtectionPolicyImpl(&skd.sealedKeyDataBase, tpm, authKey, pcrPolicyCounter.Pub(), pcrProfile, session); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot set initial PCR policy: %w", err)
	}
	if err := protectedKey.MarshalAndUpdatePlatformHandle(skd); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot update platform handle: %w", err)
	}

	return protectedKey, authKey, pcrPolicyCounter, nil
}

// ProtectKeyWithExternalStorageKey seals the supplied disk encryption key to the TPM storage
// key asociated with the supplied public tpmKey. This creates an importable sealed key and
// is suitable in environments that don't have access to the TPM but do have access to the
// public part of the TPM's storage primary key.
//
// The tpmKey argument must correspond to the storage primary key on the target TPM,
// persisted at the standard handle (0x81000001).
//
// This function cannot create a sealed key that uses a PCR policy counter. The
// PCRPolicyCounterHandle field of the params argument must be tpm2.HandleNull.
//
// The key will be protected with a PCR policy computed from the PCRProtectionProfile
// supplied via the PCRProfile field of the params argument. The PCR policy can be updated
// later on via the SealedKeyObject.UpdatePCRProtectionPolicy API.
//
// The sealed key will be created with the snap models provided via the AuthorizedSnapModels
// field of params authorized to access the data protected by this key. The set of
// authorized models can be updated later on by calling
// secboot.KeyData.SetAuthorizedSnapModels.
//
// The key used for authorizing changes to the sealed key object via the
// SealedKeyObject.UpdatePCRProtectionPolicy and secboot.KeyData.SetAuthorizedSnapModels
// APIs can be supplied via the AuthKey field of params. This should be cryptographically
// strong 32-byte key. If one is not supplied, it will be created automatically.
//
// On success, this function returns the the sealed key object and a key used for
// authorizing changes via the SealedKeyObject.UpdatePCRProtectionPolicy and
// secboot.KeyData.SetAuthorizedSnapModels APIs. This key doesn't need to be
// stored anywhere, and certainly mustn't be stored outside of the encrypted container
// protected by the supplied key. The key is stored encrypted inside the sealed
// key data and will be returnred from future calls to secboot.KeyData.RecoverKeys.
func ProtectKeyWithExternalStorageKey(tpmKey *tpm2.Public, key secboot.DiskUnlockKey, params *ProtectKeyParams) (protectedKey *secboot.KeyData, authKey secboot.PrimaryKey, err error) {
	// params is mandatory.
	if params == nil {
		return nil, nil, errors.New("no ProtectKeyParams provided")
	}
	if params.PCRPolicyCounterHandle != tpm2.HandleNull {
		return nil, nil, errors.New("PCR policy counter handle must be tpm2.HandleNull when creating an importable sealed key")
	}

	sealer := &importableObjectKeySealer{tpmKey: tpmKey}

	protectedKey, authKey, _, err = makeKeyData(nil, key, params.AuthKey, &keyDataParams{
		PCRPolicyCounterHandle: params.PCRPolicyCounterHandle,
		PCRProfile:             params.PCRProfile}, sealer, nil)
	if err != nil {
		return nil, nil, err
	}

	if err := protectedKey.SetAuthorizedSnapModels(authKey, params.AuthorizedSnapModels...); err != nil {
		return nil, nil, xerrors.Errorf("cannot set authorized snap models: %w", err)
	}

	return protectedKey, authKey, nil
}

// ProtectKeysWithTPM seals the supplied disk encryption keys to the storage
// hierarchy of the TPM. The keys are specified by the keys argument.
//
// This function requires knowledge of the authorization value for the storage hierarchy,
// which must be provided by calling Connection.OwnerHandleContext().SetAuthValue() prior
// to calling this function. If the provided authorization value is incorrect, a
// AuthFailError error will be returned.
//
// This function will create a NV index at the handle specified by the
// PCRPolicyCounterHandle field of the params argument if it is not tpm2.HandleNull. If
// the handle is already in use, a TPMResourceExistsError error will be returned. In this
// case, the caller will need to either choose a different handle or undefine the existing
// one. If it is not tpm2.HandleNull, then it must be a valid NV index handle (MSO == 0x01),
// and the choice of handle should take in to consideration the reserved indices from the
// "Registry of reserved TPM 2.0 handles and localities" specification. It is recommended
// that the handle is in the block reserved for owner objects (0x01800000 - 0x01bfffff).
//
// All keys will be created with the same authorization policy, and will be protected with
// a PCR policy computed from the PCRProtectionProfile supplied via the PCRProfile field
// of the params argument. The PCR policy can be updated later on via the
// UpdateKeyPCRProtectionPolicyMultiple API.
//
// The sealed keys will be created with the snap models provided via the AuthorizedSnapModels
// field of params authorized to access the data protected by these keys. The set
// of authorized models can be updated later on by calling
// secboot.KeyData.SetAuthorizedSnapModels for each key.
//
// The key used for authorizing changes to the sealed key objects via the
// UpdateKeyPCRProtectionPolicyMultiple and secboot.KeyData.SetAuthorizedSnapModels
// APIs can be supplied via the AuthKey field of params. This should be cryptographically
// strong 32-byte key. If one is not supplied, it will be created automatically.
//
// On success, this function returns the the sealed key objects and a key used for
// authorizing changes via the UpdateKeyPCRProtectionPolicyMultiple and
// secboot.KeyData.SetAuthorizedSnapModels APIs. This key doesn't need to be
// stored anywhere, and certainly mustn't be stored outside of the encrypted containers
// protected by the supplied keys. The key is stored encrypted inside the sealed
// key data and will be returnred from future calls to secboot.KeyData.RecoverKeys.
func ProtectKeysWithTPM(tpm *Connection, keys []secboot.DiskUnlockKey, params *ProtectKeyParams) (protectedKeys []*secboot.KeyData, authKey secboot.PrimaryKey, err error) {
	// params is mandatory.
	if params == nil {
		return nil, nil, errors.New("no ProtectKeyParams provided")
	}
	if len(keys) == 0 {
		return nil, nil, errors.New("no keys provided")
	}

	sealer := &sealedObjectKeySealer{tpm}

	var protectedKey *secboot.KeyData
	var pcrPolicyCounter *createdPcrPolicyCounter

	protectedKey, authKey, pcrPolicyCounter, err = makeKeyData(tpm.TPMContext, keys[0], params.AuthKey,
		&keyDataParams{
			PCRPolicyCounterHandle: params.PCRPolicyCounterHandle,
			PCRProfile:             params.PCRProfile},
		sealer, tpm.HmacSession())
	if err != nil {
		return nil, nil, err
	}
	defer func() { pcrPolicyCounter.undefineOnError(err) }()
	protectedKeys = append(protectedKeys, protectedKey)

	skd, err := NewSealedKeyData(protectedKey)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot obtain SealedKeyObject from KeyData: %w", err)
	}

	policy := &keyDataPolicyParams{
		Alg:        skd.data.Public().NameAlg,
		AuthPolicy: skd.data.Public().AuthPolicy,
		PolicyData: skd.data.Policy()}
	for _, key := range keys[1:] {
		protectedKey, err := makeKeyDataWithPolicy(key, authKey, policy, sealer)
		if err != nil {
			return nil, nil, err
		}
		protectedKeys = append(protectedKeys, protectedKey)
	}

	for _, kd := range protectedKeys {
		if err := kd.SetAuthorizedSnapModels(authKey, params.AuthorizedSnapModels...); err != nil {
			return nil, nil, xerrors.Errorf("cannot set authorized snap models: %w", err)
		}
	}

	return protectedKeys, authKey, nil
}

// ProtectKeyWithTPM seals the supplied disk encryption key to the storage hierarchy of
// the TPM.
//
// This function requires knowledge of the authorization value for the storage hierarchy,
// which must be provided by calling Connection.OwnerHandleContext().SetAuthValue() prior
// to calling this function. If the provided authorization value is incorrect, a
// AuthFailError error will be returned.
//
// This function will create a NV index at the handle specified by the
// PCRPolicyCounterHandle field of the params argument if it is not tpm2.HandleNull. If
// the handle is already in use, a TPMResourceExistsError error will be returned. In this
// case, the caller will need to either choose a different handle or undefine the existing
// one. If it is not tpm2.HandleNull, then it must be a valid NV index handle (MSO == 0x01),
// and the choice of handle should take in to consideration the reserved indices from the
// "Registry of reserved TPM 2.0 handles and localities" specification. It is recommended
// that the handle is in the block reserved for owner objects (0x01800000 - 0x01bfffff).
//
// The key will be protected with a PCR policy computed from the PCRProtectionProfile
// supplied via the PCRProfile field of the params argument. The PCR policy can be updated
// later on via the SealedKeyObject.UpdatePCRProtectionPolicy API.
//
// The sealed key will be created with the snap models provided via the AuthorizedSnapModels
// field of params authorized to access the data protected by this key. The set of
// authorized models can be updated later on by calling
// secboot.KeyData.SetAuthorizedSnapModels.
//
// The key used for authorizing changes to the sealed key object via the
// SealedKeyObject.UpdatePCRProtectionPolicy and secboot.KeyData.SetAuthorizedSnapModels
// APIs can be supplied via the AuthKey field of params. This should be cryptographically
// strong 32-byte key. If one is not supplied, it will be created automatically.
//
// On success, this function returns the the sealed key object and a key used for
// authorizing changes via the SealedKeyObject.UpdatePCRProtectionPolicy and
// secboot.KeyData.SetAuthorizedSnapModels APIs. This key doesn't need to be
// stored anywhere, and certainly mustn't be stored outside of the encrypted container
// protected by the supplied key. The key is stored encrypted inside the sealed
// key data and will be returnred from future calls to secboot.KeyData.RecoverKeys.
func ProtectKeyWithTPM(tpm *Connection, key secboot.DiskUnlockKey, params *ProtectKeyParams) (protectedKey *secboot.KeyData, authKey secboot.PrimaryKey, err error) {
	// params is mandatory.
	if params == nil {
		return nil, nil, errors.New("no ProtectKeyParams provided")
	}

	var protectedKeys []*secboot.KeyData

	protectedKeys, authKey, err = ProtectKeysWithTPM(tpm, []secboot.DiskUnlockKey{key}, params)
	if err != nil {
		return nil, nil, err
	}

	return protectedKeys[0], authKey, nil
}
