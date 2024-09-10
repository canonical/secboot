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
	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
)

var (
	secbootNewKeyData               = secboot.NewKeyData
	secbootNewKeyDataWithPassphrase = secboot.NewKeyDataWithPassphrase
)

// ProtectKeyParams provides arguments for the ProtectKey* APIs.
type ProtectKeyParams struct {
	// PCRProfile defines the profile used to generate the initial PCR protection
	// policy for the newly created sealed key data. This can be updated later on
	// by calling SealedKeyData.UpdatePCRProtectionPolicy.
	PCRProfile *PCRProtectionProfile

	Role string

	// PCRPolicyCounterHandle is the handle at which to create a NV index for PCR
	// authorization policy revocation support. The handle must either be tpm2.HandleNull
	// (in which case, no NV index will be created and the sealed key will not benefit
	// from PCR authorization policy revocation support), or it must be a valid NV index
	// handle (MSO == 0x01). The choice of handle should take in to consideration the
	// reserved indices from the "Registry of reserved TPM 2.0 handles and localities"
	// specification. It is recommended that the handle is in the block reserved for
	// owner objects (0x01800000 - 0x01bfffff).
	PCRPolicyCounterHandle tpm2.Handle

	PrimaryKey secboot.PrimaryKey
}

type PassphraseProtectKeyParams struct {
	ProtectKeyParams

	KDFOptions secboot.KDFOptions
}

type keyDataConstructor func(skd *SealedKeyData, role string, encryptedPayload []byte, kdfAlg crypto.Hash) (*secboot.KeyData, error)

func makeKeyDataNoAuth(skd *SealedKeyData, role string, encryptedPayload []byte, kdfAlg crypto.Hash) (*secboot.KeyData, error) {
	return secbootNewKeyData(&secboot.KeyParams{
		Handle:           skd,
		Role:             role,
		EncryptedPayload: encryptedPayload,
		PlatformName:     platformName,
		KDFAlg:           kdfAlg,
	})
}

func makeKeyDataWithPassphraseConstructor(kdfOptions secboot.KDFOptions, passphrase string) keyDataConstructor {
	return func(skd *SealedKeyData, role string, encryptedPayload []byte, kdfAlg crypto.Hash) (*secboot.KeyData, error) {
		return secbootNewKeyDataWithPassphrase(&secboot.KeyWithPassphraseParams{
			KeyParams: secboot.KeyParams{
				Handle:           skd,
				Role:             role,
				EncryptedPayload: encryptedPayload,
				PlatformName:     platformName,
				KDFAlg:           kdfAlg,
			},
			KDFOptions:  kdfOptions,
			AuthKeySize: skd.data.Public().NameAlg.Size(),
		}, passphrase)
	}
}

type makeSealedKeyDataParams struct {
	PcrProfile             *PCRProtectionProfile
	Role                   string
	PcrPolicyCounterHandle tpm2.Handle
	PrimaryKey             secboot.PrimaryKey
	AuthMode               secboot.AuthMode
}

// makeSealedKeyData makes a sealed key data using the supplied parameters, keySealer implementation,
// and keyDataConstructor implementation.
//
// If supplied, the session must be a HMAC session with the AttrContinueSession attribute set and is
// used for authenticating the storage hierarchy in order to avoid trasmitting the cleartext authorization
// value.
var makeSealedKeyData = func(tpm *tpm2.TPMContext, params *makeSealedKeyDataParams, sealer keySealer, constructor keyDataConstructor, session tpm2.SessionContext) (*secboot.KeyData, secboot.PrimaryKey, secboot.DiskUnlockKey, error) {
	// Create a primary key, if required.
	primaryKey := params.PrimaryKey
	if primaryKey == nil {
		primaryKey = make(secboot.PrimaryKey, 32)
		if _, err := rand.Read(primaryKey); err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot create primary key: %w", err)
		}
	}

	// Create the key for authorizing PCR policy updates.
	authPublicKey, err := newPolicyAuthPublicKey(primaryKey)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot derive public area of key for signing dynamic authorization policies: %w", err)
	}

	// Create PCR policy counter, if requested and if one doesn't already exist.
	var pcrPolicyCounterPub *tpm2.NVPublic
	if params.PcrPolicyCounterHandle != tpm2.HandleNull {
		if tpm == nil {
			return nil, nil, nil, errors.New("cannot create a PCR policy counter without a TPM connection")
		}

		var err error
		pcrPolicyCounterPub, err = ensurePcrPolicyCounter(tpm, params.PcrPolicyCounterHandle, authPublicKey, session)
		switch {
		case tpm2.IsTPMError(err, tpm2.ErrorNVDefined, tpm2.CommandNVDefineSpace):
			return nil, nil, nil, TPMResourceExistsError{params.PcrPolicyCounterHandle}
		case isAuthFailError(err, tpm2.CommandNVDefineSpace, 1):
			return nil, nil, nil, AuthFailError{tpm2.HandleOwner}
		case err != nil:
			return nil, nil, nil, xerrors.Errorf("cannot create new PCR policy counter: %w", err)
		}
	}

	// Create the initial policy data.
	nameAlg := tpm2.HashAlgorithmSHA256
	requireAuthValue := params.AuthMode != secboot.AuthModeNone

	policyData, authPolicyDigest, err := newKeyDataPolicy(nameAlg, authPublicKey, params.Role, pcrPolicyCounterPub, requireAuthValue)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create initial policy data: %w", err)
	}

	// Create a 32 byte symmetric key and 12 byte nonce.
	var symKey [32 + 12]byte
	if _, err := rand.Read(symKey[:]); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create symmetric key: %w", err)
	}

	// Seal the symmetric key and nonce.
	priv, pub, importSymSeed, err := sealer.CreateSealedObject(symKey[:], nameAlg, authPolicyDigest, !requireAuthValue)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a new SealedKeyData.
	data, err := newKeyData(priv, pub, importSymSeed, policyData)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create key data: %w", err)
	}
	skd := &SealedKeyData{sealedKeyDataBase: sealedKeyDataBase{data: data}}

	// Set the initial PCR policy.
	pcrProfile := params.PcrProfile
	if pcrProfile == nil {
		pcrProfile = NewPCRProtectionProfile()
	}
	if err := skdbUpdatePCRProtectionPolicyNoValidate(&skd.sealedKeyDataBase, tpm, primaryKey, pcrPolicyCounterPub, pcrProfile, resetPcrPolicyVersion); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot set initial PCR policy: %w", err)
	}

	// Create the GCM encrypted payload. Use the name algorithm as the KDF algorithm here.
	kdfAlg := crypto.SHA256
	unlockKey, payload, err := secboot.MakeDiskUnlockKey(rand.Reader, kdfAlg, primaryKey)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create new unlock key: %w", err)
	}

	// Serialize the AAD. Note that we don't protect the role parameter directly because it's
	// already bound to the sealed object via its authorization policy.
	aad, err := mu.MarshalToBytes(&additionalData_v3{
		Generation: uint32(secboot.KeyDataGeneration),
		KDFAlg:     tpm2.HashAlgorithmSHA256,
		AuthMode:   params.AuthMode,
	})
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create AAD: %w", err)
	}

	b, err := aes.NewCipher(symKey[:32])
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(b)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create AEAD cipher: %w", err)
	}
	ciphertext := aead.Seal(nil, symKey[32:], payload, aad)

	// Construct the secboot.KeyData object
	kd, err := constructor(skd, params.Role, ciphertext, kdfAlg)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot create key data object: %w", err)
	}

	return kd, primaryKey, unlockKey, nil
}

// NewExternalTPMProtectedKey seals the supplied primary key to the TPM storage
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
// On success, this function returns the the sealed key object, the primary key and the
// unique key which is used for disk unlocking.
func NewExternalTPMProtectedKey(tpmKey *tpm2.Public, params *ProtectKeyParams) (protectedKey *secboot.KeyData, primaryKey secboot.PrimaryKey, unlockKey secboot.DiskUnlockKey, err error) {
	// params is mandatory.
	if params == nil {
		return nil, nil, nil, errors.New("no ProtectKeyParams provided")
	}

	sealer := &importableObjectKeySealer{tpmKey: tpmKey}

	return makeSealedKeyData(nil, &makeSealedKeyDataParams{
		PrimaryKey:             params.PrimaryKey,
		PcrPolicyCounterHandle: params.PCRPolicyCounterHandle,
		AuthMode:               secboot.AuthModeNone,
		Role:                   params.Role,
		PcrProfile:             params.PCRProfile,
	}, sealer, makeKeyDataNoAuth, nil)
}

// NewTPMProtectedKey seals the supplied disk encryption key to the storage hierarchy of
// the TPM.
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
// The key used for authorizing changes to the sealed key object via the
// SealedKeyObject.UpdatePCRProtectionPolicy is derived from the primary key.
//
// On success, this function returns the the sealed key object, the primary key and the
// unique key which is used for disk unlocking.
func NewTPMProtectedKey(tpm *Connection, params *ProtectKeyParams) (protectedKey *secboot.KeyData, primaryKey secboot.PrimaryKey, unlockKey secboot.DiskUnlockKey, err error) {
	// params is mandatory.
	if params == nil {
		return nil, nil, nil, errors.New("no ProtectKeyParams provided")
	}

	sealer := &sealedObjectKeySealer{tpm}

	return makeSealedKeyData(tpm.TPMContext, &makeSealedKeyDataParams{
		PcrProfile:             params.PCRProfile,
		Role:                   params.Role,
		PcrPolicyCounterHandle: params.PCRPolicyCounterHandle,
		PrimaryKey:             params.PrimaryKey,
		AuthMode:               secboot.AuthModeNone,
	}, sealer, makeKeyDataNoAuth, tpm.HmacSession())
}

func NewTPMPassphraseProtectedKey(tpm *Connection, params *PassphraseProtectKeyParams, passphrase string) (protectedKey *secboot.KeyData, primaryKey secboot.PrimaryKey, unlockKey secboot.DiskUnlockKey, err error) {
	// params is mandatory.
	if params == nil {
		return nil, nil, nil, errors.New("no PassphraseProtectKeyParams provided")
	}

	sealer := &sealedObjectKeySealer{tpm}

	return makeSealedKeyData(tpm.TPMContext, &makeSealedKeyDataParams{
		PrimaryKey:             params.PrimaryKey,
		PcrPolicyCounterHandle: params.PCRPolicyCounterHandle,
		AuthMode:               secboot.AuthModePassphrase,
		Role:                   params.Role,
		PcrProfile:             params.PCRProfile,
	}, sealer, makeKeyDataWithPassphraseConstructor(params.KDFOptions, passphrase), tpm.HmacSession())
}
