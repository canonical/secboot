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

package tpm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/util"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
)

func makeSealedKeyTemplate() *tpm2.Public {
	return &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent,
		Params:  &tpm2.PublicParamsU{KeyedHashDetail: &tpm2.KeyedHashParams{Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
}

func makeImportableSealedKeyTemplate() *tpm2.Public {
	tmpl := makeSealedKeyTemplate()
	tmpl.Attrs &^= tpm2.AttrFixedTPM | tpm2.AttrFixedParent
	return tmpl
}

// KeyCreationParams provides arguments for SealKeyToTPM.
//
// Deprecated: Use ProtectKeys* APIs.
type KeyCreationParams struct {
	// PCRProfile defines the profile used to generate a PCR protection policy for the newly created sealed key file.
	PCRProfile *PCRProtectionProfile

	// PCRPolicyCounterHandle is the handle at which to create a NV index for PCR authorization policy revocation support. The handle
	// must either be tpm2.HandleNull (in which case, no NV index will be created and the sealed key will not benefit from PCR
	// authorization policy revocation support), or it must be a valid NV index handle (MSO == 0x01). The choice of handle should take
	// in to consideration the reserved indices from the "Registry of reserved TPM 2.0 handles and localities" specification. It is
	// recommended that the handle is in the block reserved for owner objects (0x01800000 - 0x01bfffff).
	PCRPolicyCounterHandle tpm2.Handle

	// AuthKey can be set to chose an auhorisation key whose
	// private part will be used for authorizing PCR policy
	// updates with SealedKeyObject.UpdatePCRProtectionPolicy
	// If set a key from elliptic.P256 must be used,
	// if not set one is generated.
	AuthKey *ecdsa.PrivateKey
}

// SealKeyToExternalTPMStorageKey seals the supplied disk encryption key to the TPM storage key associated with the supplied public
// tpmKey. This creates an importable sealed key and is suitable in environments that don't have access to the TPM but do have
// access to the public part of the TPM's storage primary key. The sealed key object and associated metadata that is required
// during early boot in order to unseal the key again and unlock the associated encrypted volume is written to a file at the path
// specified by keyPath.
//
// The tpmKey argument must correspond to the storage primary key on the target TPM, persisted at the standard handle.
//
// This function cannot create a sealed key that uses a PCR policy counter. The PCRPolicyCounterHandle field of the params argument
// must be tpm2.HandleNull.
//
// The key will be protected with a PCR policy computed from the PCRProtectionProfile supplied via the PCRProfile field of the params
// argument.
//
// On success, this function returns the private part of the key used for authorizing PCR policy updates with
// UpdateKeyPCRProtectionPolicy. This key doesn't need to be stored anywhere, and certainly mustn't be stored outside of the encrypted
// volume protected with this sealed key file. The key is stored encrypted inside this sealed key file and returned from future calls
// to SealedKeyObject.UnsealFromTPM.
//
// The authorization key can also be chosen and provided by setting
// AuthKey in the params argument.
//
// Deprecated: Use ProtectKeyWithExternalStorageKey.
func SealKeyToExternalTPMStorageKey(tpmKey *tpm2.Public, key secboot.DiskUnlockKey, keyPath string, params *KeyCreationParams) (authKey secboot.PrimaryKey, err error) {
	// params is mandatory.
	if params == nil {
		return nil, errors.New("no KeyCreationParams provided")
	}

	// Perform some sanity checks on params.
	if params.AuthKey != nil && params.AuthKey.Curve != elliptic.P256() {
		return nil, errors.New("provided AuthKey must be from elliptic.P256, no other curve is supported")
	}

	if params.PCRPolicyCounterHandle != tpm2.HandleNull {
		return nil, errors.New("PCRPolicyCounter must be tpm2.HandleNull when creating an importable sealed key")
	}

	// Compute metadata.

	var goAuthKey *ecdsa.PrivateKey
	// Use the provided authorization key,
	// otherwise create an asymmetric key for signing
	// authorization policy updates, and authorizing dynamic
	// authorization policy revocations.
	if params.AuthKey != nil {
		goAuthKey = params.AuthKey
	} else {
		goAuthKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, xerrors.Errorf("cannot generate key for signing dynamic authorization policies: %w", err)
		}
	}
	authPublicKey := createTPMPublicAreaForECDSAKey(&goAuthKey.PublicKey)
	authKey = goAuthKey.D.Bytes()

	pub := makeImportableSealedKeyTemplate()

	// Create the initial policy data
	policyData, authPolicy, err := newKeyDataPolicyLegacy(pub.NameAlg, authPublicKey, nil, 0)
	if err != nil {
		return nil, xerrors.Errorf("cannot create initial policy data: %w", err)
	}

	pub.AuthPolicy = authPolicy

	// Seal key

	// Create the sensitive data
	sealedData, err := mu.MarshalToBytes(sealedData{Key: key, AuthPrivateKey: authKey})
	if err != nil {
		panic(fmt.Sprintf("cannot marshal sensitive data: %v", err))
	}
	// Define the actual sensitive area. The initial auth value is empty - note
	// that util.CreateDuplicationObjectFromSensitive pads this to the length of
	// the name algorithm for us so we don't define it here.
	sensitive := tpm2.Sensitive{
		Type:      pub.Type,
		SeedValue: make(tpm2.Digest, pub.NameAlg.Size()),
		Sensitive: &tpm2.SensitiveCompositeU{Bits: sealedData}}
	if _, err := io.ReadFull(rand.Reader, sensitive.SeedValue); err != nil {
		return nil, xerrors.Errorf("cannot create seed value: %w", err)
	}

	// Compute the public ID
	h := pub.NameAlg.NewHash()
	h.Write(sensitive.SeedValue)
	h.Write(sensitive.Sensitive.Bits)
	pub.Unique = &tpm2.PublicIDU{KeyedHash: h.Sum(nil)}

	// Now create the importable sealed key object (duplication object).
	_, priv, importSymSeed, err := util.CreateDuplicationObject(&sensitive, pub, tpmKey, nil, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot create duplication object: %w", err)
	}

	w := NewFileSealedKeyObjectWriter(keyPath)

	data, err := newKeyData(priv, pub, importSymSeed, policyData)
	if err != nil {
		return nil, xerrors.Errorf("cannot create key data: %w", err)
	}

	// Marshal the entire object (sealed key object and auxiliary data) to disk
	sko := newSealedKeyObject(data)

	// Create a PCR authorization policy
	pcrProfile := params.PCRProfile
	if pcrProfile == nil {
		pcrProfile = NewPCRProtectionProfile()
	}
	if err := sko.updatePCRProtectionPolicyNoValidate(nil, authKey, nil, pcrProfile, false, nil); err != nil {
		return nil, xerrors.Errorf("cannot create initial PCR policy: %w", err)
	}

	if err := sko.WriteAtomic(w); err != nil {
		return nil, xerrors.Errorf("cannot write key data file: %w", err)
	}

	return authKey, nil
}

// SealKeyRequest corresponds to a key that should be sealed by SealKeyToTPMMultiple
// to a file at the specified path.
//
// Deprecated: Use ProtectKeys* APIs.
type SealKeyRequest struct {
	Key  secboot.DiskUnlockKey
	Path string
}

// SealKeyToTPMMultiple seals the supplied disk encryption keys to the storage hierarchy of the TPM. The keys are specified by
// the keys argument, which is a slice of associated key and corresponding file path. The sealed key objects and associated
// metadata that is required during early boot in order to unseal the keys again and unlock the associated encrypted volumes
// are written to files at the specifed paths.
//
// This function requires knowledge of the authorization value for the storage hierarchy, which must be provided by calling
// Connection.OwnerHandleContext().SetAuthValue() prior to calling this function. If the provided authorization value is incorrect,
// a AuthFailError error will be returned.
//
// This function will create a NV index at the handle specified by the PCRPolicyCounterHandle field of the params argument if it is
// not tpm2.HandleNull. If the handle is already in use, a TPMResourceExistsError error will be returned. In this case, the caller
// will need to either choose a different handle or undefine the existing one. If it is not tpm2.HandleNull, then it must be a valid
// NV index handle (MSO == 0x01), and the choice of handle should take in to consideration the reserved indices from the "Registry of
// reserved TPM 2.0 handles and localities" specification. It is recommended that the handle is in the block reserved for owner
// objects (0x01800000 - 0x01bfffff).
//
// All keys will be created with the same authorization policy, and will be protected with a PCR policy computed from the
// PCRProtectionProfile supplied via the PCRProfile field of the params argument.
//
// If any part of this function fails, no sealed keys will be created.
//
// On success, this function returns the private part of the key used for authorizing PCR policy updates with
// UpdateKeyPCRProtectionPolicyMultiple. This key doesn't need to be stored anywhere, and certainly mustn't be stored outside of the
// encrypted volume protected with this sealed key file. The key is stored encrypted inside this sealed key file and returned from
// future calls to SealedKeyObject.UnsealFromTPM.
//
// The authorization key can also be chosen and provided by setting
// AuthKey in the params argument.
//
// Deprecated: Use ProtectKeysWithTPM.
func SealKeyToTPMMultiple(tpm *Connection, keys []*SealKeyRequest, params *KeyCreationParams) (authKey secboot.PrimaryKey, err error) {
	// params is mandatory.
	if params == nil {
		return nil, errors.New("no KeyCreationParams provided")
	}
	if len(keys) == 0 {
		return nil, errors.New("no keys provided")
	}

	// Perform some sanity checks on params.
	if params.AuthKey != nil && params.AuthKey.Curve != elliptic.P256() {
		return nil, errors.New("provided AuthKey must be from elliptic.P256, no other curve is supported")
	}

	// Use the HMAC session created when the connection was opened rather than creating a new one.
	session := tpm.HmacSession()

	// Obtain a context for the SRK now. If we're called immediately after ProvisionTPM without closing the Connection, we use the
	// context cached by ProvisionTPM, which corresponds to the object provisioned. If not, we just unconditionally provision a new
	// SRK as this function requires knowledge of the owner hierarchy authorization anyway. This way, we know that the primary key we
	// seal to is good and future calls to ProvisionTPM won't provision an object that cannot unseal the key we protect.
	srk := tpm.provisionedSrk
	if srk == nil {
		var err error
		srk, err = provisionStoragePrimaryKey(tpm.TPMContext, session)
		switch {
		case isAuthFailError(err, tpm2.AnyCommandCode, 1):
			return nil, AuthFailError{tpm2.HandleOwner}
		case err != nil:
			return nil, xerrors.Errorf("cannot provision storage root key: %w", err)
		}
	}

	succeeded := false

	// Compute metadata.

	var goAuthKey *ecdsa.PrivateKey
	// Use the provided authorization key,
	// otherwise create an asymmetric key for signing
	// authorization policy updates, and authorizing dynamic
	// authorization policy revocations.
	if params.AuthKey != nil {
		goAuthKey = params.AuthKey
	} else {
		goAuthKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, xerrors.Errorf("cannot generate key for signing dynamic authorization policies: %w", err)
		}
	}
	authPublicKey := createTPMPublicAreaForECDSAKey(&goAuthKey.PublicKey)
	authKey = goAuthKey.D.Bytes()

	// Create PCR policy counter, if requested.
	var pcrPolicyCounterPub *tpm2.NVPublic
	var pcrPolicyCount uint64
	if params.PCRPolicyCounterHandle != tpm2.HandleNull {
		pcrPolicyCounterPub, pcrPolicyCount, err = createPcrPolicyCounterLegacy(tpm.TPMContext, params.PCRPolicyCounterHandle, authPublicKey, session)
		switch {
		case tpm2.IsTPMError(err, tpm2.ErrorNVDefined, tpm2.CommandNVDefineSpace):
			return nil, TPMResourceExistsError{params.PCRPolicyCounterHandle}
		case isAuthFailError(err, tpm2.CommandNVDefineSpace, 1):
			return nil, AuthFailError{tpm2.HandleOwner}
		case err != nil:
			return nil, xerrors.Errorf("cannot create new dynamic authorization policy counter: %w", err)
		}
		defer func() {
			if succeeded {
				return
			}
			index, err := tpm2.CreateNVIndexResourceContextFromPublic(pcrPolicyCounterPub)
			if err != nil {
				return
			}
			tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, session)
		}()
	}

	template := makeSealedKeyTemplate()

	// Create the initial policy data
	policyData, authPolicy, err := newKeyDataPolicyLegacy(template.NameAlg, authPublicKey, pcrPolicyCounterPub, pcrPolicyCount)
	if err != nil {
		return nil, xerrors.Errorf("cannot create initial policy data: %w", err)
	}

	// Define the template for the sealed key object, using the computed policy digest
	template.AuthPolicy = authPolicy

	// Clean up files on failure.
	defer func() {
		if succeeded {
			return
		}
		for _, key := range keys {
			os.Remove(key.Path)
		}
	}()

	// Seal each key.
	for i, key := range keys {
		// Create the sensitive data
		sealedData, err := mu.MarshalToBytes(sealedData{Key: key.Key, AuthPrivateKey: authKey})
		if err != nil {
			panic(fmt.Sprintf("cannot marshal sensitive data: %v", err))
		}
		sensitive := tpm2.SensitiveCreate{Data: sealedData}

		// Now create the sealed key object. The command is integrity protected so if the object at the handle we expect the SRK to reside
		// at has a different name (ie, if we're connected via a resource manager and somebody swapped the object with another one), this
		// command will fail. We take advantage of parameter encryption here too.
		priv, pub, _, _, _, err := tpm.Create(srk, &sensitive, template, nil, nil, session.IncludeAttrs(tpm2.AttrCommandEncrypt))
		if err != nil {
			return nil, xerrors.Errorf("cannot create sealed data object for key: %w", err)
		}

		w := NewFileSealedKeyObjectWriter(key.Path)

		data, err := newKeyData(priv, pub, nil, policyData)
		if err != nil {
			return nil, xerrors.Errorf("cannot create key data: %w", err)
		}

		// Marshal the entire object (sealed key object and auxiliary data) to disk
		sko := newSealedKeyObject(data)

		// Create a PCR authorization policy, only for the first key though. Subsequent keys
		// share the same keyDataPolicy structure.
		if i == 0 {
			pcrProfile := params.PCRProfile
			if pcrProfile == nil {
				pcrProfile = NewPCRProtectionProfile()
			}
			if err := sko.updatePCRProtectionPolicyNoValidate(tpm.TPMContext, authKey, pcrPolicyCounterPub, pcrProfile, false, session); err != nil {
				return nil, xerrors.Errorf("cannot create initial PCR policy: %w", err)
			}
		}

		if err := sko.WriteAtomic(w); err != nil {
			return nil, xerrors.Errorf("cannot write key data file: %w", err)
		}
	}

	succeeded = true
	return authKey, nil
}

// SealKeyToTPM seals the supplied disk encryption key to the storage hierarchy of the TPM. The sealed key object and associated
// metadata that is required during early boot in order to unseal the key again and unlock the associated encrypted volume is written
// to a file at the path specified by keyPath.
//
// This function requires knowledge of the authorization value for the storage hierarchy, which must be provided by calling
// Connection.OwnerHandleContext().SetAuthValue() prior to calling this function. If the provided authorization value is incorrect,
// a AuthFailError error will be returned.
//
// If the TPM is not correctly provisioned, a ErrTPMProvisioning error will be returned. In this case, ProvisionTPM must be called
// before proceeding.
//
// This function will create a NV index at the handle specified by the PCRPolicyCounterHandle field of the params argument if it is not
// tpm2.HandleNull. If the handle is already in use, a TPMResourceExistsError error will be returned. In this case, the caller will
// need to either choose a different handle or undefine the existing one. If it is not tpm2.HandleNull, then it must be a valid NV
// index handle (MSO == 0x01), and the choice of handle should take in to consideration the reserved indices from the "Registry of
// reserved TPM 2.0 handles and localities" specification. It is recommended that the handle is in the block reserved for owner
// objects (0x01800000 - 0x01bfffff).
//
// The key will be protected with a PCR policy computed from the PCRProtectionProfile supplied via the PCRProfile field of the params
// argument.
//
// On success, this function returns the private part of the key used for authorizing PCR policy updates with
// UpdateKeyPCRProtectionPolicy. This key doesn't need to be stored anywhere, and certainly mustn't be stored outside of the encrypted
// volume protected with this sealed key file. The key is stored encrypted inside this sealed key file and returned from future calls
// to SealedKeyObject.UnsealFromTPM.
//
// The authorization key can also be chosen and provided by setting
// AuthKey in the params argument.
//
// Deprecated: Use ProtectKeyWithTPM.
func SealKeyToTPM(tpm *Connection, key secboot.DiskUnlockKey, keyPath string, params *KeyCreationParams) (authKey secboot.PrimaryKey, err error) {
	return SealKeyToTPMMultiple(tpm, []*SealKeyRequest{{Key: key, Path: keyPath}}, params)
}
