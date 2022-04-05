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
	"bytes"
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

// updatePCRProtectionPolicyImpl is a helper to update the PCR policy using the supplied
// profile, authorized with the supplied key.
//
// If tpm is not nil, this function will verify that the supplied profile produces a PCR
// selection that is supported by the TPM. If tpm is nil, it will be assumed that the target
// TPM supports the PCRs and algorithms defined in the TCG PC Client Platform TPM Profile
// Specification for TPM 2.0.
//
// If k.data.policy().pcrPolicyCounterHandle() is not tpm2.HandleNull, then counterPub
// must be supplied, and it must correspond to the public area associated with that handle.
func (k *SealedKeyObject) updatePCRProtectionPolicyImpl(tpm *tpm2.TPMContext, key secboot.AuxiliaryKey,
	counterPub *tpm2.NVPublic, profile *PCRProtectionProfile, session tpm2.SessionContext) error {
	var counterName tpm2.Name
	if counterPub != nil {
		var err error
		counterName, err = counterPub.Name()
		if err != nil {
			return xerrors.Errorf("cannot compute name of policy counter: %w", err)
		}
	}

	var supportedPcrs tpm2.PCRSelectionList
	if tpm != nil {
		var err error
		supportedPcrs, err = tpm.GetCapabilityPCRs(session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			return xerrors.Errorf("cannot determine supported PCRs: %w", err)
		}
	} else {
		// Defined as mandatory in the TCG PC Client Platform TPM Profile Specification for TPM 2.0
		supportedPcrs = tpm2.PCRSelectionList{
			{Hash: tpm2.HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}},
			{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}}}
	}

	alg := k.data.Public().NameAlg

	// Compute PCR digests
	pcrs, pcrDigests, err := profile.ComputePCRDigests(tpm, alg)
	if err != nil {
		return xerrors.Errorf("cannot compute PCR digests from protection profile: %w", err)
	}

	if len(pcrDigests) == 0 {
		return errors.New("PCR protection profile contains no digests")
	}

	for _, p := range pcrs {
		for _, s := range p.Select {
			found := false
			for _, p2 := range supportedPcrs {
				if p2.Hash != p.Hash {
					continue
				}
				for _, s2 := range p2.Select {
					if s2 == s {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				return errors.New("PCR protection profile contains digests for unsupported PCRs")
			}
		}
	}

	params := &pcrPolicyParams{
		key:               key,
		pcrs:              pcrs,
		pcrDigests:        pcrDigests,
		policyCounterName: counterName}
	return k.data.Policy().UpdatePCRPolicy(alg, params)
}

func (k *SealedKeyObject) revokeOldPCRProtectionPoliciesImpl(tpm *tpm2.TPMContext, key secboot.AuxiliaryKey, session tpm2.SessionContext) error {
	pcrPolicyCounterPub, err := k.validateData(tpm, session)
	if err != nil {
		if isKeyDataError(err) {
			return InvalidKeyDataError{err.Error()}
		}
		return xerrors.Errorf("cannot validate key data: %w", err)
	}

	if pcrPolicyCounterPub == nil {
		return nil
	}

	target := k.data.Policy().PCRPolicySequence()

	context, err := k.data.Policy().PCRPolicyCounterContext(tpm, pcrPolicyCounterPub, session)
	if err != nil {
		return xerrors.Errorf("cannot create context for PCR policy counter: %w", err)
	}

	var lastCurrent uint64
	incremented := false
	for {
		current, err := context.Get()
		switch {
		case err != nil:
			return xerrors.Errorf("cannot read current value: %w", err)
		case current > target:
			return errors.New("cannot set counter to a lower value")
		case current == lastCurrent && incremented:
			return errors.New("cannot increment counter (no progress)")
		}

		if current == target {
			break
		}

		lastCurrent = current

		if err := context.Increment(key); err != nil {
			return xerrors.Errorf("cannot increment counter: %w", err)
		}
		incremented = true
	}

	return nil
}

// KeyCreationParams provides arguments for SealKeyToTPM.
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
func SealKeyToExternalTPMStorageKey(tpmKey *tpm2.Public, key secboot.DiskUnlockKey, keyPath string, params *KeyCreationParams) (authKey secboot.AuxiliaryKey, err error) {
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
	policyData, authPolicy, err := newKeyDataPolicy(pub.NameAlg, authPublicKey, nil, 0)
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
	_, priv, importSymSeed, err := util.CreateDuplicationObjectFromSensitive(&sensitive, pub, tpmKey, nil, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot create duplication object: %w", err)
	}

	w := NewFileSealedKeyObjectWriter(keyPath)

	// Marshal the entire object (sealed key object and auxiliary data) to disk
	sko := newSealedKeyObject(newKeyData(priv, pub, importSymSeed, policyData))

	// Create a PCR authorization policy
	pcrProfile := params.PCRProfile
	if pcrProfile == nil {
		pcrProfile = &PCRProtectionProfile{}
	}
	if err := sko.updatePCRProtectionPolicyImpl(nil, authKey, nil, pcrProfile, nil); err != nil {
		return nil, xerrors.Errorf("cannot create initial PCR policy: %w", err)
	}

	if err := sko.WriteAtomic(w); err != nil {
		return nil, xerrors.Errorf("cannot write key data file: %w", err)
	}

	return authKey, nil
}

// SealKeyRequest corresponds to a key that should be sealed by SealKeyToTPMMultiple
// to a file at the specified path.
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
func SealKeyToTPMMultiple(tpm *Connection, keys []*SealKeyRequest, params *KeyCreationParams) (authKey secboot.AuxiliaryKey, err error) {
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
		pcrPolicyCounterPub, pcrPolicyCount, err = createPcrPolicyCounter(tpm.TPMContext, params.PCRPolicyCounterHandle, authPublicKey, session)
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
	policyData, authPolicy, err := newKeyDataPolicy(template.NameAlg, authPublicKey, pcrPolicyCounterPub, pcrPolicyCount)
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

		// Marshal the entire object (sealed key object and auxiliary data) to disk
		sko := newSealedKeyObject(newKeyData(priv, pub, nil, policyData))

		// Create a PCR authorization policy, only for the first key though. Subsequent keys
		// share the same keyDataPolicy structure.
		if i == 0 {
			pcrProfile := params.PCRProfile
			if pcrProfile == nil {
				pcrProfile = &PCRProtectionProfile{}
			}
			if err := sko.updatePCRProtectionPolicyImpl(tpm.TPMContext, authKey, pcrPolicyCounterPub, pcrProfile, session); err != nil {
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
func SealKeyToTPM(tpm *Connection, key secboot.DiskUnlockKey, keyPath string, params *KeyCreationParams) (authKey secboot.AuxiliaryKey, err error) {
	return SealKeyToTPMMultiple(tpm, []*SealKeyRequest{{Key: key, Path: keyPath}}, params)
}

func updateKeyPCRProtectionPolicyCommon(tpm *tpm2.TPMContext, keys []*SealedKeyObject, authKey secboot.AuxiliaryKey, pcrProfile *PCRProtectionProfile, session tpm2.SessionContext) error {
	primaryKey := keys[0]

	// Validate the primary key object
	pcrPolicyCounterPub, err := primaryKey.validateData(tpm, session)
	if err != nil {
		if isKeyDataError(err) {
			return InvalidKeyDataError{err.Error()}
		}
		return xerrors.Errorf("cannot validate key data: %w", err)
	}
	if err := primaryKey.data.Policy().ValidateAuthKey(authKey); err != nil {
		if isKeyDataError(err) {
			return InvalidKeyDataError{err.Error()}
		}
		return xerrors.Errorf("cannot validate auth key: %w", err)
	}

	// Update the PCR policy for the primary key.
	if pcrProfile == nil {
		pcrProfile = &PCRProtectionProfile{}
	}
	if err := primaryKey.updatePCRProtectionPolicyImpl(tpm, authKey, pcrPolicyCounterPub, pcrProfile, session); err != nil {
		return xerrors.Errorf("cannot update PCR authorization policy: %w", err)
	}

	// Validate secondary key objects and make sure they are related
	for i, k := range keys[1:] {
		if k.data.Version() != primaryKey.data.Version() {
			return fmt.Errorf("key data at index %d has a different metadata version compared to the primary key data", i)
		}

		if _, err := k.validateData(tpm, session); err != nil {
			if isKeyDataError(err) {
				return InvalidKeyDataError{fmt.Sprintf("%v (%d)", err.Error(), i)}
			}
			return xerrors.Errorf("cannot validate related key data: %w", err)
		}
		// The metadata is valid and consistent with the object's static authorization policy.
		// Verify that it also has the same static authorization policy as the first key object passed
		// to this function. This policy digest includes a cryptographic record of the PCR policy counter
		// and dynamic authorization policy signing key, so this is the only check required to determine
		// if 2 keys are related.
		if !bytes.Equal(k.data.Public().AuthPolicy, primaryKey.data.Public().AuthPolicy) {
			return InvalidKeyDataError{fmt.Sprintf("key data at index %d is not related to the primary key data", i)}
		}

		k.data.Policy().SetPCRPolicyFrom(primaryKey.data.Policy())
	}

	return nil
}

// UpdatePCRProtectionPolicyV0 updates the PCR protection policy for this sealed key object to the profile defined by the
// pcrProfile argument. This function only works with version 0 sealed key data objects. In order to do this, the caller
// must also specify the path to the policy update data file that was originally saved by SealKeyToTPM.
//
// The sequence number of the new PCR policy will be incremented by 1 compared with the value associated with the current
// PCR policy. This does not increment the PCR policy NV counter on the TPM - this can be done with a subsequent call to
// RevokeOldPCRProtectionPoliciesV0.

// If the policy update data file cannot be opened, a wrapped *os.PathError error will be returned.
//
// If validation of the sealed key data fails, a InvalidKeyDataError error will be returned.
//
// On success, this SealedKeyObject will have an updated authorization policy that includes a PCR policy computed
// from the supplied PCRProtectionProfile. It must be persisted using SealedKeyObject.WriteAtomic.
func (k *SealedKeyObject) UpdatePCRProtectionPolicyV0(tpm *Connection, policyUpdatePath string, pcrProfile *PCRProtectionProfile) error {
	policyUpdateFile, err := os.Open(policyUpdatePath)
	if err != nil {
		return xerrors.Errorf("cannot open private data file: %w", err)
	}
	defer policyUpdateFile.Close()

	policyUpdateData, err := decodeKeyPolicyUpdateData(policyUpdateFile)
	if err != nil {
		return InvalidKeyDataError{fmt.Sprintf("cannot read dynamic policy update data: %v", err)}
	}
	if k.data.Version() != 0 {
		return InvalidKeyDataError{"invalid metadata versions"}
	}

	return updateKeyPCRProtectionPolicyCommon(tpm.TPMContext, []*SealedKeyObject{k}, policyUpdateData.AuthKey, pcrProfile, tpm.HmacSession())
}

// RevokeOldPCRProtectionPoliciesV0 revokes old PCR protection policies associated with this sealed key. It does
// this by incrementing the PCR policy counter associated with this sealed key on the TPM so that it contains the
// value of the current PCR policy sequence number. PCR policies with a lower sequence number cannot be satisfied
// and become invalid. The PCR policy sequence number is incremented on each call to UpdatePCRProtectionPolicyV0.
//
// This function only works with version 0 sealed key data objects. The caller must specify the path to the
// policy update data file that was originally saved by SealKeyToTPM.
//
// Note that this will perform a NV write for each call to UpdatePCRProtectionPolicyV0 since the last call
// to RevokeOldPCRProtectionPoliciesV0. As TPMs may apply rate-limiting to NV writes, this should be called
// after each call to UpdatePCRProtectionPolicyV0 that removes some PCR policy branches.
//
// If validation of the key data fails, a InvalidKeyDataError error will be returned.
func (k *SealedKeyObject) RevokeOldPCRProtectionPoliciesV0(tpm *Connection, policyUpdatePath string) error {
	policyUpdateFile, err := os.Open(policyUpdatePath)
	if err != nil {
		return xerrors.Errorf("cannot open private data file: %w", err)
	}
	defer policyUpdateFile.Close()

	policyUpdateData, err := decodeKeyPolicyUpdateData(policyUpdateFile)
	if err != nil {
		return InvalidKeyDataError{fmt.Sprintf("cannot read dynamic policy update data: %v", err)}
	}
	if k.data.Version() != 0 {
		return InvalidKeyDataError{"invalid metadata version"}
	}

	return k.revokeOldPCRProtectionPoliciesImpl(tpm.TPMContext, policyUpdateData.AuthKey, tpm.HmacSession())
}

// UpdatePCRProtectionPolicy updates the PCR protection policy for this sealed key object to the profile defined by the
// pcrProfile argument. In order to do this, the caller must also specify the private part of the authorization key
// that was either returned by SealKeyToTPM or SealedKeyObject.UnsealFromTPM.
//
// If the sealed key was created with a PCR policy counter, then the sequence number of the new PCR policy will be
// incremented by 1 compared with the value associated with the current PCR policy. This does not increment the NV
// counter on the TPM - this can be done with a subsequent call to RevokeOldPCRProtectionPolicies.
//
// On success, this SealedKeyObject will have an updated authorization policy that includes a PCR policy computed
// from the supplied PCRProtectionProfile. It must be persisted using SealedKeyObject.WriteAtomic.
func (k *SealedKeyObject) UpdatePCRProtectionPolicy(tpm *Connection, authKey secboot.AuxiliaryKey, pcrProfile *PCRProtectionProfile) error {
	return updateKeyPCRProtectionPolicyCommon(tpm.TPMContext, []*SealedKeyObject{k}, authKey, pcrProfile, tpm.HmacSession())
}

// RevokeOldPCRProtectionPolicies revokes old PCR protection policies associated with this sealed key. It does
// this by incrementing the PCR policy counter associated with this sealed key on the TPM so that it contains the
// value of the current PCR policy sequence number. PCR policies with a lower sequence number cannot be satisfied
// and become invalid. The PCR policy sequence number is incremented on each call to UpdatePCRProtectionPolicy.
// If the key data was not created with a PCR policy counter, then this function does nothing.
//
// The caller must also specify the private part of the authorization key that was either returned by SealKeyToTPM
// or SealedKeyObject.UnsealFromTPM.
//
// Note that this will perform a NV write for each call to UpdatePCRProtectionPolicy since the last call
// to RevokeOldPCRProtectionPolicies. As TPMs may apply rate-limiting to NV writes, this should be called
// after each call to UpdatePCRProtectionPolicy that removes some PCR policy branches.
//
// If validation of the key data fails, a InvalidKeyDataError error will be returned.
func (k *SealedKeyObject) RevokeOldPCRProtectionPolicies(tpm *Connection, authKey secboot.AuxiliaryKey) error {
	return k.revokeOldPCRProtectionPoliciesImpl(tpm.TPMContext, authKey, tpm.HmacSession())
}

// UpdateKeyPCRProtectionPolicyMultiple updates the PCR protection policy for the supplied sealed key objects to the
// profile defined by the pcrProfile argument. The keys must all be related (ie, they were created using
// SealKeyToTPMMultiple). If any key in the supplied set is not related, an error will be returned.
//
// If validation of any sealed key object fails, a InvalidKeyDataError error will be returned.
//
// On success, each of the supplied SealedKeyObjects will have an updated authorization policy that includes a
// PCR policy computed from the supplied PCRProtectionProfile. They must be persisted using
// SealedKeyObject.WriteAtomic.
func UpdateKeyPCRProtectionPolicyMultiple(tpm *Connection, keys []*SealedKeyObject, authKey secboot.AuxiliaryKey, pcrProfile *PCRProtectionProfile) error {
	if len(keys) == 0 {
		return errors.New("no sealed keys supplied")
	}

	return updateKeyPCRProtectionPolicyCommon(tpm.TPMContext, keys, authKey, pcrProfile, tpm.HmacSession())
}
