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

package secboot

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot/internal/tcg"

	"golang.org/x/xerrors"
)

func makeSealedKeyTemplate() *tpm2.Public {
	return &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent,
		Params:  tpm2.PublicParamsU{Data: &tpm2.KeyedHashParams{Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
}

func computeSealedKeyDynamicAuthPolicy(tpm *tpm2.TPMContext, version uint32, alg, signAlg tpm2.HashAlgorithmId, authKey crypto.PrivateKey,
	counterPub *tpm2.NVPublic, counterAuthPolicies tpm2.DigestList, pcrProfile *PCRProtectionProfile,
	session tpm2.SessionContext) (*dynamicPolicyData, error) {
	// Obtain the count for the new policy
	var nextPolicyCount uint64
	var counterName tpm2.Name
	if counterPub != nil {
		var err error
		nextPolicyCount, err = readPcrPolicyCounter(tpm, version, counterPub, counterAuthPolicies, session)
		if err != nil {
			return nil, xerrors.Errorf("cannot read policy counter: %w", err)
		}
		nextPolicyCount += 1

		counterName, err = counterPub.Name()
		if err != nil {
			return nil, xerrors.Errorf("cannot compute name of policy counter: %w", err)
		}
	}

	supportedPcrs, err := tpm.GetCapabilityPCRs(session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return nil, xerrors.Errorf("cannot determine supported PCRs: %w", err)
	}

	// Compute PCR digests
	pcrs, pcrDigests, err := pcrProfile.computePCRDigests(tpm, alg)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute PCR digests from protection profile: %w", err)
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
				return nil, errors.New("PCR protection profile contains digests for unsupported PCRs")
			}
		}
	}

	// Use the PCR digests and NV index names to generate a single signed dynamic authorization policy digest
	policyParams := dynamicPolicyComputeParams{
		key:               authKey,
		signAlg:           signAlg,
		pcrs:              pcrs,
		pcrDigests:        pcrDigests,
		policyCounterName: counterName,
		policyCount:       nextPolicyCount}

	policyData, err := computeDynamicPolicy(version, alg, &policyParams)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute dynamic authorization policy: %w", err)
	}

	return policyData, nil
}

// KeyCreationParams provides arguments for SealKeyToTPM.
type KeyCreationParams struct {
	// PCRProfile defines the profile used to generate a PCR protection policy for the newly created sealed key file.
	PCRProfile *PCRProtectionProfile

	// PCRPolicyCounterHandle is the handle at which to create a NV index for dynamic authorization poliy revocation support. The handle
	// must either be tpm2.HandleNull (in which case, no NV index will be created and the sealed key will not benefit from dynamic
	// authorization policy revocation support), or it must be a valid NV index handle (MSO == 0x01). The choice of handle should take
	// in to consideration the reserved indices from the "Registry of reserved TPM 2.0 handles and localities" specification. It is
	// recommended that the handle is in the block reserved for owner objects (0x01800000 - 0x01bfffff).
	PCRPolicyCounterHandle tpm2.Handle
}

// SealKeyToTPM seals the supplied disk encryption key to the storage hierarchy of the TPM. The sealed key object and associated
// metadata that is required during early boot in order to unseal the key again and unlock the associated encrypted volume is written
// to a file at the path specified by keyPath.
//
// This function requires knowledge of the authorization value for the storage hierarchy, which must be provided by calling
// TPMConnection.OwnerHandleContext().SetAuthValue() prior to calling this function. If the provided authorization value is incorrect,
// a AuthFailError error will be returned.
//
// If the TPM is not correctly provisioned, a ErrTPMProvisioning error will be returned. In this case, ProvisionTPM must be called
// before proceeding.
//
// This function expects there to be no file at the specified path. If keyPath references a file that already exists, a wrapped
// *os.PathError error will be returned with an underlying error of syscall.EEXIST. A wrapped *os.PathError error will be returned if
// the file cannot be created and opened for writing.
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
func SealKeyToTPM(tpm *TPMConnection, key []byte, keyPath string, params *KeyCreationParams) (authKey TPMPolicyAuthKey, err error) {
	// params is mandatory.
	if params == nil {
		return nil, errors.New("no KeyCreationParams provided")
	}

	// Use the HMAC session created when the connection was opened rather than creating a new one.
	session := tpm.HmacSession()

	// Obtain a context for the SRK now. If we're called immediately after ProvisionTPM without closing the TPMConnection, we use the
	// context cached by ProvisionTPM, which corresponds to the object provisioned. If not, we just unconditionally provision a new
	// SRK as this function requires knowledge of the owner hierarchy authorization anyway. This way, we know that the primary key we
	// seal to is good and future calls to ProvisionTPM won't provision an object that cannot unseal the key we protect.
	srk := tpm.provisionedSrk
	if srk == nil {
		var err error
		srk, err = provisionPrimaryKey(tpm.TPMContext, tpm.OwnerHandleContext(), tcg.SRKTemplate, tcg.SRKHandle, session)
		switch {
		case isAuthFailError(err, tpm2.AnyCommandCode, 1):
			return nil, AuthFailError{tpm2.HandleOwner}
		case err != nil:
			return nil, xerrors.Errorf("cannot provision storage root key: %w", err)
		}
	}

	// Validate that the lock NV index is valid and obtain its name
	lockIndex, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	switch {
	case tpm2.IsResourceUnavailableError(err, lockNVHandle):
		return nil, ErrTPMProvisioning
	case err != nil:
		return nil, xerrors.Errorf("cannot create context for lock NV index: %w", err)
	}

	lockIndexPub, err := readAndValidateLockNVIndexPublic(tpm.TPMContext, lockIndex, session)
	if err != nil {
		return nil, ErrTPMProvisioning
	}
	lockIndexName, err := lockIndexPub.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute name of global lock NV index: %w", err)
	}

	succeeded := false

	// Create destination files
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, xerrors.Errorf("cannot create key data file: %w", err)
	}
	defer func() {
		keyFile.Close()
		if succeeded {
			return
		}
		os.Remove(keyPath)
	}()

	// Create an asymmetric key for signing authorization policy updates, and authorizing dynamic authorization policy revocations.
	goAuthKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, xerrors.Errorf("cannot generate RSA key pair for signing dynamic authorization policies: %w", err)
	}
	authPublicKey := createTPMPublicAreaForECDSAKey(&goAuthKey.PublicKey)
	authKeyName, err := authPublicKey.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute name of signing key for dynamic policy authorization: %w", err)
	}

	// Create PCR policy counter
	var pcrPolicyCounterPub *tpm2.NVPublic
	if params.PCRPolicyCounterHandle != tpm2.HandleNull {
		pcrPolicyCounterPub, err = createPcrPolicyCounter(tpm.TPMContext, params.PCRPolicyCounterHandle, authKeyName, session)
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

	// Compute the static policy - this never changes for the lifetime of this key file
	staticPolicyData, authPolicy, err := computeStaticPolicy(template.NameAlg, &staticPolicyComputeParams{
		key:                 authPublicKey,
		pcrPolicyCounterPub: pcrPolicyCounterPub,
		lockIndexName:       lockIndexName})
	if err != nil {
		return nil, xerrors.Errorf("cannot compute static authorization policy: %w", err)
	}

	// Define the template for the sealed key object, using the computed policy digest
	template.AuthPolicy = authPolicy

	// Create the sensitive data
	sealedData, err := tpm2.MarshalToBytes(sealedData{Key: key, AuthPrivateKey: goAuthKey.D.Bytes()})
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

	// Create a dynamic authorization policy
	pcrProfile := params.PCRProfile
	if pcrProfile == nil {
		pcrProfile = &PCRProtectionProfile{}
	}
	dynamicPolicyData, err := computeSealedKeyDynamicAuthPolicy(tpm.TPMContext, currentMetadataVersion, template.NameAlg,
		authPublicKey.NameAlg, goAuthKey, pcrPolicyCounterPub, nil, pcrProfile, session)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute dynamic authorization policy: %w", err)
	}

	// Marshal the entire object (sealed key object and auxiliary data) to disk
	data := keyData{
		version:           currentMetadataVersion,
		keyPrivate:        priv,
		keyPublic:         pub,
		authModeHint:      AuthModeNone,
		staticPolicyData:  staticPolicyData,
		dynamicPolicyData: dynamicPolicyData}

	if err := data.write(keyFile); err != nil {
		return nil, xerrors.Errorf("cannot write key data file: %w", err)
	}

	if pcrPolicyCounterPub != nil {
		if err := incrementPcrPolicyCounter(tpm.TPMContext, currentMetadataVersion, pcrPolicyCounterPub, nil, goAuthKey, authPublicKey,
			session); err != nil {
			return nil, xerrors.Errorf("cannot increment PCR policy counter: %w", err)
		}
	}

	succeeded = true
	return goAuthKey.D.Bytes(), nil
}

func updateKeyPCRProtectionPolicyCommon(tpm *tpm2.TPMContext, keyPath string, authData interface{}, pcrProfile *PCRProtectionProfile, session tpm2.SessionContext) error {
	// Open the key data file
	keyFile, err := os.Open(keyPath)
	if err != nil {
		return xerrors.Errorf("cannot open key data file: %w", err)
	}
	defer keyFile.Close()

	data, authKey, pcrPolicyCounterPub, err := decodeAndValidateKeyData(tpm, keyFile, authData, session)
	if err != nil {
		if isKeyFileError(err) {
			return InvalidKeyFileError{err.Error()}
		}
		// FIXME: Turn the missing lock NV index in to ErrProvisioning
		return xerrors.Errorf("cannot read and validate key data file: %w", err)
	}

	authPublicKey := data.staticPolicyData.authPublicKey
	v0PinIndexAuthPolicies := data.staticPolicyData.v0PinIndexAuthPolicies

	// Compute a new dynamic authorization policy
	if pcrProfile == nil {
		pcrProfile = &PCRProtectionProfile{}
	}
	policyData, err := computeSealedKeyDynamicAuthPolicy(tpm, data.version, data.keyPublic.NameAlg, authPublicKey.NameAlg, authKey,
		pcrPolicyCounterPub, v0PinIndexAuthPolicies, pcrProfile, session)
	if err != nil {
		return xerrors.Errorf("cannot compute dynamic authorization policy: %w", err)
	}

	// Atomically update the key data file
	data.dynamicPolicyData = policyData

	if err := data.writeToFileAtomic(keyPath); err != nil {
		return xerrors.Errorf("cannot write key data file: %v", err)
	}

	if pcrPolicyCounterPub == nil {
		return nil
	}

	if err := incrementPcrPolicyCounter(tpm, data.version, pcrPolicyCounterPub, v0PinIndexAuthPolicies, authKey, authPublicKey, session); err != nil {
		return xerrors.Errorf("cannot revoke old PCR policies: %w", err)
	}

	return nil
}

// UpdateKeyPCRProtectionPolicyV0 updates the PCR protection policy for the sealed key at the path specified by the keyPath argument
// to the profile defined by the pcrProfile argument. This function only works with version 0 sealed key files. In order to do this,
// the caller must also specify the path to the policy update data file that was originally saved by SealKeyToTPM.
//
// If either file cannot be opened, a wrapped *os.PathError error will be returned.
//
// If either file cannot be deserialized correctly or validation of the files fails, a InvalidKeyFileError error will be returned.
//
// On success, the sealed key data file is updated atomically with an updated authorization policy that includes a PCR policy
// computed from the supplied PCRProtectionProfile.
func UpdateKeyPCRProtectionPolicyV0(tpm *TPMConnection, keyPath, policyUpdatePath string, pcrProfile *PCRProtectionProfile) error {
	policyUpdateFile, err := os.Open(policyUpdatePath)
	if err != nil {
		return xerrors.Errorf("cannot open private data file: %w", err)
	}
	defer policyUpdateFile.Close()

	return updateKeyPCRProtectionPolicyCommon(tpm.TPMContext, keyPath, policyUpdateFile, pcrProfile, tpm.HmacSession())
}

// UpdateKeyPCRProtectionPolicy updates the PCR protection policy for the sealed key at the path specified by the keyPath argument
// to the profile defined by the pcrProfile argument. In order to do this, the caller must also specify the private part of the
// authorization key that was either returned by SealKeyToTPM or SealedKeyObject.UnsealFromTPM.
//
// If the file cannot be opened, a wrapped *os.PathError error will be returned.
//
// If the file cannot be deserialized correctly or validation of the file fails, a InvalidKeyFileError error will be returned.
//
// On success, the sealed key data file is updated atomically with an updated authorization policy that includes a PCR policy
// computed from the supplied PCRProtectionProfile.
func UpdateKeyPCRProtectionPolicy(tpm *TPMConnection, keyPath string, authKey TPMPolicyAuthKey, pcrProfile *PCRProtectionProfile) error {
	return updateKeyPCRProtectionPolicyCommon(tpm.TPMContext, keyPath, authKey, pcrProfile, tpm.HmacSession())
}
