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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"
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

// computeSealedKeyDynamicAuthPolicy is a helper to compute a new PCR policy using the supplied
// pcrProfile, signed with the supplied authKey.
//
// If tpm is not nil, this function will verify that the supplied pcrProfile produces a PCR
// selection that is supported by the TPM. If tpm is nil, it will be assumed that the target
// TPM supports the PCRs and algorithms defined in the TCG PC Client Platform TPM Profile
// Specification for TPM 2.0.
//
// If tpm is not nil and counterPub is supplied, the current policy count will be read from
// the TPM and the new PCR policy will have a count of this value + 1. If tpm is nil then
// counterPub must also be nil, else an error will be returned.
func computeSealedKeyDynamicAuthPolicy(tpm *tpm2.TPMContext, version uint32, alg, signAlg tpm2.HashAlgorithmId, authKey crypto.PrivateKey,
	counterPub *tpm2.NVPublic, counterAuthPolicies tpm2.DigestList, pcrProfile *PCRProtectionProfile,
	session tpm2.SessionContext) (*dynamicPolicyData, error) {

	var nextPolicyCount uint64
	var counterName tpm2.Name
	var supportedPcrs tpm2.PCRSelectionList
	if tpm != nil {
		var err error
		// Obtain the count for the new policy
		if counterPub != nil {
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

		supportedPcrs, err = tpm.GetCapabilityPCRs(session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			return nil, xerrors.Errorf("cannot determine supported PCRs: %w", err)
		}
	} else {
		if counterPub != nil {
			return nil, errors.New("use of policy counter requires a TPM connection")
		}

		// Defined as mandatory in the TCG PC Client Platform TPM Profile Specification for TPM 2.0
		supportedPcrs = tpm2.PCRSelectionList{
			{Hash: tpm2.HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}},
			{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}}}
	}

	// Compute PCR digests
	pcrs, pcrDigests, err := pcrProfile.ComputePCRDigests(tpm, alg)
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

	// AuthKey can be set to chose an auhorisation key whose
	// private part will be used for authorizing PCR policy
	// updates with UpdateKeyPCRProtectionPolicy
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
// This function expects there to be no file at the specified path. If keyPath references a file that already exists, a wrapped
// *os.PathError error will be returned with an underlying error of syscall.EEXIST. A wrapped *os.PathError error will be returned if
// the file cannot be created and opened for writing.
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
func SealKeyToExternalTPMStorageKey(tpmKey *tpm2.Public, key []byte, keyPath string, params *KeyCreationParams) (authKey TPMPolicyAuthKey, err error) {
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

	pub := makeImportableSealedKeyTemplate()

	// Compute the static policy - this never changes for the lifetime of this key file
	staticPolicyData, authPolicy, err := computeStaticPolicy(pub.NameAlg, &staticPolicyComputeParams{key: authPublicKey})
	if err != nil {
		return nil, xerrors.Errorf("cannot compute static authorization policy: %w", err)
	}

	pub.AuthPolicy = authPolicy

	// Create a dynamic authorization policy
	pcrProfile := params.PCRProfile
	if pcrProfile == nil {
		pcrProfile = &PCRProtectionProfile{}
	}
	dynamicPolicyData, err := computeSealedKeyDynamicAuthPolicy(nil, currentMetadataVersion, pub.NameAlg, authPublicKey.NameAlg,
		goAuthKey, nil, nil, pcrProfile, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute dynamic authorization policy: %w", err)
	}

	// Clean up files on failure.
	defer func() {
		if succeeded {
			return
		}
		os.Remove(keyPath)
	}()

	// Seal key

	// Create the destination file
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, xerrors.Errorf("cannot create key data file: %w", err)
	}
	defer f.Close()

	// Create the sensitive data
	sealedData, err := mu.MarshalToBytes(sealedData{Key: key, AuthPrivateKey: authKey})
	if err != nil {
		panic(fmt.Sprintf("cannot marshal sensitive data: %v", err))
	}
	// Define the actual sensitive area. The initial auth value is empty - note
	// that tpm2.CreateDuplicationObjectFromSensitive pads this to the length of
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
	_, priv, importSymSeed, err := tpm2.CreateDuplicationObjectFromSensitive(&sensitive, pub, tpmKey, nil, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot create duplication object: %w", err)
	}

	// Marshal the entire object (sealed key object and auxiliary data) to disk
	data := tpmKeyData{
		version:           currentMetadataVersion,
		keyPrivate:        priv,
		keyPublic:         pub,
		authModeHint:      authModeNone,
		importSymSeed:     importSymSeed,
		staticPolicyData:  staticPolicyData,
		dynamicPolicyData: dynamicPolicyData}

	if err := data.write(f); err != nil {
		return nil, xerrors.Errorf("cannot write key data file: %w", err)
	}

	succeeded = true
	return authKey, nil
}

// SealKeyRequest corresponds to a key that should be sealed by SealKeyToTPMMultiple
// to a file at the specified path.
type SealKeyRequest struct {
	Key  []byte
	Path string
}

// SealKeyToTPMMultiple seals the supplied disk encryption keys to the storage hierarchy of the TPM. The keys are specified by
// the keys argument, which is a slice of associated key and corresponding file path. The sealed key objects and associated
// metadata that is required during early boot in order to unseal the keys again and unlock the associated encrypted volumes
// are written to files at the specifed paths.
//
// This function requires knowledge of the authorization value for the storage hierarchy, which must be provided by calling
// TPMConnection.OwnerHandleContext().SetAuthValue() prior to calling this function. If the provided authorization value is incorrect,
// a AuthFailError error will be returned.
//
// This function expects there to be no files at the specified paths. If the keys argument references a file that already exists, a
// wrapped *os.PathError error will be returned with an underlying error of syscall.EEXIST. A wrapped *os.PathError error will be
// returned if any file cannot be created and opened for writing.
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
func SealKeyToTPMMultiple(tpm *TPMConnection, keys []*SealKeyRequest, params *KeyCreationParams) (authKey TPMPolicyAuthKey, err error) {
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

	// Obtain a context for the SRK now. If we're called immediately after ProvisionTPM without closing the TPMConnection, we use the
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
	authKeyName, err := authPublicKey.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute name of signing key for dynamic policy authorization: %w", err)
	}
	authKey = goAuthKey.D.Bytes()

	// Create PCR policy counter, if requested.
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
		pcrPolicyCounterPub: pcrPolicyCounterPub})
	if err != nil {
		return nil, xerrors.Errorf("cannot compute static authorization policy: %w", err)
	}

	// Define the template for the sealed key object, using the computed policy digest
	template.AuthPolicy = authPolicy

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
	for _, key := range keys {
		// Create the destination file
		f, err := os.OpenFile(key.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, xerrors.Errorf("cannot create key data file %s: %w", key.Path, err)
		}
		// We'll close this at the end of this loop, but make sure it is closed if the function
		// returns early
		defer f.Close()

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

		// Marshal the entire object (sealed key object and auxiliary data) to disk
		data := tpmKeyData{
			version:           currentMetadataVersion,
			keyPrivate:        priv,
			keyPublic:         pub,
			authModeHint:      authModeNone,
			staticPolicyData:  staticPolicyData,
			dynamicPolicyData: dynamicPolicyData}

		if err := data.write(f); err != nil {
			return nil, xerrors.Errorf("cannot write key data file: %w", err)
		}

		f.Close()
	}

	// Increment the PCR policy counter for the first time.
	if pcrPolicyCounterPub != nil {
		if err := incrementPcrPolicyCounter(tpm.TPMContext, currentMetadataVersion, pcrPolicyCounterPub, nil, goAuthKey, authPublicKey,
			session); err != nil {
			return nil, xerrors.Errorf("cannot increment PCR policy counter: %w", err)
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
//
// The authorization key can also be chosen and provided by setting
// AuthKey in the params argument.
func SealKeyToTPM(tpm *TPMConnection, key []byte, keyPath string, params *KeyCreationParams) (authKey TPMPolicyAuthKey, err error) {
	return SealKeyToTPMMultiple(tpm, []*SealKeyRequest{{Key: key, Path: keyPath}}, params)
}

func updateKeyPCRProtectionPolicyCommon(tpm *tpm2.TPMContext, keyPaths []string, authData interface{}, pcrProfile *PCRProtectionProfile, session tpm2.SessionContext) error {
	if len(keyPaths) == 0 {
		return errors.New("no key files supplied")
	}

	var datas []*tpmKeyData
	// Open the primary data file
	keyFile, err := os.Open(keyPaths[0])
	if err != nil {
		return xerrors.Errorf("cannot open key data file: %w", err)
	}
	defer keyFile.Close()

	// Validate the primary file
	primaryData, authKey, pcrPolicyCounterPub, err := decodeAndValidateKeyData(tpm, keyFile, authData, session)
	if err != nil {
		if isKeyFileError(err) {
			return InvalidKeyFileError{err.Error()}
		}
		// FIXME: Turn the missing lock NV index in to ErrProvisioning
		return xerrors.Errorf("cannot read and validate key data file: %w", err)
	}
	datas = append(datas, primaryData)

	// Open and validate secondary files and make sure they are related
	for _, p := range keyPaths[1:] {
		keyFile, err := os.Open(p)
		if err != nil {
			return xerrors.Errorf("cannot open related key data file: %w", err)
		}
		defer keyFile.Close()

		data, _, _, err := decodeAndValidateKeyData(tpm, keyFile, nil, session)
		if err != nil {
			if isKeyFileError(err) {
				return InvalidKeyFileError{err.Error() + " (" + p + ")"}
			}
			// FIXME: Turn the missing lock NV index in to ErrProvisioning
			return xerrors.Errorf("cannot read and validate related key data file: %w", err)
		}
		// The metadata is valid and consistent with the object's static authorization policy.
		// Verify that it also has the same static authorization policy as the first key object passed
		// to this function. This policy digest includes a cryptographic record of the PCR policy counter
		// and dynamic authorization policy signing key, so this is the only check required to determine
		// if 2 keys are related.
		if !bytes.Equal(data.keyPublic.AuthPolicy, primaryData.keyPublic.AuthPolicy) {
			return InvalidKeyFileError{"key data file " + p + " is not a related key file"}
		}
		datas = append(datas, data)
	}

	authPublicKey := primaryData.staticPolicyData.authPublicKey
	v0PinIndexAuthPolicies := primaryData.staticPolicyData.v0PinIndexAuthPolicies

	// Compute a new dynamic authorization policy
	if pcrProfile == nil {
		pcrProfile = &PCRProtectionProfile{}
	}
	policyData, err := computeSealedKeyDynamicAuthPolicy(tpm, primaryData.version, primaryData.keyPublic.NameAlg, authPublicKey.NameAlg, authKey,
		pcrPolicyCounterPub, v0PinIndexAuthPolicies, pcrProfile, session)
	if err != nil {
		return xerrors.Errorf("cannot compute dynamic authorization policy: %w", err)
	}

	// Atomically update the key data files
	for i, data := range datas {
		data.dynamicPolicyData = policyData

		if err := data.writeToFileAtomic(keyPaths[i]); err != nil {
			return xerrors.Errorf("cannot write key data file: %v", err)
		}
	}

	if pcrPolicyCounterPub == nil {
		return nil
	}

	if err := incrementPcrPolicyCounter(tpm, primaryData.version, pcrPolicyCounterPub, v0PinIndexAuthPolicies, authKey, authPublicKey, session); err != nil {
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

	return updateKeyPCRProtectionPolicyCommon(tpm.TPMContext, []string{keyPath}, policyUpdateFile, pcrProfile, tpm.HmacSession())
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
// computed from the supplied PCRProtectionProfile. If the sealed key data file was created with a PCR policy counter, the
// previous PCR policy will be revoked.
func UpdateKeyPCRProtectionPolicy(tpm *TPMConnection, keyPath string, authKey TPMPolicyAuthKey, pcrProfile *PCRProtectionProfile) error {
	return updateKeyPCRProtectionPolicyCommon(tpm.TPMContext, []string{keyPath}, authKey, pcrProfile, tpm.HmacSession())
}

// UpdateKeyPCRProtectionPolicyMultiple updates the PCR protection policy for the sealed keys at the paths specified
// by the keyPaths argument to the profile defined by the pcrProfile argument. The keys must all be related (ie, they
// were created using SealKeyToTPMMultiple). If any key in the supplied set is not related, an error will be returned.
//
// If any file cannot be opened, a wrapped *os.PathError error will be returned.
//
// If any file cannot be deserialized correctly or validation of a file fails, a InvalidKeyFileError error will
// be returned.
//
// On success, each sealed key data file is updated atomically with an updated authorization policy that includes a PCR
// policy computed from the supplied PCRProtectionProfile. If the sealed key data files were created with a PCR policy
// counter, the previous PCR policy will be revoked only when all of the sealed key data files have been updated
// successfully. If any file is not updated successfully, the previous PCR policy will not be revoked and the associated
// error will be returned.
func UpdateKeyPCRProtectionPolicyMultiple(tpm *TPMConnection, keyPaths []string, authKey TPMPolicyAuthKey, pcrProfile *PCRProtectionProfile) error {
	return updateKeyPCRProtectionPolicyCommon(tpm.TPMContext, keyPaths, authKey, pcrProfile, tpm.HmacSession())
}
