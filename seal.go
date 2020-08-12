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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

func computeSealedKeyDynamicAuthPolicy(tpm *tpm2.TPMContext, version uint32, alg, signAlg tpm2.HashAlgorithmId, authKey *rsa.PrivateKey,
	counterPub *tpm2.NVPublic, counterAuthPolicies tpm2.DigestList, pcrProfile *PCRProtectionProfile, policyRef tpm2.Nonce,
	session tpm2.SessionContext) (*dynamicPolicyData, error) {
	// Obtain the count for the new policy
	nextPolicyCount, err := readDynamicPolicyCounter(tpm, version, counterPub, counterAuthPolicies, session)
	if err != nil {
		return nil, xerrors.Errorf("cannot read policy counter: %w", err)
	}
	nextPolicyCount += 1

	counterName, err := counterPub.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute name of policy counter: %w", err)
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
		policyCount:       nextPolicyCount,
		policyRef:         policyRef}

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

	// PolicyCounterHandle is the handle at which to create a NV index for dynamic authorization poliy revocation support. The handle
	// must be a valid NV index handle (MSO == 0x01) and the choice of handle should take in to consideration the reserved indices
	// from the "Registry of reserved TPM 2.0 handles and localities" specification. It is recommended that the handle is in the block
	// reserved for owner objects (0x01800000 - 0x01bfffff).
	PolicyCounterHandle tpm2.Handle
}

// SealKeyToTPM seals the supplied disk encryption key to the storage hierarchy of the TPM. The sealed key object and associated
// metadata that is required during early boot in order to unseal the key again and unlock the associated encrypted volume is written
// to a file at the path specified by keyPath. Additional data that is required in order to update the authorization policy for the
// sealed key is written to a file at the path specified by policyUpdatePath. This file must live inside the encrypted volume
// protected by the sealed key.
//
// The supplied key must be 64-bytes long. An error will be returned if it isn't.
//
// This function requires knowledge of the authorization value for the storage hierarchy, which must be provided by calling
// TPMConnection.OwnerHandleContext().SetAuthValue() prior to calling this function. If the provided authorization value is incorrect,
// a AuthFailError error will be returned.
//
// If the TPM is not correctly provisioned, a ErrTPMProvisioning error will be returned. In this case, ProvisionTPM must be called
// before proceeding.
//
// This function expects there to be no files at the specified paths. If either path references a file that already exists, a wrapped
// *os.PathError error will be returned with an underlying error of syscall.EEXIST. A wrapped *os.PathError error will be returned if
// either file cannot be created and opened for writing.
//
// This function will create a NV index at the handle specified by the PolicyCounterHandle field of the params argument. If the handle
// is already in use, a TPMResourceExistsError error will be returned. In this case, the caller will need to either choose a different
// handle or undefine the existing one. The handle must be a valid NV index handle (MSO == 0x01), and the choice of handle should take
// in to consideration the reserved indices from the "Registry of reserved TPM 2.0 handles and localities" specification. It is
// recommended that the handle is in the block reserved for owner objects (0x01800000 - 0x01bfffff).
//
// The key will be protected with a PCR policy computed from the PCRProtectionProfile supplied via the PCRProfile field of the params
// argument.
func SealKeyToTPM(tpm *TPMConnection, key []byte, keyPath, policyUpdatePath string, params *KeyCreationParams) error {
	// params is mandatory.
	if params == nil {
		return errors.New("no KeyCreationParams provided")
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
			return AuthFailError{tpm2.HandleOwner}
		case err != nil:
			return xerrors.Errorf("cannot provision storage root key: %w", err)
		}
	}

	// Validate that the lock NV index is valid and obtain its name
	lockIndex, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	switch {
	case tpm2.IsResourceUnavailableError(err, lockNVHandle):
		return ErrTPMProvisioning
	case err != nil:
		return xerrors.Errorf("cannot create context for lock NV index: %w", err)
	}

	lockIndexPub, err := readAndValidateLockNVIndexPublic(tpm.TPMContext, lockIndex, session)
	if err != nil {
		return ErrTPMProvisioning
	}
	lockIndexName, err := lockIndexPub.Name()
	if err != nil {
		return xerrors.Errorf("cannot compute name of global lock NV index: %w", err)
	}

	succeeded := false

	// Create destination files
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return xerrors.Errorf("cannot create key data file: %w", err)
	}
	defer func() {
		keyFile.Close()
		if succeeded {
			return
		}
		os.Remove(keyPath)
	}()

	var policyUpdateFile *os.File
	if policyUpdatePath != "" {
		var err error
		policyUpdateFile, err = os.OpenFile(policyUpdatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return xerrors.Errorf("cannot create private data file: %w", err)
		}
		defer func() {
			policyUpdateFile.Close()
			if succeeded {
				return
			}
			os.Remove(policyUpdatePath)
		}()
	}

	// Create an asymmetric key for signing authorization policy updates, and authorizing dynamic authorization policy revocations.
	authKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return xerrors.Errorf("cannot generate RSA key pair for signing dynamic authorization policies: %w", err)
	}
	authPublicKey := createPublicAreaForRSASigningKey(&authKey.PublicKey)
	authKeyName, err := authPublicKey.Name()
	if err != nil {
		return xerrors.Errorf("cannot compute name of signing key for dynamic policy authorization: %w", err)
	}

	// Create dynamic policy counter
	policyCounterPub, err := createDynamicPolicyCounter(tpm.TPMContext, params.PolicyCounterHandle, authKeyName, session)
	switch {
	case tpm2.IsTPMError(err, tpm2.ErrorNVDefined, tpm2.CommandNVDefineSpace):
		return TPMResourceExistsError{params.PolicyCounterHandle}
	case isAuthFailError(err, tpm2.CommandNVDefineSpace, 1):
		return AuthFailError{tpm2.HandleOwner}
	case err != nil:
		return xerrors.Errorf("cannot create new dynamic authorization policy counter: %w", err)
	}
	defer func() {
		if succeeded {
			return
		}
		index, err := tpm2.CreateNVIndexResourceContextFromPublic(policyCounterPub)
		if err != nil {
			return
		}
		tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, session)
	}()

	template := makeSealedKeyTemplate()

	// Compute the static policy - this never changes for the lifetime of this key file
	staticPolicyData, authPolicy, err := computeStaticPolicy(template.NameAlg, &staticPolicyComputeParams{
		key:              authPublicKey,
		policyCounterPub: policyCounterPub,
		lockIndexName:    lockIndexName})
	if err != nil {
		return xerrors.Errorf("cannot compute static authorization policy: %w", err)
	}

	// Define the template for the sealed key object, using the computed policy digest
	template.AuthPolicy = authPolicy
	sensitive := tpm2.SensitiveCreate{Data: key}

	// Have the digest of the private data recorded in the creation data for the sealed data object.
	authKeyBytes := x509.MarshalPKCS1PrivateKey(authKey)
	h := crypto.SHA256.New()
	if _, err := tpm2.MarshalToWriter(h, authKeyBytes); err != nil {
		panic(fmt.Sprintf("cannot marshal dynamic authorization policy update data: %v", err))
	}
	creationInfo := h.Sum(nil)

	// Now create the sealed key object. The command is integrity protected so if the object at the handle we expect the SRK to reside
	// at has a different name (ie, if we're connected via a resource manager and somebody swapped the object with another one), this
	// command will fail. We take advantage of parameter encryption here too.
	priv, pub, creationData, _, creationTicket, err :=
		tpm.Create(srk, &sensitive, template, creationInfo, nil, session.IncludeAttrs(tpm2.AttrCommandEncrypt))
	if err != nil {
		return xerrors.Errorf("cannot create sealed data object for key: %w", err)
	}

	// Create a dynamic authorization policy
	pcrProfile := params.PCRProfile
	if pcrProfile == nil {
		pcrProfile = &PCRProtectionProfile{}
	}
	dynamicPolicyData, err := computeSealedKeyDynamicAuthPolicy(tpm.TPMContext, currentMetadataVersion, template.NameAlg,
		authPublicKey.NameAlg, authKey, policyCounterPub, nil, pcrProfile, staticPolicyData.dynamicPolicyRef, session)
	if err != nil {
		return xerrors.Errorf("cannot compute dynamic authorization policy: %w", err)
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
		return xerrors.Errorf("cannot write key data file: %w", err)
	}

	if policyUpdateFile != nil {
		policyUpdateData := keyPolicyUpdateData{
			version:        currentMetadataVersion,
			authKey:        authKey,
			creationInfo:   creationInfo,
			creationData:   creationData,
			creationTicket: creationTicket}

		// Marshal the private data to disk
		if err := policyUpdateData.write(policyUpdateFile); err != nil {
			return xerrors.Errorf("cannot write dynamic authorization policy update data file: %w", err)
		}
	}

	if err := incrementDynamicPolicyCounter(tpm.TPMContext, currentMetadataVersion, policyCounterPub, nil, authKey, authPublicKey,
		session); err != nil {
		return xerrors.Errorf("cannot increment dynamic policy counter: %w", err)
	}

	succeeded = true
	return nil
}

// UpdateKeyPCRProtectionPolicy updates the PCR protection policy for the sealed key at the path specified by the keyPath argument
// to the profile defined by the pcrProfile argument. In order to do this, the caller must also specify the path to the policy update
// data file that was saved by SealKeyToTPM.
//
// If either file cannot be opened, a wrapped *os.PathError error will be returned.
//
// If either file cannot be deserialized correctly or validation of the files fails, a InvalidKeyFileError error will be returned.
//
// On success, the sealed key data file is updated atomically with an updated authorization policy that includes a PCR policy
// computed from the supplied PCRProtectionProfile.
func UpdateKeyPCRProtectionPolicy(tpm *TPMConnection, keyPath, policyUpdatePath string, pcrProfile *PCRProtectionProfile) error {
	// Use the HMAC session created when the connection was opened rather than creating a new one.
	session := tpm.HmacSession()

	// Open the key data file
	keyFile, err := os.Open(keyPath)
	if err != nil {
		return xerrors.Errorf("cannot open key data file: %w", err)
	}
	defer keyFile.Close()

	// Open the policy update data file
	policyUpdateFile, err := os.Open(policyUpdatePath)
	if err != nil {
		return xerrors.Errorf("cannot open private data file: %w", err)
	}
	defer policyUpdateFile.Close()

	data, policyUpdateData, policyCounterPub, err := decodeAndValidateKeyData(tpm.TPMContext, keyFile, policyUpdateFile, session)
	if err != nil {
		if isKeyFileError(err) {
			return InvalidKeyFileError{err.Error()}
		}
		// FIXME: Turn the missing lock NV index in to ErrProvisioning
		return xerrors.Errorf("cannot read and validate key data file: %w", err)
	}

	authPublicKey := data.staticPolicyData.authPublicKey
	authKey := policyUpdateData.authKey
	v0PinIndexAuthPolicies := data.staticPolicyData.v0PinIndexAuthPolicies

	// Compute a new dynamic authorization policy
	if pcrProfile == nil {
		pcrProfile = &PCRProtectionProfile{}
	}
	policyData, err := computeSealedKeyDynamicAuthPolicy(tpm.TPMContext, data.version, data.keyPublic.NameAlg, authPublicKey.NameAlg,
		authKey, policyCounterPub, v0PinIndexAuthPolicies, pcrProfile, data.staticPolicyData.dynamicPolicyRef, session)
	if err != nil {
		return xerrors.Errorf("cannot compute dynamic authorization policy: %w", err)
	}

	// Atomically update the key data file
	data.dynamicPolicyData = policyData

	if err := data.writeToFileAtomic(keyPath); err != nil {
		return xerrors.Errorf("cannot write key data file: %v", err)
	}

	if err := incrementDynamicPolicyCounter(tpm.TPMContext, data.version, policyCounterPub, v0PinIndexAuthPolicies, authKey,
		authPublicKey, session); err != nil {
		return xerrors.Errorf("cannot revoke old dynamic authorization policies: %w", err)
	}

	return nil
}
