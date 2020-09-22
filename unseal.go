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
	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot/internal/tcg"

	"golang.org/x/xerrors"
)

// UnsealFromTPM will load the TPM sealed object in to the TPM and attempt to unseal it, returning the cleartext key on success.
// If a PIN has been set, the correct PIN must be provided via the pin argument. If the wrong PIN is provided, a ErrPINFail error
// will be returned, and the TPM's dictionary attack counter will be incremented.
//
// If the TPM's dictionary attack logic has been triggered, a ErrTPMLockout error will be returned.
//
// If the TPM is not provisioned correctly, then a ErrTPMProvisioning error will be returned. In this case, ProvisionTPM should be
// called to attempt to resolve this.
//
// If the TPM sealed object cannot be loaded in to the TPM for reasons other than the lack of a storage root key, then a
// InvalidKeyFileError error will be returned. This could be caused because the sealed object data is invalid in some way, or because
// the sealed object is associated with another TPM owner (the TPM has been cleared since the sealed key data file was created with
// SealKeyToTPM), or because the TPM object at the persistent handle reserved for the storage root key has a public area that looks
// like a valid storage root key but it was created with the wrong template. This latter case is really caused by an incorrectly
// provisioned TPM, but it isn't possible to detect this. A subsequent call to SealKeyToTPM or ProvisionTPM will rectify this.
//
// If the TPM's current PCR values are not consistent with the PCR protection policy for this key file, a InvalidKeyFileError error
// will be returned.
//
// If any of the metadata in this key file is invalid, a InvalidKeyFileError error will be returned.
//
// If the TPM is missing any persistent resources associated with this key file, then a InvalidKeyFileError error will be returned.
//
// If the key file has been superceded (eg, by a call to UpdateKeyPCRProtectionPolicy), then a InvalidKeyFileError error will be
// returned.
//
// If the signature of the updatable part of the key file's authorization policy is invalid, then a InvalidKeyFileError error will
// be returned.
//
// If the metadata for the updatable part of the key file's authorization policy is not consistent with the approved policy, then a
// InvalidKeyFileError error will be returned.
//
// If the provided PIN is incorrect, then a ErrPINFail error will be returned and the TPM's dictionary attack counter will be
// incremented.
//
// If access to sealed key objects created by this package is disallowed until the next TPM reset or TPM restart, then a
// ErrSealedKeyAccessLocked error will be returned.
//
// If the authorization policy check fails during unsealing, then a InvalidKeyFileError error will be returned. Note that this
// condition can also occur as the result of an incorrectly provisioned TPM, which will be detected during a subsequent call to
// SealKeyToTPM.
//
// On success, the unsealed cleartext key is returned as the first return value, and the private part of the key used for
// authorizing PCR policy updates with UpdateKeyPCRProtectionPolicy is returned as the second return value.
func (k *SealedKeyObject) UnsealFromTPM(tpm *TPMConnection, pin string) (key []byte, authKey TPMPolicyAuthKey, err error) {
	// Use the HMAC session created when the connection was opened for parameter encryption rather than creating a new one.
	hmacSession := tpm.HmacSession()

	// Load the key data
	keyObject, err := k.data.load(tpm.TPMContext, hmacSession)
	switch {
	case tpm2.IsResourceUnavailableError(err, tcg.SRKHandle):
		return nil, nil, ErrTPMProvisioning
	case isKeyFileError(err):
		// A keyFileError can be as a result of an improperly provisioned TPM - detect if the object at tcg.SRKHandle is a valid primary key
		// with the correct attributes. If it's not, then it's definitely a provisioning error because the object at tcg.SRKHandle is not
		// the one that we provisioned the TPM with. If it is, then it could still be a provisioning error because we don't know if the
		// object was created with the same template that ProvisionTPM uses, but in this case, we can't tell the difference between an
		// invalid key file or a provisioning error.
		srk, err2 := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
		if err2 != nil {
			return nil, nil, xerrors.Errorf("cannot create context for SRK: %w", err2)
		}
		ok, err2 := isObjectPrimaryKeyWithTemplate(tpm.TPMContext, tpm.OwnerHandleContext(), srk, tcg.SRKTemplate, tpm.HmacSession())
		switch {
		case err2 != nil:
			return nil, nil, xerrors.Errorf("cannot determine if object at %v is a primary key in the storage hierarchy: %w", tcg.SRKHandle, err2)
		case !ok:
			return nil, nil, ErrTPMProvisioning
		}
		return nil, nil, InvalidKeyFileError{err.Error()}
	case err != nil:
		return nil, nil, xerrors.Errorf("cannot load sealed key in to TPM: %w", err)
	}
	defer tpm.FlushContext(keyObject)

	// Begin and execute policy session
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, k.data.keyPublic.NameAlg)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot start policy session: %w", err)
	}
	defer tpm.FlushContext(policySession)

	if err := executePolicySession(tpm.TPMContext, policySession, k.data.version, k.data.staticPolicyData, k.data.dynamicPolicyData, pin, hmacSession); err != nil {
		err = xerrors.Errorf("cannot complete authorization policy assertions: %w", err)
		switch {
		case isDynamicPolicyDataError(err):
			// TODO: Add a separate error for this
			return nil, nil, InvalidKeyFileError{err.Error()}
		case isStaticPolicyDataError(err):
			return nil, nil, InvalidKeyFileError{err.Error()}
		case isAuthFailError(err, tpm2.CommandPolicySecret, 1):
			return nil, nil, ErrPINFail
		case tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandPolicySecret):
			return nil, nil, ErrTPMLockout
		case tpm2.IsResourceUnavailableError(err, lockNVHandle):
			return nil, nil, ErrTPMProvisioning
		case tpm2.IsTPMError(err, tpm2.ErrorNVLocked, tpm2.CommandPolicyNV):
			return nil, nil, ErrSealedKeyAccessLocked
		}
		return nil, nil, err
	}

	// For metadata version > 0, the PIN is the auth value for the sealed key object, and the authorization
	// policy asserts that this value is known when the policy session is used.
	keyObject.SetAuthValue([]byte(pin))

	// Unseal
	keyData, err := tpm.Unseal(keyObject, policySession, hmacSession.IncludeAttrs(tpm2.AttrResponseEncrypt))
	switch {
	case tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandUnseal, 1):
		return nil, nil, InvalidKeyFileError{"the authorization policy check failed during unsealing"}
	case isAuthFailError(err, tpm2.CommandUnseal, 1):
		return nil, nil, ErrPINFail
	case err != nil:
		return nil, nil, xerrors.Errorf("cannot unseal key: %w", err)
	}

	if k.data.version == 0 {
		return keyData, nil, nil
	}

	var sealedData sealedData
	if _, err := tpm2.UnmarshalFromBytes(keyData, &sealedData); err != nil {
		return nil, nil, InvalidKeyFileError{err.Error()}
	}

	return sealedData.Key, sealedData.AuthPrivateKey, nil
}
