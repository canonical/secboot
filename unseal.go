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
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/canonical/go-tpm2"

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
// On success, the unsealed cleartext key is returned.
func (k *SealedKeyObject) UnsealFromTPM(tpm *TPMConnection, pin string) ([]byte, error) {
	// Check if the TPM is in lockout mode
	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return nil, xerrors.Errorf("cannot fetch properties from TPM: %w", err)
	}

	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrInLockout > 0 {
		return nil, ErrTPMLockout
	}

	// Use the HMAC session created when the connection was opened for parameter encryption rather than creating a new one.
	hmacSession := tpm.HmacSession()

	// Load the key data
	keyObject, err := k.data.load(tpm.TPMContext, hmacSession)
	switch {
	case isKeyFileError(err):
		// A keyFileError can be as a result of an improperly provisioned TPM - detect if the object at srkHandle is a valid primary key
		// with the correct attributes. If it's not, then it's definitely a provisioning error. If it is, then it could still be a
		// provisioning error because we don't know if the object was created with the same template that ProvisionTPM uses. In that case,
		// we'll just assume an invalid key file
		srk, err2 := tpm.CreateResourceContextFromTPM(srkHandle)
		switch {
		case tpm2.IsResourceUnavailableError(err2, srkHandle):
			return nil, ErrTPMProvisioning
		case err2 != nil:
			return nil, xerrors.Errorf("cannot create context for SRK: %w", err2)
		}
		ok, err2 := isObjectPrimaryKeyWithTemplate(tpm.TPMContext, tpm.OwnerHandleContext(), srk, srkTemplate, tpm.HmacSession())
		switch {
		case err2 != nil:
			return nil, xerrors.Errorf("cannot determine if object at 0x%08x is a primary key in the storage hierarchy: %w", srkHandle, err2)
		case !ok:
			return nil, ErrTPMProvisioning
		}
		// This is probably a broken key file, but it could still be a provisioning error because we don't know if the SRK object was
		// created with the same template that ProvisionTPM uses.
		return nil, InvalidKeyFileError{err.Error()}
	case tpm2.IsResourceUnavailableError(err, srkHandle):
		return nil, ErrTPMProvisioning
	case err != nil:
		return nil, err
	}
	defer tpm.FlushContext(keyObject)

	var ikSplit *afSplitData
	var tpmAuthValue []byte
	if k.data.AuthModeHint == AuthModeNone {
		ikSplit = k.data.UnprotectedIK
	} else {
		var err error
		ikSplit, tpmAuthValue, err = k.data.PINData.decryptIKAndObtainTPMAuthValue(pin)
		if err != nil {
			return nil, InvalidKeyFileError{fmt.Sprintf("cannot decrypt intermediate key: %v", err)}
		}
	}

	// Begin and execute policy session
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, k.data.EncryptedKey.Public.NameAlg)
	if err != nil {
		return nil, xerrors.Errorf("cannot start policy session: %w", err)
	}
	defer tpm.FlushContext(policySession)

	if err := executePolicySession(tpm.TPMContext, policySession, k.data.StaticPolicyData, k.data.DynamicPolicyData, tpmAuthValue, hmacSession); err != nil {
		err = xerrors.Errorf("cannot complete authorization policy assertions: %w", err)
		switch {
		case isDynamicPolicyDataError(err):
			// TODO: Add a separate error for this
			return nil, InvalidKeyFileError{err.Error()}
		case isStaticPolicyDataError(err):
			return nil, InvalidKeyFileError{err.Error()}
		case isAuthFailError(err, tpm2.CommandPolicySecret, 1):
			return nil, ErrPINFail
		case tpm2.IsResourceUnavailableError(err, lockNVHandle):
			return nil, ErrTPMProvisioning
		case tpm2.IsTPMError(err, tpm2.ErrorNVLocked, tpm2.CommandPolicyNV):
			return nil, ErrSealedKeyAccessLocked
		}
		return nil, err
	}

	// Unseal
	key, err := tpm.Unseal(keyObject, policySession, hmacSession.IncludeAttrs(tpm2.AttrResponseEncrypt))
	switch {
	case tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandUnseal, 1):
		return nil, InvalidKeyFileError{"the authorization policy check failed during unsealing"}
	case err != nil:
		return nil, xerrors.Errorf("cannot unseal encrypted key: %w", err)
	}

	ik, err := ikSplit.merge()
	if err != nil {
		return nil, InvalidKeyFileError{fmt.Sprintf("cannot merge intermediate key stripes: %v", err)}
	}

	c, err := aes.NewCipher(ik)
	if err != nil {
		return nil, xerrors.Errorf("cannot create block cipher: %w", err)
	}
	if len(k.data.KeyIV) != c.BlockSize() {
		return nil, InvalidKeyFileError{"invalid IV length"}
	}
	if len(key)%c.BlockSize() != 0 {
		return nil, InvalidKeyFileError{"invalid encrypted key length"}
	}
	b := cipher.NewCBCDecrypter(c, k.data.KeyIV)
	b.CryptBlocks(key, key)

	return key, nil
}
