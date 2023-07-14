// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2021 Canonical Ltd
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
	"github.com/canonical/go-tpm2/mu"

	"github.com/snapcore/secboot"
)

// UnsealFromTPM will load the TPM sealed object in to the TPM and attempt to
// unseal it, returning the cleartext key on success.
//
// If the TPM's dictionary attack logic has been triggered, a ErrTPMLockout error
// will be returned.
//
// If the TPM is not correctly provisioned with a valid storage root key and a
// transient one cannot be created, an ErrTPMProvisioning error will be returned.
// In this case, Connection.EnsureProvisioned should be called to attempt to resolve
// this.
//
// If the TPM sealed object cannot be loaded in to the TPM for reasons other than
// the lack of a valid storage root key, then a InvalidKeyDataError error will be returned.
// This could be caused because the sealed object data is invalid in some way, or because
// the sealed object is associated with another TPM owner (the TPM has been cleared
// since the sealed key data file was created with SealKeyToTPM), or because the
// TPM object at the persistent handle reserved for the storage root key has a public area
// that looks like a valid storage root key but it was created with a different template.
// This latter case is really caused by an incorrectly provisioned TPM, but it isn't
// possible to differentiate between the 2 errors. A subsequent call to SealKeyToTPM
// or Connection.EnsureProvisioned may rectify this.
//
// If the TPM's current PCR values are not consistent with the PCR protection policy
// for this key file, a InvalidKeyDataError error will be returned.
//
// If any of the metadata in this key file is invalid, a InvalidKeyDataError error
// will be returned.
//
// If the TPM is missing any persistent resources associated with this key file,
// then a InvalidKeyDataError error will be returned.
//
// If the PCR policy has been revoked (eg, by a call to
// SealedKeyObject.RevokeOldPCRProtectionPolicies), then a InvalidKeyDataError error
// will be returned.
//
// If the PCR policy has an invalid signature, then a InvalidKeyDataError error will be
// returned.
//
// If the PCR policy metadata is not consistent with the approved policy digest, then a
// InvalidKeyDataError error will be returned.
//
// If the authorization policy check fails during unsealing, then a InvalidKeyDataError
// error will be returned.
//
// On success, the unsealed cleartext key is returned as the first return value, and the
// private part of the key used for authorizing PCR policy updates with
// SealedKeyObject.UpdatePCRProtectionPolicy is returned as the second return value.
//
// Deprecated: Use NewKeyData and the secboot.KeyData API for key recovery.
func (k *SealedKeyObject) UnsealFromTPM(tpm *Connection) (key secboot.DiskUnlockKey, authKey secboot.PrimaryKey, err error) {
	data, err := k.unsealDataFromTPM(tpm.TPMContext, nil, tpm.HmacSession())
	if err != nil {
		return nil, nil, err
	}

	if k.data.Version() == 0 {
		return secboot.DiskUnlockKey(data), nil, nil
	}

	var sealedData sealedData
	if _, err := mu.UnmarshalFromBytes(data, &sealedData); err != nil {
		return nil, nil, InvalidKeyDataError{err.Error()}
	}

	return sealedData.Key, sealedData.AuthPrivateKey, nil
}
