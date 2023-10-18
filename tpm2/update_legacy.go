// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2022 Canonical Ltd
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
	"errors"
	"fmt"
	"os"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
)

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
//
// Deprecated: Only useful for V0 key data files.
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

	return k.updatePCRProtectionPolicy(tpm.TPMContext, policyUpdateData.AuthKey, "", pcrProfile, true, tpm.HmacSession())
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
//
// Deprecated: Only useful for V0 key data files.
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

	return k.revokeOldPCRProtectionPolicies(tpm.TPMContext, policyUpdateData.AuthKey, "", tpm.HmacSession())
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
func (k *SealedKeyObject) UpdatePCRProtectionPolicy(tpm *Connection, authKey secboot.PrimaryKey, pcrProfile *PCRProtectionProfile) error {
	return k.updatePCRProtectionPolicy(tpm.TPMContext, authKey, "", pcrProfile, true, tpm.HmacSession())
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
func (k *SealedKeyObject) RevokeOldPCRProtectionPolicies(tpm *Connection, authKey secboot.PrimaryKey) error {
	return k.revokeOldPCRProtectionPolicies(tpm.TPMContext, authKey, "", tpm.HmacSession())
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
//
// Deprecated: Use UpdateKeyDataPCRProtectionPolicy.
func UpdateKeyPCRProtectionPolicyMultiple(tpm *Connection, keys []*SealedKeyObject, authKey secboot.PrimaryKey, pcrProfile *PCRProtectionProfile) error {
	if len(keys) == 0 {
		return errors.New("no sealed keys supplied")
	}

	for i, key := range keys {
		if err := key.UpdatePCRProtectionPolicy(tpm, authKey, pcrProfile); err != nil {
			return xerrors.Errorf("cannot update key at index %d: %w", i, err)
		}
	}

	return nil
}
