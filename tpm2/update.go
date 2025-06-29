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

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
)

var skdbUpdatePCRProtectionPolicyNoValidate = (*sealedKeyDataBase).updatePCRProtectionPolicyNoValidate

// pcrPolicyVersionOption is used to tell sealedKeyDataBase.updatePCRProtectionPolicyNoValidate
// how to determine the version of a new PCR policy.
type pcrPolicyVersionOption int

const (
	// resetPcrPolicyVersion indicates that the new policy version should be set
	// to the current counter value. This is used for the initial policy when creating
	// any key, and is also used when updating a policy for existing keys with the
	// new SealedKeyData API when called with NoNewPCRPolicyVersion.
	resetPcrPolicyVersion pcrPolicyVersionOption = iota

	// newPcrPolicyVersion indicates that the new policy version should be the current
	// counter value plus 1. This is used when updating a policy for existing keys
	// with the new SealedKeyData API when called with NewPCRPolicyVersion. A subsequent
	// counter increment to the new policy version will revoke all policies created with
	// resetPcrPolicyVersion since the previous revocation.
	newPcrPolicyVersion

	// incrementPolicyVersion indicates that the new policy version should be the
	// current policy version plus 1, and is used to maintain the behaviour of
	// policy updates when using the previous SealedKeyObject API, which incremented
	// the policy version with every update.  A subsequent counter increment to the
	// new policy version will revoke all policies created since the previous
	// revocation, but this may require multiple counter increments (one per created
	// policy).
	incrementPcrPolicyVersion
)

// updatePCRProtectionPolicyNoValidate is a helper to update the PCR policy using the supplied
// profile, authorized with the supplied key.
//
// If tpm is not nil, this function will verify that the supplied profile produces a PCR
// selection that is supported by the TPM. If tpm is nil, it will be assumed that the target
// TPM supports the PCRs and algorithms defined in the TCG PC Client Platform TPM Profile
// Specification for TPM 2.0.
//
// If k.data.policy().pcrPolicyCounterHandle() is not tpm2.HandleNull, then counterPub
// must be supplied, and it must correspond to the public area associated with that handle.
func (k *sealedKeyDataBase) updatePCRProtectionPolicyNoValidate(tpm *tpm2.TPMContext, key secboot.PrimaryKey, role string,
	counterPub *tpm2.NVPublic, profile *PCRProtectionProfile, policyVersionOption pcrPolicyVersionOption) error {
	var policySequence uint64
	if counterPub != nil {
		if tpm == nil {
			return errors.New("TPM connection required to update PCR policy with revocation")
		}

		switch policyVersionOption {
		case resetPcrPolicyVersion, newPcrPolicyVersion:
			counterContext, err := k.data.Policy().PCRPolicyCounterContext(tpm, counterPub)
			if err != nil {
				return xerrors.Errorf("cannot obtain PCR policy counter context: %w", err)
			}

			value, err := counterContext.Get()
			if err != nil {
				return xerrors.Errorf("cannot obtain PCR policy counter value: %w", err)
			}

			policySequence = value
			if policyVersionOption == newPcrPolicyVersion {
				policySequence += 1
			}
		case incrementPcrPolicyVersion:
			policySequence = k.data.Policy().PCRPolicySequence() + 1
		}
	}

	var supportedPcrs tpm2.PCRSelectionList
	if tpm != nil {
		var err error
		supportedPcrs, err = tpm.GetCapabilityPCRs()
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
		key:            key,
		role:           []byte(role),
		pcrs:           pcrs,
		pcrDigests:     pcrDigests,
		policyCounter:  counterPub,
		policySequence: policySequence}
	return k.data.Policy().UpdatePCRPolicy(k.data.Public().NameAlg, params)
}

func (k *sealedKeyDataBase) revokeOldPCRProtectionPolicies(tpm *tpm2.TPMContext, key secboot.PrimaryKey, role string) error {
	pcrPolicyCounterPub, err := k.validateData(tpm, role)
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

	context, err := k.data.Policy().PCRPolicyCounterContext(tpm, pcrPolicyCounterPub)
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

func (k *sealedKeyDataBase) updatePCRProtectionPolicy(tpm *tpm2.TPMContext, authKey secboot.PrimaryKey, role string, pcrProfile *PCRProtectionProfile, policyVersionOption pcrPolicyVersionOption) error {
	pcrPolicyCounterPub, err := k.validateData(tpm, role)
	if err != nil {
		if isKeyDataError(err) {
			return InvalidKeyDataError{err.Error()}
		}
		return xerrors.Errorf("cannot validate key data: %w", err)
	}
	if err := k.data.Policy().ValidateAuthKey(authKey); err != nil {
		if isKeyDataError(err) {
			return InvalidKeyDataError{err.Error()}
		}
		return xerrors.Errorf("cannot validate auth key: %w", err)
	}

	if pcrProfile == nil {
		pcrProfile = NewPCRProtectionProfile()
	}
	return k.updatePCRProtectionPolicyNoValidate(tpm, authKey, role, pcrPolicyCounterPub, pcrProfile, policyVersionOption)
}

// PCRPolicyVersionOption describes how to set the version for a new PCR policy.
type PCRPolicyVersionOption int

const (
	// NoNewPCRPolicyVersion indicates that the version of an updated PCR
	// policy will be set to the current value of the PCR policy counter.
	NoNewPCRPolicyVersion PCRPolicyVersionOption = iota

	// NewPCRPolicyVersion indicates that the version of an updated PCR
	// policy will be set to the current value of the PCR policy counter
	// plus 1. A subsequent revocation (where the counter is incremented
	// by 1) will revoke all previous policies created with
	// NoNewPCRPolicyVersion since the last revocation.
	NewPCRPolicyVersion
)

func (o PCRPolicyVersionOption) internalOpt() pcrPolicyVersionOption {
	switch o {
	case NoNewPCRPolicyVersion:
		return resetPcrPolicyVersion
	case NewPCRPolicyVersion:
		return newPcrPolicyVersion
	default:
		panic("unexpected option")
	}
}

// UpdatePCRProtectionPolicy updates the PCR protection policy for this sealed key object to the profile defined by the
// pcrProfile argument. In order to do this, the caller must also specify the private part of the authorization key
// that was either returned by SealKeyToTPM or SealedKeyObject.UnsealFromTPM.
//
// If the sealed key was created with a PCR policy counter and policyVersionOption is set to [NoNewPCRPolicyVersion],
// the the sequence number of the new PCR policy will be set to the value of the corresponding counter. If
// policyVersionOption is set to [NewPCRPolicyVersion], then the sequence number will be set to 1 greater than the value
// of the corresponding counter. A subsequent call to RevokeOldPCRProtectionPolicies will revoke previous policies.
//
// On success, this SealedKeyObject will have an updated authorization policy that includes a PCR policy computed
// from the supplied PCRProtectionProfile. It must be persisted using SealedKeyObject.WriteAtomic.
func (k *SealedKeyData) UpdatePCRProtectionPolicy(tpm *Connection, authKey secboot.PrimaryKey, pcrProfile *PCRProtectionProfile, policyVersionOption PCRPolicyVersionOption) error {
	if err := k.updatePCRProtectionPolicy(tpm.TPMContext, authKey, k.k.Role(), pcrProfile, policyVersionOption.internalOpt()); err != nil {
		return xerrors.Errorf("cannot update PCR protection policy: %w", err)
	}
	if err := k.k.MarshalAndUpdatePlatformHandle(k); err != nil {
		return xerrors.Errorf("cannot update TPM platform handle on KeyData: %w", err)
	}
	return nil
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
func (k *SealedKeyData) RevokeOldPCRProtectionPolicies(tpm *Connection, authKey secboot.PrimaryKey) error {
	return k.revokeOldPCRProtectionPolicies(tpm.TPMContext, authKey, k.k.Role())
}

// UpdateKeyPCRProtectionPolicy updates the PCR protection policy for one or more TPM protected KeyData
// objects to the profile defined by the pcrProfile argument. The keys must all be related (ie, they were
// created using NewKeyDataMultiple). If any key in the supplied set is not related, an error will be returned.
//
// If validation of any KeyData object fails, an InvalidKeyDataError error will be returned.
//
// On success, each of the supplied KeyData objects will have an updated authorization policy that includes a
// PCR policy computed from the supplied PCRProtectionProfile. They must be persisted using
// secboot.KeyData.WriteAtomic.
func UpdateKeyDataPCRProtectionPolicy(tpm *Connection, authKey secboot.PrimaryKey, pcrProfile *PCRProtectionProfile, policyVersionOption PCRPolicyVersionOption, keys ...*secboot.KeyData) error {
	if len(keys) == 0 {
		return errors.New("no sealed keys supplied")
	}

	role := keys[0].Role()
	for i, key := range keys[1:] {
		if key.Role() != role {
			return fmt.Errorf("unexpected role for key at index %d (expected %s, got %s)", i+1, role, key.Role())
		}
	}

	for i, key := range keys {
		skd, err := NewSealedKeyData(key)
		if err != nil {
			return xerrors.Errorf("cannot obtain SealedKeyData for key at index %d: %w", i, err)
		}

		if err := skd.UpdatePCRProtectionPolicy(tpm, authKey, pcrProfile, policyVersionOption); err != nil {
			return xerrors.Errorf("cannot update key at index %d: %w", i, err)
		}
	}

	return nil
}
