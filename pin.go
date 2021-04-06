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
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot/internal/tcg"

	"golang.org/x/xerrors"
)

// computeV0PinNVIndexPostInitAuthPolicies computes the authorization policy digests associated with the post-initialization
// actions on a NV index created with the removed createPinNVIndex for version 0 key files. These are:
// - A policy for updating the index to revoke old dynamic authorization policies, requiring an assertion signed by the key
//   associated with updateKeyName.
// - A policy for updating the authorization value (PIN / passphrase), requiring knowledge of the current authorization value.
// - A policy for reading the counter value without knowing the authorization value, as the value isn't secret.
// - A policy for using the counter value in a TPM2_PolicyNV assertion without knowing the authorization value.
func computeV0PinNVIndexPostInitAuthPolicies(alg tpm2.HashAlgorithmId, updateKeyName tpm2.Name) (tpm2.DigestList, error) {
	var out tpm2.DigestList
	// Compute a policy for incrementing the index to revoke dynamic authorization policies, requiring an assertion signed by the
	// key associated with updateKeyName.
	trial, err := tpm2.ComputeAuthPolicy(alg)
	if err != nil {
		return nil, err
	}
	trial.PolicyCommandCode(tpm2.CommandNVIncrement)
	trial.PolicyNvWritten(true)
	trial.PolicySigned(updateKeyName, nil)
	out = append(out, trial.GetDigest())

	// Compute a policy for updating the authorization value of the index, requiring knowledge of the current authorization value.
	trial, err = tpm2.ComputeAuthPolicy(alg)
	if err != nil {
		return nil, err
	}
	trial.PolicyCommandCode(tpm2.CommandNVChangeAuth)
	trial.PolicyAuthValue()
	out = append(out, trial.GetDigest())

	// Compute a policy for reading the counter value without knowing the authorization value.
	trial, err = tpm2.ComputeAuthPolicy(alg)
	if err != nil {
		return nil, err
	}
	trial.PolicyCommandCode(tpm2.CommandNVRead)
	out = append(out, trial.GetDigest())

	// Compute a policy for using the counter value in a TPM2_PolicyNV assertion without knowing the authorization value.
	trial, err = tpm2.ComputeAuthPolicy(alg)
	if err != nil {
		return nil, err
	}
	trial.PolicyCommandCode(tpm2.CommandPolicyNV)
	out = append(out, trial.GetDigest())

	return out, nil
}

// performPinChangeV0 changes the authorization value of the dynamic authorization policy counter associated with the public
// argument, for PIN integration in version 0 key files. This requires the authorization policy digests initially returned from
// (the now removed) createPinNVIndex function in order to execute the policy session required to change the authorization value.
// The current authorization value must be provided via the oldAuth argument.
//
// On success, the authorization value of the counter will be changed to newAuth.
func performPinChangeV0(tpm *tpm2.TPMContext, public *tpm2.NVPublic, authPolicies tpm2.DigestList, oldAuth, newAuth string, hmacSession tpm2.SessionContext) error {
	index, err := tpm2.CreateNVIndexResourceContextFromPublic(public)
	if err != nil {
		return xerrors.Errorf("cannot create resource context for NV index: %w", err)
	}
	index.SetAuthValue([]byte(oldAuth))

	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, public.NameAlg)
	if err != nil {
		return xerrors.Errorf("cannot start policy session: %w", err)
	}
	defer tpm.FlushContext(policySession)

	if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVChangeAuth); err != nil {
		return xerrors.Errorf("cannot execute assertion: %w", err)
	}
	if err := tpm.PolicyAuthValue(policySession); err != nil {
		return xerrors.Errorf("cannot execute assertion: %w", err)
	}
	if err := tpm.PolicyOR(policySession, authPolicies); err != nil {
		return xerrors.Errorf("cannot execute assertion: %w", err)
	}

	if err := tpm.NVChangeAuth(index, tpm2.Auth(newAuth), policySession, hmacSession.IncludeAttrs(tpm2.AttrCommandEncrypt)); err != nil {
		return xerrors.Errorf("cannot change authorization value for NV index: %w", err)
	}

	return nil
}

// performPinChange changes the authorization value of the sealed key object associated with keyPrivate and keyPublic, for PIN
// integration in current key files. The sealed key file must be created without the AttrAdminWithPolicy attribute. The current
// authorization value must be provided via the oldAuth argument.
//
// On success, a new private area will be returned for the sealed key object, containing the new PIN.
func performPinChange(tpm *tpm2.TPMContext, keyPrivate tpm2.Private, keyPublic *tpm2.Public, oldPIN, newPIN string, session tpm2.SessionContext) (tpm2.Private, error) {
	srk, err := tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for SRK: %w", err)
	}

	key, err := tpm.Load(srk, keyPrivate, keyPublic, session)
	if err != nil {
		return nil, xerrors.Errorf("cannot load sealed key object in to TPM: %w", err)
	}
	defer tpm.FlushContext(key)

	key.SetAuthValue([]byte(oldPIN))

	newKeyPrivate, err := tpm.ObjectChangeAuth(key, srk, []byte(newPIN), session.IncludeAttrs(tpm2.AttrCommandEncrypt))
	if err != nil {
		return nil, xerrors.Errorf("cannot change sealed key object authorization value: %w", err)
	}

	return newKeyPrivate, nil
}

// ChangePIN changes the PIN for the key data file at the specified path. The existing PIN must be supplied via the oldPIN argument.
// Setting newPIN to an empty string will clear the PIN and set a hint on the key data file that no PIN is set.
//
// If the TPM's dictionary attack logic has been triggered, a ErrTPMLockout error will be returned.
//
// If the file at the specified path cannot be opened, then a wrapped *os.PathError error will be returned.
//
// If the supplied key data file fails validation checks, an InvalidKeyFileError error will be returned.
//
// If oldPIN is incorrect, then a ErrPINFail error will be returned and the TPM's dictionary attack counter will be incremented.
func ChangePIN(tpm *TPMConnection, path string, oldPIN, newPIN string) error {
	// Check if the TPM is in lockout mode
	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return xerrors.Errorf("cannot fetch properties from TPM: %w", err)
	}

	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrInLockout > 0 {
		return ErrTPMLockout
	}

	// Open the key data file
	keyFile, err := os.Open(path)
	if err != nil {
		return xerrors.Errorf("cannot open key data file: %w", err)
	}
	defer keyFile.Close()

	// Read and validate the key data file
	data, _, pcrPolicyCounterPub, err := decodeAndValidateKeyData(tpm.TPMContext, keyFile, nil, tpm.HmacSession())
	if err != nil {
		if isKeyFileError(err) {
			return InvalidKeyFileError{err.Error()}
		}
		return xerrors.Errorf("cannot read and validate key data file: %w", err)
	}

	// Change the PIN
	if data.version == 0 {
		if err := performPinChangeV0(tpm.TPMContext, pcrPolicyCounterPub, data.staticPolicyData.v0PinIndexAuthPolicies, oldPIN, newPIN, tpm.HmacSession()); err != nil {
			if isAuthFailError(err, tpm2.CommandNVChangeAuth, 1) {
				return ErrPINFail
			}
			return err
		}
	} else {
		newKeyPrivate, err := performPinChange(tpm.TPMContext, data.keyPrivate, data.keyPublic, oldPIN, newPIN, tpm.HmacSession())
		if err != nil {
			if isAuthFailError(err, tpm2.CommandObjectChangeAuth, 1) {
				return ErrPINFail
			}
			return err
		}
		data.keyPrivate = newKeyPrivate
	}

	// Update the metadata and write a new key data file
	origAuthModeHint := data.authModeHint
	if newPIN == "" {
		data.authModeHint = authModeNone
	} else {
		data.authModeHint = authModePIN
	}

	if origAuthModeHint == data.authModeHint && data.version == 0 {
		return nil
	}

	if err := data.writeToFileAtomic(path); err != nil {
		return xerrors.Errorf("cannot write key data file: %v", err)
	}

	return nil
}
