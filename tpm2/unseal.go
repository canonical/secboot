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
	"fmt"

	"github.com/canonical/go-tpm2"

	"github.com/snapcore/secboot/internal/tcg"
)

const (
	tryPersistentSRK = iota
	tryTransientSRK
	tryMax
)

// loadForUnseal loads the sealed key object into the TPM and returns a context
// for it. It first tries by using the persistent shared SRK at the well known
// handle as the parent object. If this object doesn't exist or loading fails with
// an error indicating that the supplied sealed key object data is invalid, this
// function will try to create a transient SRK and then retry loading of the sealed
// key object by specifying the newly created transient object as the parent.
//
// If both attempts to load the sealed key object fail, or if the first attempt fails
// and a transient SRK cannot be created, an error will be returned.
//
// If a transient SRK is created, it is flushed from the TPM before this function
// returns.
func (k *sealedKeyDataBase) loadForUnseal(tpm *tpm2.TPMContext, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	var lastError error
	for try := tryPersistentSRK; try <= tryMax; try++ {
		var srk tpm2.ResourceContext
		if try == tryPersistentSRK {
			var err error
			srk, err = tpm.CreateResourceContextFromTPM(tcg.SRKHandle)
			if tpm2.IsResourceUnavailableError(err, tcg.SRKHandle) {
				// No SRK - save the error and try creating a transient
				lastError = ErrTPMProvisioning
				continue
			} else if err != nil {
				// This is an unexpected error
				return nil, fmt.Errorf("cannot create context for SRK: %w", err)
			}
		} else {
			var err error
			srk, _, _, _, _, err = tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, selectSrkTemplate(tpm, session), nil, nil, session)
			if isAuthFailError(err, tpm2.CommandCreatePrimary, 1) {
				// We don't know the authorization value for the storage hierarchy - ignore
				// this so we end up returning the last error.
				continue
			} else if err != nil {
				// This is an unexpected error
				return nil, fmt.Errorf("cannot create transient SRK: %w", err)
			}
			defer tpm.FlushContext(srk)
		}

		// Load the key data
		keyObject, err := k.load(tpm, srk, session)
		if isLoadInvalidParamError(err) || isImportInvalidParamError(err) {
			// The supplied key data is invalid or is not protected by the supplied SRK.
			lastError = InvalidKeyDataError{
				fmt.Sprintf("cannot load sealed key object into TPM: %v. Either the sealed key object is bad or the TPM owner has changed", err)}
			continue
		} else if isLoadInvalidParentError(err) || isImportInvalidParentError(err) {
			// The supplied SRK is not a valid storage parent.
			lastError = ErrTPMProvisioning
			continue
		} else if err != nil {
			// This is an unexpected error
			return nil, fmt.Errorf("cannot load sealed key object into TPM: %w", err)
		}

		return keyObject, nil
	}

	// No more attempts left - return the last error
	return nil, lastError
}

func (k *sealedKeyDataBase) unsealDataFromTPM(tpm *tpm2.TPMContext, authValue []byte, hmacSession tpm2.SessionContext) (data []byte, err error) {
	// Check if the TPM is in lockout mode
	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch properties from TPM: %w", err)
	}

	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrInLockout > 0 {
		return nil, ErrTPMLockout
	}

	keyObject, err := k.loadForUnseal(tpm, hmacSession)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(keyObject)

	keyObject.SetAuthValue(authValue)

	// Begin and execute policy session
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, k.data.Public().NameAlg)
	if err != nil {
		return nil, fmt.Errorf("cannot start policy session: %w", err)
	}
	defer tpm.FlushContext(policySession)

	if err := k.data.Policy().ExecutePCRPolicy(tpm, policySession, hmacSession); err != nil {
		err = fmt.Errorf("cannot complete authorization policy assertions: %w", err)
		switch {
		case isPolicyDataError(err):
			return nil, InvalidKeyDataError{err.Error()}
		case tpm2.IsResourceUnavailableError(err, lockNVHandle):
			return nil, InvalidKeyDataError{"required legacy lock NV index is not present"}
		}
		return nil, err
	}

	// Unseal
	data, err = tpm.Unseal(keyObject, policySession, hmacSession.IncludeAttrs(tpm2.AttrResponseEncrypt))
	switch {
	case tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandUnseal, 1):
		return nil, InvalidKeyDataError{"the authorization policy check failed during unsealing"}
	case err != nil:
		return nil, fmt.Errorf("cannot unseal key: %w", err)
	}

	return data, nil
}
