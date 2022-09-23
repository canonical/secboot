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
	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"
)

const (
	tryPersistentSRK = iota
	tryTransientSRK
)

// loadForUnseal loads the sealed key object into the TPM and returns a context
// for it. It first tries by going through all the peristent handles. If none can be
// used, this function will try to create a transient SRK and then retry loading of
// the sealed key object by specifying the newly created transient object as parent.
//
// If all attempts to load the sealed key object fail and a transient SRK cannot be
// created, an error will be returned.
//
// If a transient SRK is created, it is flushed from the TPM before this function
// returns.
func (k *SealedKeyObject) loadForUnseal(tpm *tpm2.TPMContext, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	var lastError error

	handles, err := tpm.GetCapabilityHandles(tpm2.HandleTypePersistent.BaseHandle(), tpm2.CapabilityMaxProperties)
	if err != nil {
		return nil, err
	}

	tries := map[int]int{
		tryPersistentSRK: len(handles),
		tryTransientSRK:  len(handles) + 1,
	}

	for try := 0; try < tries[tryTransientSRK]; try++ {
		var srk tpm2.ResourceContext
		var err error
		if try < tries[tryPersistentSRK] {
			srk, err = tpm.CreateResourceContextFromTPM(handles[try])
		} else {
			srk, _, _, _, _, err = tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, selectSrkTemplate(tpm, session), nil, nil, session)
			defer tpm.FlushContext(srk)
		}
		if err != nil {
			lastError = ErrTPMProvisioning
			continue
		}

		// Load the key data
		keyObject, err := k.load(tpm, srk, session)
		if err != nil {
			lastError = ErrTPMProvisioning
			continue
		}

		return keyObject, nil
	}

	return nil, lastError
}

func (k *SealedKeyObject) unsealDataFromTPM(tpm *tpm2.TPMContext, hmacSession tpm2.SessionContext) (data []byte, err error) {
	// Check if the TPM is in lockout mode
	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return nil, xerrors.Errorf("cannot fetch properties from TPM: %w", err)
	}

	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrInLockout > 0 {
		return nil, ErrTPMLockout
	}

	keyObject, err := k.loadForUnseal(tpm, hmacSession)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(keyObject)

	// Begin and execute policy session
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, k.data.Public().NameAlg)
	if err != nil {
		return nil, xerrors.Errorf("cannot start policy session: %w", err)
	}
	defer tpm.FlushContext(policySession)

	if err := k.data.Policy().ExecutePCRPolicy(tpm, policySession, hmacSession); err != nil {
		err = xerrors.Errorf("cannot complete authorization policy assertions: %w", err)
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
		return nil, xerrors.Errorf("cannot unseal key: %w", err)
	}

	return data, nil
}
