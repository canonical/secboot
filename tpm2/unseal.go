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

	"golang.org/x/xerrors"

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
//
// If session is supplied, it must be a HMAC session with the AttrContinueSession attribute
// set, used for authenticating the use of the storage hirearchy if a transient strorage
// primary key needs to be created, in order to avoid transmitting the cleartext authorzation
// value.
func (k *sealedKeyDataBase) loadForUnseal(tpm *tpm2.TPMContext, session tpm2.SessionContext) (keyObject tpm2.ResourceContext, policySession tpm2.SessionContext, err error) {
	for try := tryPersistentSRK; try <= tryMax; try++ {
		var srk tpm2.ResourceContext
		var thisErr error
		if try == tryPersistentSRK {
			srk, thisErr = tpm.NewResourceContext(tcg.SRKHandle)
			if tpm2.IsResourceUnavailableError(thisErr, tcg.SRKHandle) {
				// No SRK - save the error and try creating a transient
				err = ErrTPMProvisioning
				continue
			} else if thisErr != nil {
				// This is an unexpected error
				return nil, nil, xerrors.Errorf("cannot create context for SRK: %w", thisErr)
			}
		} else {
			srk, _, _, _, _, thisErr = tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, selectSrkTemplate(tpm, session), nil, nil, session)
			if isAuthFailError(thisErr, tpm2.CommandCreatePrimary, 1) {
				// We don't know the authorization value for the storage hierarchy - ignore
				// this so we end up returning the last error.
				continue
			} else if thisErr != nil {
				// This is an unexpected error
				return nil, nil, xerrors.Errorf("cannot create transient SRK: %w", err)
			}
			defer tpm.FlushContext(srk)
		}

		// Load the key data
		keyObject, err = k.load(tpm, srk)
		if isLoadInvalidParamError(err) || isImportInvalidParamError(err) {
			// The supplied key data is invalid or is not protected by the supplied SRK.
			err = InvalidKeyDataError{
				fmt.Sprintf("cannot load sealed key object into TPM: %v. Either the sealed key object is bad or the TPM owner has changed", err)}
			continue
		} else if isLoadInvalidParentError(err) || isImportInvalidParentError(err) {
			// The supplied SRK is not a valid storage parent.
			err = ErrTPMProvisioning
			continue
		} else if err != nil {
			// This is an unexpected error
			return nil, nil, xerrors.Errorf("cannot load sealed key object into TPM: %w", err)
		}

		defer func() {
			if err == nil {
				return
			}
			tpm.FlushContext(keyObject)
		}()

		// Begin policy session with parameter encryption support and salted with the SRK.
		// Note that this only provides protection against passive interposers, as active
		// interposers can modify session attributes supplied in the TPM2_Unseal command and
		// then redirect the command to an adversary supplied session for which they can calculate
		// the HMAC for. Whilst the host CPU can detect this tampering (because the response
		// HMAC will be invalid), this happens after the TPM has already provided the unsealed data.

		symmetric := &tpm2.SymDef{
			Algorithm: tpm2.SymAlgorithmAES,
			KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
			Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB},
		}
		policySession, err = tpm.StartAuthSession(srk, nil, tpm2.SessionTypePolicy, symmetric, k.data.Public().NameAlg)
		if err != nil {
			return nil, nil, xerrors.Errorf("cannot start policy session: %w", err)
		}
		return keyObject, policySession.WithAttrs(tpm2.AttrResponseEncrypt), nil
	}

	// No more attempts left - return the last error
	return nil, nil, err
}

// unsealDataFromTPM unseals the data from this sealed object.
//
// Unsealing uses a policy session that is salted with the SRK that is used to protect the key
// and uses the same session for response encryption. Note that this only provides protection
// against passive interposer attacks. There is no effort to protection against active
// interposer attacks (where an advesary can modify communications) for a few reasons:
//   - An adversary can remove the encrypt attribute from the session and redirect the command
//     to a session for which they can compute the HMAC. The host CPU will detect this because the
//     response HMAC will be invalid, but it's too late at this point. Using TPM2_EncryptDecrypt2
//     with both command and response parameter encryption could mitigate this attack.
//   - An adversary can modify and spoof PCR extends earlier in the boot chain, unless all
//     critical commands like these are integrity protected with a session that is salted with a
//     verified TPM key. This is not the case with any firmware today.
//   - Protecting against an active interposer would require the use of a verified key. There is
//     one - the endorsement key, but what happens if we don't have access to and can't download
//     intermediate certs for verification? Does the boot fail? How is this communicated securely
//     to the TPM?
//   - The use of go's crypto/x509 for certificate verification doesn't permit disabling validity
//     period valdidation. Hardware certificates will generally expire during the lifetime of a
//     device and ignoring validity periods is generally quite normal here (eg, such as in UEFI
//     secure boot).
//   - An adversary could go one step further and just unsolder the discrete TPM and place
//     it into a malcious platform that spoofs a specific host.
//
// If a session is supplied, it should be a HMAC session with the AttrContinueSession
// attribute set, used for authenticating use of the storage hierarchy if a transient
// storage primary key needs to be created, in order to avoid transmitting the cleartext
// authorization value.
func (k *sealedKeyDataBase) unsealDataFromTPM(tpm *tpm2.TPMContext, authValue []byte, hmacSession tpm2.SessionContext) (data []byte, err error) {
	keyObject, policySession, err := k.loadForUnseal(tpm, hmacSession)
	if err != nil {
		return nil, err
	}
	defer func() {
		tpm.FlushContext(keyObject)
		tpm.FlushContext(policySession)
	}()

	keyObject.SetAuthValue(authValue)

	// Execute policy session
	if err := k.data.Policy().ExecutePCRPolicy(tpm, policySession, hmacSession); err != nil {
		err = xerrors.Errorf("cannot complete authorization policy assertions: %w", err)
		switch {
		case isPCRPolicyDataError(err):
			return nil, &PCRPolicyDataError{err}
		case isPolicyDataError(err):
			return nil, InvalidKeyDataError{err.Error()}
		case tpm2.IsResourceUnavailableError(err, lockNVHandle):
			return nil, InvalidKeyDataError{"required legacy lock NV index is not present"}
		}
		return nil, err
	}

	// Unseal
	data, err = tpm.Unseal(keyObject, policySession)
	switch {
	case tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandUnseal):
		return nil, ErrTPMLockout
	case tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandUnseal, 1):
		return nil, InvalidKeyDataError{"the authorization policy check failed during unsealing"}
	case err != nil:
		return nil, xerrors.Errorf("cannot unseal key: %w", err)
	}

	return data, nil
}
