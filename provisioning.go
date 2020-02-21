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
	"bytes"
	"fmt"
	"os"

	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

const (
	ppiPath string = "/sys/class/tpm/tpm0/ppi/request" // Path for submitting PPI operation requests to firmware for the default TPM

	// clearPPIRequest is the operation value for asking the firmware to clear the TPM, see section 9 of "TCG PC Client Platform Physical
	// Presence Interface Specification", version 1.30, revision 00.52, 28 July 2015.
	clearPPIRequest string = "5"

	// DA lockout parameters.
	maxTries        uint32 = 32
	recoveryTime    uint32 = 7200
	lockoutRecovery uint32 = 86400
)

// ProvisionStatusAttributes correspond to the state of the TPM with regards to provisioning for full disk encryption.
type ProvisionStatusAttributes int

const (
	// AttrValidSRK indicates that the TPM contains a valid primary storage key with the expected properties at the
	// expected location. Note that this does not mean that the object was created with the same template that ProvisionTPM
	// uses, and is no guarantee that a call to ProvisionTPM wouldn't result in a different key being created.
	AttrValidSRK ProvisionStatusAttributes = 1 << iota

	// AttrValidEK indicates that the TPM contains a valid endorsement key at the expected location. On a TPMConnection created
	// with SecureConnectToDefaultTPM, it means that the TPM contains the key associated with the verified endorsement certificate.
	// On a TPMConnection created with ConnectToDefaultTPM, it means that the TPM contains a valid primary key with the expected
	// properties at the expected location, but does not mean that the object was created with the the same template that
	// ProvisionTPM uses, and is no guarantee that a call to ProvisionTPM wouldn't result in a different key being created.
	AttrValidEK

	AttrDAParamsOK         // The dictionary attack lockout parameters are configured correctly.
	AttrOwnerClearDisabled // The ability to clear the TPM with owner authorization is disabled.

	// AttrLockoutAuthSet indicates that the lockout hierarchy has an authorization value defined. This
	// doesn't necessarily mean that the authorization value is the same one that was originally provided
	// to ProvisionTPM - it could have been changed outside of our control.
	AttrLockoutAuthSet

	AttrValidLockNVIndex // The TPM has a valid NV index used for locking access to keys sealed with SealKeyToTPM
)

// ProvisionMode is used to control the behaviour of ProvisionTPM.
type ProvisionMode int

const (
	// ProvisionModeClear specifies that the TPM should be fully provisioned after clearing it.
	ProvisionModeClear ProvisionMode = iota

	// ProvisionModeWithoutLockout specifies that the TPM should be refreshed without performing operations that require knowledge of
	// the lockout hierarchy authorization value. Operations that won't be performed in this mode are disabling owner clear, configuring
	// the dictionary attack parameters and setting the authorization value for the lockout hierarchy.
	ProvisionModeWithoutLockout

	// ProvisionModeFull specifies that the TPM should be fully provisioned without clearing it.
	ProvisionModeFull
)

var (
	// srkTemplate is the default RSA2048 SRK template, see section 7.5.1 of "TCG TPM v2.0 Provisioning Guidance", version 1.0,
	// revision 1.0, 15 March 2017.
	srkTemplate = tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA |
			tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: tpm2.PublicParamsU{
			Data: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.SymKeyBitsU{Data: uint16(128)},
					Mode:      tpm2.SymModeU{Data: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}},
		Unique: tpm2.PublicIDU{Data: make(tpm2.PublicKeyRSA, 256)}}
)

func provisionPrimaryKey(tpm *tpm2.TPMContext, hierarchy tpm2.ResourceContext, template *tpm2.Public, handle tpm2.Handle, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	obj, err := tpm.CreateResourceContextFromTPM(handle)
	switch {
	case err != nil && !isResourceUnavailableError(err):
		// Unexpected error
		return nil, xerrors.Errorf("cannot create context to determine if persistent handle is already occupied: %w", err)
	case isResourceUnavailableError(err):
		// No existing object to evict
	default:
		// Evict the current object
		if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), obj, handle, session); err != nil {
			return nil, xerrors.Errorf("cannot evict existing object at persistent handle: %w", err)
		}
	}

	transientObj, _, _, _, _, err := tpm.CreatePrimary(hierarchy, nil, template, nil, nil, session)
	if err != nil {
		return nil, xerrors.Errorf("cannot create key: %w", err)
	}
	defer tpm.FlushContext(transientObj)

	obj, err = tpm.EvictControl(tpm.OwnerHandleContext(), transientObj, handle, session)
	if err != nil {
		return nil, xerrors.Errorf("cannot make key persistent: %w", err)
	}

	return obj, nil
}

// ProvisionTPM prepares the TPM associated with the tpm parameter for full disk encryption. The mode parameter specifies the
// behaviour of this function.
//
// If mode is ProvisionModeClear, this function will attempt to clear the TPM before provisioning it. If owner clear has been
// disabled (which will be the case if the TPM has previously been provisioned with this function), then ErrTPMClearRequiresPPI
// will be returned. In this case, the TPM must be cleared via the physical presence interface by calling RequestTPMClearUsingPPI
// and performing a system restart.
//
// If mode is ProvisionModeClear or ProvisionModeFull then the authorization value for the lockout hierarchy will be set to
// newLockoutAuth, owner clear will be disabled, and the parameters of the TPM's dictionary attack logic will be configured. These
// operations require knowledge of the lockout hierarchy authorization value, which must be provided by calling
// TPMConnection.LockoutHandleContext().SetAuthValue() prior to this call. If the wrong lockout hierarchy authorization value is
// provided, then a AuthFailError error will be returned. If this happens, the TPM will have entered dictionary attack lockout mode
// for the lockout hierarchy. Further calls will result in a ErrTPMLockout error being returned. The only way to recover from this is
// to either wait for the pre-programmed recovery time to expire, or to clear the TPM via the physical presence interface by calling
// RequestTPMClearUsingPPI. If the lockout hierarchy authorization value is not known or the caller wants to skip the operations that
// require use of the lockout hierarchy, then mode can be set to ProvisionModeWithoutLockout.
//
// If mode is ProvisionModeFull or ProvisionModeWithoutLockout, this function performs operations that require knowledge of the
// storage and endorsement hierarchies (creation of primary keys and NV indices, detailed below). Whilst these will be empty after
// clearing the TPM, if they have been set since clearing the TPM then they will need to be provided by calling
// TPMConnection.EndorsementHandleContext().SetAuthValue() and TPMConnection.OwnerHandleContext().SetAuthValue() prior to calling
// this function. If the wrong value is provided for either authorization, then a AuthFailError error will be returned. If the correct
// authorization values are not known, then the only way to recover from this is to clear the TPM either by calling this function with
// mode set to ProvisionModeClear, or by using the physical presence interface.
//
// In all modes, this function will create and persist both a storage root key and an endorsement key. Both of these will be created
// using the RSA templates defined in and persisted at the handles specified in the "TCG EK Credential Profile for TPM Family 2.0"
// and "TCG TPM v2.0 Provisioning Guidance" specifications. If there are any objects already stored at the locations required for
// either primary key, then this function will evict them automatically from the TPM.
//
// In all modes, this function will also create a pair of NV indices used for locking access to sealed key objects, if necessary.
// These indices will be created at handles 0x01801100 and 0x01801101. If there are already NV indices defined at either of the
// required handles but they don't meet the requirements of this function, a TPMResourceExistsError error will be returned. In this
// case, the caller will either need to manually undefine these using TPMConnection.NVUndefineSpace, or clear the TPM.
func ProvisionTPM(tpm *TPMConnection, mode ProvisionMode, newLockoutAuth []byte) error {
	status, err := ProvisionStatus(tpm)
	if err != nil {
		return xerrors.Errorf("cannot determine the current TPM status: %w", err)
	}

	// Create an initial session for HMAC authorizations
	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, defaultSessionHashAlgorithm, nil)
	if err != nil {
		return xerrors.Errorf("cannot start session: %w", err)
	}
	defer tpm.FlushContext(session)

	session.SetAttrs(tpm2.AttrContinueSession)

	if mode == ProvisionModeClear {
		if status&AttrOwnerClearDisabled > 0 {
			return ErrTPMClearRequiresPPI
		}

		if err := tpm.Clear(tpm.LockoutHandleContext(), session); err != nil {
			switch {
			case isAuthFailError(err):
				return AuthFailError{tpm2.HandleLockout}
			case isLockoutError(err):
				return ErrTPMLockout
			}
			return xerrors.Errorf("cannot clear the TPM: %w", err)
		}

		status = 0
	}

	// Provision an endorsement key
	if _, err := provisionPrimaryKey(tpm.TPMContext, tpm.EndorsementHandleContext(), ekTemplate, ekHandle, session); err != nil {
		var tpmErr *tpm2.TPMError
		switch {
		case xerrors.As(err, &tpmErr) && tpmErr.Command == tpm2.CommandEvictControl:
			return AuthFailError{tpm2.HandleOwner}
		case isAuthFailError(err):
			return AuthFailError{tpm2.HandleEndorsement}
		default:
			return xerrors.Errorf("cannot provision endorsement key: %w", err)
		}
	}

	// Close the existing session and create a new session that's salted with a value protected with the newly provisioned EK.
	// This will have a symmetric algorithm for parameter encryption during HierarchyChangeAuth.
	tpm.FlushContext(session)
	if err := tpm.init(); err != nil {
		var verifyErr verificationError
		if xerrors.As(err, &verifyErr) {
			return TPMVerificationError{fmt.Sprintf("cannot reinitialize TPM connection after provisioning endorsement key: %v", err)}
		}
		return xerrors.Errorf("cannot reinitialize TPM connection after provisioning endorsement key: %w", err)
	}
	session = tpm.HmacSession()

	// Provision a storage root key
	srk, err := provisionPrimaryKey(tpm.TPMContext, tpm.OwnerHandleContext(), &srkTemplate, srkHandle, session)
	if err != nil {
		switch {
		case isAuthFailError(err):
			return AuthFailError{tpm2.HandleOwner}
		default:
			return xerrors.Errorf("cannot provision storage root key: %w", err)
		}
	}
	tpm.provisionedSrk = srk

	// Provision a lock NV index
	if err := ensureLockNVIndex(tpm.TPMContext, session); err != nil {
		if isNVIndexDefinedWithHandleError(err) {
			return TPMResourceExistsError{err.(*nvIndexDefinedError).handle}
		}
		return xerrors.Errorf("cannot create lock NV index: %w", err)
	}

	if mode == ProvisionModeWithoutLockout {
		return nil
	}

	// Perform actions that require the lockout hierarchy authorization.

	// Set the DA parameters.
	if err := tpm.DictionaryAttackParameters(tpm.LockoutHandleContext(), maxTries, recoveryTime, lockoutRecovery, session); err != nil {
		switch {
		case isAuthFailError(err):
			return AuthFailError{tpm2.HandleLockout}
		case isLockoutError(err):
			return ErrTPMLockout
		}
		return xerrors.Errorf("cannot configure dictionary attack parameters: %w", err)
	}

	// Disable owner clear
	if err := tpm.ClearControl(tpm.LockoutHandleContext(), true, session); err != nil {
		// Lockout auth failure or lockout mode would have been caught by DictionaryAttackParameters
		return xerrors.Errorf("cannot disable owner clear: %w", err)
	}

	// Set the lockout hierarchy authorization.
	if err := tpm.HierarchyChangeAuth(tpm.LockoutHandleContext(), tpm2.Auth(newLockoutAuth),
		session.IncludeAttrs(tpm2.AttrCommandEncrypt)); err != nil {
		return xerrors.Errorf("cannot set the lockout hierarchy authorization value: %w", err)
	}

	return nil
}

// RequestTPMClearUsingPPI submits a request to the firmware to clear the TPM on the next reboot. This is the only way to clear
// the TPM if owner clear has been disabled for the TPM, or the lockout hierarchy authorization value has been set previously but
// is unknown.
func RequestTPMClearUsingPPI() error {
	f, err := os.OpenFile(ppiPath, os.O_WRONLY, 0)
	if err != nil {
		return xerrors.Errorf("cannot open request handle: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(clearPPIRequest); err != nil {
		return xerrors.Errorf("cannot submit request: %w", err)
	}

	return nil
}

// ProvisionStatus returns the provisioning status for the specified TPM.
func ProvisionStatus(tpm *TPMConnection) (ProvisionStatusAttributes, error) {
	var out ProvisionStatusAttributes

	session := tpm.HmacSession().IncludeAttrs(tpm2.AttrAudit)

	ek, err := tpm.CreateResourceContextFromTPM(ekHandle, session)
	switch {
	case err != nil && !isResourceUnavailableError(err):
		// Unexpected error
		return 0, err
	case isResourceUnavailableError(err):
		// Nothing to do
	default:
		if ekInit, err := tpm.EndorsementKey(); err == nil && bytes.Equal(ekInit.Name(), ek.Name()) {
			out |= AttrValidEK
		}
	}

	srk, err := tpm.CreateResourceContextFromTPM(srkHandle, session)
	switch {
	case err != nil && !isResourceUnavailableError(err):
		// Unexpected error
		return 0, err
	case isResourceUnavailableError(err):
		// Nothing to do
	case tpm.provisionedSrk != nil:
		// ProvisionTPM has been called with this TPMConnection. Make sure it's the same object
		if bytes.Equal(tpm.provisionedSrk.Name(), srk.Name()) {
			out |= AttrValidSRK
		}
	default:
		// ProvisionTPM hasn't been called with this TPMConnection, but there is an object at srkHandle. Make sure it looks like a storage
		// primary key.
		ok, err := isObjectPrimaryKeyWithTemplate(tpm.TPMContext, tpm.OwnerHandleContext(), srk, &srkTemplate, tpm.HmacSession())
		switch {
		case err != nil:
			return 0, xerrors.Errorf("cannot determine if object at %v is a primary key in the storage hierarchy: %w", srkHandle, err)
		case ok:
			out |= AttrValidSRK
		}
	}

	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyMaxAuthFail, 3)
	if err != nil {
		return 0, xerrors.Errorf("cannot fetch DA parameters: %w", err)
	}
	if props[0].Value <= maxTries && props[1].Value >= recoveryTime && props[2].Value >= lockoutRecovery {
		out |= AttrDAParamsOK
	}

	props, err = tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return 0, xerrors.Errorf("cannot fetch permanent properties: %w", err)
	}
	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrDisableClear > 0 {
		out |= AttrOwnerClearDisabled
	}
	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrLockoutAuthSet > 0 {
		out |= AttrLockoutAuthSet
	}

	lockIndex, err := tpm.CreateResourceContextFromTPM(lockNVHandle, session)
	switch {
	case err != nil && !isResourceUnavailableError(err):
		// Unexpected error
		return 0, err
	case isResourceUnavailableError(err):
		// Nothing to do
	default:
		if _, err := readAndValidateLockNVIndexPublic(tpm.TPMContext, lockIndex, session); err == nil {
			out |= AttrValidLockNVIndex
		}
	}

	return out, nil
}
