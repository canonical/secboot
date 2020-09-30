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
	"errors"
	"fmt"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot/internal/tcg"

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

// ProvisionMode is used to control the behaviour of TPMConnection.EnsureProvisioned.
type ProvisionMode int

const (
	// ProvisionModeWithoutLockout specifies that the TPM should be refreshed without performing operations that require the use of the
	// lockout hierarchy. Operations that won't be performed in this mode are disabling owner clear, configuring the dictionary attack
	// parameters, and setting the authorization value for the lockout hierarchy.
	ProvisionModeWithoutLockout ProvisionMode = iota

	// ProvisionModeFull specifies that the TPM should be fully provisioned without clearing it. This requires use of the lockout
	// hierarchy.
	ProvisionModeFull

	// ProvisionModeClear specifies that the TPM should be fully provisioned after clearing it. This requires use of the lockout
	// hierarchy.
	ProvisionModeClear
)

func provisionPrimaryKey(tpm *tpm2.TPMContext, hierarchy tpm2.ResourceContext, template *tpm2.Public, handle tpm2.Handle, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	obj, err := tpm.CreateResourceContextFromTPM(handle)
	switch {
	case err != nil && !tpm2.IsResourceUnavailableError(err, handle):
		// Unexpected error
		return nil, xerrors.Errorf("cannot create context to determine if persistent handle is already occupied: %w", err)
	case tpm2.IsResourceUnavailableError(err, handle):
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

// EnsureProvisioned prepares the TPM for full disk encryption. The mode parameter specifies the behaviour of this function.
//
// If mode is ProvisionModeClear, this function will attempt to clear the TPM before provisioning it. If owner clear has been
// disabled (which will be the case if the TPM has previously been provisioned with this function), then ErrTPMClearRequiresPPI
// will be returned. In this case, the TPM must be cleared via the physical presence interface by calling RequestTPMClearUsingPPI
// and performing a system restart. Note that clearing the TPM makes all previously sealed keys permanently unrecoverable. This
// mode should normally be used when resetting a device to factory settings (ie, performing a new installation).
//
// If mode is ProvisionModeClear or ProvisionModeFull, then the authorization value for the lockout hierarchy will be set to
// newLockoutAuth, owner clear will be disabled, and the parameters of the TPM's dictionary attack logic will be configured to
// appropriate values.
//
// If mode is ProvisionModeClear or ProvisionModeFull, this function performs operations that require the use of the lockout
// hierarchy (detailed above), and knowledge of the lockout hierarchy's authorization value. This must be provided by calling
// TPMConnection.LockoutHandleContext().SetAuthValue() prior to this call. If the wrong lockout hierarchy authorization value is
// provided, then a AuthFailError error will be returned. If this happens, the TPM will have entered dictionary attack lockout mode
// for the lockout hierarchy. Further calls will result in a ErrTPMLockout error being returned. The only way to recover from this is
// to either wait for the pre-programmed recovery time to expire, or to clear the TPM via the physical presence interface by calling
// RequestTPMClearUsingPPI. If the lockout hierarchy authorization value is not known then mode should be set to
// ProvisionModeWithoutLockout, with the caveat that this mode cannot fully provision the TPM.
//
// If mode is ProvisionModeFull or ProvisionModeWithoutLockout, this function will not affect the ability to recover sealed keys that
// can currently be recovered.
//
// In all modes, this function performs operations that require the use of the storage and endorsement hierarchies (creation of
// primary keys and NV indices, detailed below). If mode is ProvisionModeFull or ProvisionModeWithoutLockout, then knowledge of the
// authorization values for those hierarchies is required. Whilst these will be empty after clearing the TPM, if they have been set
// since clearing the TPM then they will need to be provided by calling TPMConnection.EndorsementHandleContext().SetAuthValue() and
// TPMConnection.OwnerHandleContext().SetAuthValue() prior to calling this function. If the wrong value is provided for either
// authorization, then a AuthFailError error will be returned. If the correct authorization values are not known, then the only way
// to recover from this is to clear the TPM either by calling this function with mode set to ProvisionModeClear (and providing the
// correct authorization value for the lockout hierarchy), or by using the physical presence interface.
//
// In all modes, this function will create and persist both a storage root key and an endorsement key. Both of these will be created
// using the RSA templates defined in and persisted at the handles specified in the "TCG EK Credential Profile for TPM Family 2.0"
// and "TCG TPM v2.0 Provisioning Guidance" specifications. If there are any objects already stored at the locations required for
// either primary key, then this function will evict them automatically from the TPM.
//
// In all modes, this function will also create a pair of NV indices used for locking access to sealed key objects, if necessary.
// These indices will be created at handles 0x01801100 and 0x01801101. If there are already NV indices defined at either of the
// required handles but they don't meet the requirements of this function, then this function will undefine them automatically in
// order to define new indices. Note that these indices will be created in their locked state (as if LockAccessToSealedKeys has been
// called), and so secrets protected with SealKeyToTPM cannot be recovered until the next TPM reset or restart.
//
// If mode is ProvisionModeWithoutLockout but the TPM indicates that use of the lockout hierarchy is required to fully provision the
// TPM (eg, to disable owner clear, set the lockout hierarchy authorization value or configure the DA lockout parameters), then a
// ErrTPMProvisioningRequiresLockout error will be returned. In this scenario, the function will complete all operations that can be
// completed without using the lockout hierarchy, but the function should be called again either with mode set to ProvisionModeFull
// (if the authorization value for the lockout hierarchy is known), or ProvisionModeClear.
func (t *TPMConnection) EnsureProvisioned(mode ProvisionMode, newLockoutAuth []byte) error {
	session := t.HmacSession()

	props, err := t.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return xerrors.Errorf("cannot fetch permanent properties: %w", err)
	}
	if props[0].Property != tpm2.PropertyPermanent {
		return errors.New("TPM returned value for the wrong property")
	}
	if mode == ProvisionModeClear {
		if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrDisableClear > 0 {
			return ErrTPMClearRequiresPPI
		}

		if err := t.Clear(t.LockoutHandleContext(), session); err != nil {
			switch {
			case isAuthFailError(err, tpm2.CommandClear, 1):
				return AuthFailError{tpm2.HandleLockout}
			case tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandClear):
				return ErrTPMLockout
			}
			return xerrors.Errorf("cannot clear the TPM: %w", err)
		}
	}

	// Provision an endorsement key
	if _, err := provisionPrimaryKey(t.TPMContext, t.EndorsementHandleContext(), tcg.EKTemplate, tcg.EKHandle, session); err != nil {
		switch {
		case isAuthFailError(err, tpm2.CommandEvictControl, 1):
			return AuthFailError{tpm2.HandleOwner}
		case isAuthFailError(err, tpm2.AnyCommandCode, 1):
			return AuthFailError{tpm2.HandleEndorsement}
		default:
			return xerrors.Errorf("cannot provision endorsement key: %w", err)
		}
	}

	// Reinitialize the connection, which creates a new session that's salted with a value protected with the newly provisioned EK.
	// This will have a symmetric algorithm for parameter encryption during HierarchyChangeAuth.
	if err := t.init(); err != nil {
		var verifyErr verificationError
		if xerrors.As(err, &verifyErr) {
			return TPMVerificationError{fmt.Sprintf("cannot reinitialize TPM connection after provisioning endorsement key: %v", err)}
		}
		return xerrors.Errorf("cannot reinitialize TPM connection after provisioning endorsement key: %w", err)
	}
	session = t.HmacSession()

	// Provision a storage root key
	srk, err := provisionPrimaryKey(t.TPMContext, t.OwnerHandleContext(), tcg.SRKTemplate, tcg.SRKHandle, session)
	if err != nil {
		switch {
		case isAuthFailError(err, tpm2.AnyCommandCode, 1):
			return AuthFailError{tpm2.HandleOwner}
		default:
			return xerrors.Errorf("cannot provision storage root key: %w", err)
		}
	}
	t.provisionedSrk = srk

	// Provision new lock NV indices if required
	if err := ensureLockNVIndices(t.TPMContext, session); err != nil {
		return xerrors.Errorf("cannot create lock NV indices: %w", err)
	}

	if mode == ProvisionModeWithoutLockout {
		props, err := t.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1, session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			return xerrors.Errorf("cannot fetch permanent properties to determine if lockout hierarchy is required: %w", err)
		}
		if props[0].Property != tpm2.PropertyPermanent {
			return errors.New("TPM returned value for the wrong property")
		}
		required := tpm2.AttrLockoutAuthSet | tpm2.AttrDisableClear
		if tpm2.PermanentAttributes(props[0].Value)&required != required {
			return ErrTPMProvisioningRequiresLockout
		}

		props, err = t.GetCapabilityTPMProperties(tpm2.PropertyMaxAuthFail, 3, session.IncludeAttrs(tpm2.AttrAudit))
		if err != nil {
			return xerrors.Errorf("cannot fetch DA parameters to determine if lockout hierarchy is required: %w", err)
		}
		if props[0].Property != tpm2.PropertyMaxAuthFail || props[1].Property != tpm2.PropertyLockoutInterval || props[2].Property != tpm2.PropertyLockoutRecovery {
			return errors.New("TPM returned values for the wrong properties")
		}
		if props[0].Value > maxTries || props[1].Value < recoveryTime || props[2].Value < lockoutRecovery {
			return ErrTPMProvisioningRequiresLockout
		}

		return nil
	}

	// Perform actions that require the lockout hierarchy authorization.

	// Set the DA parameters.
	if err := t.DictionaryAttackParameters(t.LockoutHandleContext(), maxTries, recoveryTime, lockoutRecovery, session); err != nil {
		switch {
		case isAuthFailError(err, tpm2.CommandDictionaryAttackParameters, 1):
			return AuthFailError{tpm2.HandleLockout}
		case tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandDictionaryAttackParameters):
			return ErrTPMLockout
		}
		return xerrors.Errorf("cannot configure dictionary attack parameters: %w", err)
	}

	// Disable owner clear
	if err := t.ClearControl(t.LockoutHandleContext(), true, session); err != nil {
		// Lockout auth failure or lockout mode would have been caught by DictionaryAttackParameters
		return xerrors.Errorf("cannot disable owner clear: %w", err)
	}

	// Set the lockout hierarchy authorization.
	if err := t.HierarchyChangeAuth(t.LockoutHandleContext(), newLockoutAuth, session.IncludeAttrs(tpm2.AttrCommandEncrypt)); err != nil {
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
