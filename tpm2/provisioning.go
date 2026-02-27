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
	"errors"
	"fmt"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot/internal/tcg"
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

	// srkTemplateHandle is the NV index at which we can find a custom template for
	// the storage primary key, if one is supplied during provisioning. The handle
	// here is in the range reserved for owner indices, so there shouldn't be
	// anything here on a new installation.
	srkTemplateHandle tpm2.Handle = 0x01810001
)

// provisionMode is used to control the behaviour of Connection.EnsureProvisioned.
type provisionMode int

const (
	// provisionModeWithoutLockout specifies that the TPM should be refreshed without performing operations that require the use of the
	// lockout hierarchy. Operations that won't be performed in this mode are disabling owner clear, configuring the dictionary attack
	// parameters, and setting the authorization value for the lockout hierarchy.
	provisionModeWithoutLockout provisionMode = iota

	// provisionModeFull specifies that the TPM should be fully provisioned without clearing it. This requires use of the lockout
	// hierarchy.
	provisionModeFull

	// provisionModeClear specifies that the TPM should be fully provisioned after clearing it. This requires use of the lockout
	// hierarchy.
	provisionModeClear
)

// provisionPrimaryKey provisions a primary key in the specified hierarchy at the specified persistent
// handle. If session is supplied, it is expected to be a HMAC session with the AttrContinueSession
// attribute set, and is used for authenticating with the relevant hierarchies to avoid sending the
// authorization value in the clear.
func provisionPrimaryKey(tpm *tpm2.TPMContext, hierarchy tpm2.ResourceContext, template *tpm2.Public, handle tpm2.Handle, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	obj, err := tpm.NewResourceContext(handle)
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

// selectSrkTemplate chooses a template to use for the storage primary key. Either the default
// template will be returned or a custom one stored in a decidcated NV index. The supplied
// HMAC session is used for authenticating with the storage hierarchy and is used to avoid sending
// the authorization value in the clear.
// XXX: The NV index should be created with the TPMA_NV_AUTHREAD attribute to avoid this entirely.
func selectSrkTemplate(tpm *tpm2.TPMContext, session tpm2.SessionContext) *tpm2.Public {
	nv, err := tpm.NewResourceContext(srkTemplateHandle)
	if err != nil {
		return tcg.SRKTemplate
	}

	nvPub, _, err := tpm.NVReadPublic(nv)
	if err != nil {
		return tcg.SRKTemplate
	}

	b, err := tpm.NVRead(tpm.OwnerHandleContext(), nv, nvPub.Size, 0, session)
	if err != nil {
		return tcg.SRKTemplate
	}

	var tmpl *tpm2.Public
	if _, err := mu.UnmarshalFromBytes(b, &tmpl); err != nil {
		return tcg.SRKTemplate
	}

	if !tmpl.IsStorageParent() {
		return tcg.SRKTemplate
	}

	return tmpl
}

// provisionStoragePrimaryKey provisions a storage primary key at the well known persistent
// handle. If session is supplied, it is expected to be a HMAC session with the AttrContinueSession
// attribute set, and is used for authenticating with the relevant hierarchies to avoid sending
// authorization values in the clear.
func provisionStoragePrimaryKey(tpm *tpm2.TPMContext, session tpm2.SessionContext) (tpm2.ResourceContext, error) {
	return provisionPrimaryKey(tpm, tpm.OwnerHandleContext(), selectSrkTemplate(tpm, session), tcg.SRKHandle, session)
}

// storeSrkTemplate stores the supplied template at a well known handle. If session is supplied,
// it must be a HMAC session and is used for authenticating with the storage hierarchy to avoid sending
// authorization values in the clear.
func storeSrkTemplate(tpm *tpm2.TPMContext, template *tpm2.Public, session tpm2.SessionContext) error {
	tmplB, err := mu.MarshalToBytes(template)
	if err != nil {
		return xerrors.Errorf("cannot marshal template: %w", err)
	}

	nvPub := tpm2.NVPublic{
		Index:   srkTemplateHandle,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVWriteDefine | tpm2.AttrNVOwnerRead | tpm2.AttrNVNoDA),
		Size:    uint16(len(tmplB))}
	nv, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPub, session)
	if err != nil {
		return xerrors.Errorf("cannot define NV index: %w", err)
	}

	if err := tpm.NVWrite(nv, nv, tmplB, 0, nil); err != nil {
		return xerrors.Errorf("cannot write NV index: %w", err)
	}

	if err := tpm.NVWriteLock(nv, nv, nil); err != nil {
		return xerrors.Errorf("cannot write lock NV index: %w", err)
	}

	return nil
}

// removeStoredSrkTemplate removes the SRK template stored at the well known handle, if there
// is one. If a session is supplied, it must be a HMAC session and is used for authenticating
// with the storage hierarchy to avoid sending the authorization value in the clear.
func removeStoredSrkTemplate(tpm *tpm2.TPMContext, session tpm2.SessionContext) error {
	nv, err := tpm.NewResourceContext(srkTemplateHandle)
	switch {
	case err != nil && !tpm2.IsResourceUnavailableError(err, srkTemplateHandle):
		// Unexpected error
		return xerrors.Errorf("cannot create resource context: %w", err)
	case tpm2.IsResourceUnavailableError(err, srkTemplateHandle):
		// Ok, nothing to do
		return nil
	}

	if err := tpm.NVUndefineSpace(tpm.OwnerHandleContext(), nv, session); err != nil {
		return xerrors.Errorf("cannot undefine index: %w", err)
	}

	return nil
}

type ensureProvisionedParams struct {
	mode                   provisionMode
	newLockoutAuthValue    []byte
	srkTemplate            *tpm2.Public
	useExistingSrkTemplate bool
}

type EnsureProvisionedOption func(*ensureProvisionedParams)

// ProvisionModeWithoutLockout tells [Connection.EnsureProvisioned] to not perform any actions
// that require use of the TPM's lockout hierarchy. If the TPM indicates that use of the lockout
// hierarchy is required to fully provision the TPM (eg, to disable owner clear, set the lockout
// hierarchy authorization value or configure the DA lockout parameters), then a
// [ErrTPMProvisioningRequiresLockout] error will be returned. In this scenario,
// [Connection.EnsureProvisioned] will complete all operations that can be completed without using
// the lockout hierarchy, but it should be called again without this option.
func ProvisionWithoutLockout() EnsureProvisionedOption {
	return func(p *ensureProvisionedParams) {
		if p.mode == provisionModeClear {
			panic("ProvisionWithoutLockout conflicts with WithClearBeforeProvision")
		}
		p.mode = provisionModeWithoutLockout
	}
}

// WithClearBeforeProvision tells [Connection.EnsureProvisioned] to clear the TPM before provisioning
// it. If owner clear has been disabled (which will be the case if the TPM has previously been provisioned
// with this function), then [ErrTPMClearRequiresPPI] will be returned. In this case, the TPM must be cleared
// via the physical presence interface by calling [RequestTPMClearUsingPPI] and performing a system restart.
// Note that clearing the TPM makes all previously sealed keys permanently unrecoverable. This option should
// normally be used when resetting a device to factory settings (ie, performing a new installation).
func WithClearBeforeProvision() EnsureProvisionedOption {
	return func(p *ensureProvisionedParams) {
		if p.mode == provisionModeWithoutLockout {
			panic("WithClearBeforeProvision conflicts with ProvisionWithoutLockout")
		}
		p.mode = provisionModeClear
	}
}

// WithProvisionNewLockoutAuthValue supplies the value to set the TPM's lockout hierarchy authorization
// value to. If this option is not supplied and [ProvisionWithoutLockout] is not supplied, then
// [Connection.EnsureProvisioned] will set it to an empty value. If [ProvisionWithoutLockout] is supplied,
// then this option has no effect.
func WithProvisionNewLockoutAuthValue(authValue []byte) EnsureProvisionedOption {
	return func(p *ensureProvisionedParams) {
		p.newLockoutAuthValue = authValue
	}
}

// WithCustomSRKTemplate tells [Connection.EnsureProvisioned] to create the storage root key using the supplied
// custom template rather than the one defined in the "TCG TPM v2.0 Provisioning Guidance" spec. The template will
// be persisted in a NV index and will be used in future calls to [Connection.EnsureProvisioned] if called
// without this option.
func WithCustomSRKTemplate(template *tpm2.Public) EnsureProvisionedOption {
	return func(p *ensureProvisionedParams) {
		p.srkTemplate = template
		p.useExistingSrkTemplate = false
	}
}

// EnsureProvisioned prepares the TPM for full disk encryption. The mode parameter specifies the behaviour of this function.
//
// This function will create and persist both a storage root key and an endorsement key. Both of these will be persisted
// at the handles specied in the "TCG TPM v2.0 Provisioning Guidance" specification. The endorsement key will be created
// using the RSA template defined in the "TCG EK Credential Profile for TPM Family 2.0" specification. The storage root
// key will be created using the RSA template defined in the "TCG TPM v2.0 Provisioning Guidance" specification unless the
// TPM has previously been provisioned with a custom SRK template using the [WithProvisionCustomSRKTemplate] option and the
// [WithClearBeforeProvision] option isn't supplied, in which case, the originally supplied template will be used instead. If
// there are any objects already stored at the locations required for either primary key, then this function will evict them
// automatically from the TPM. These operations both require the use of the storage and endorsement hierarchies. If the
// [WithClearBeforeProvision] option is not supplied, then knowledge of the authorization values for these hierarchies is
// required. Whilst these will be empty after clearing the TPM, if they have been set since clearing the TPM then they will
// need to be provided by calling Connection.EndorsementHandleContext().SetAuthValue() and
// Connection.OwnerHandleContext().SetAuthValue() prior to calling this function. If the wrong value is provided for either
// authorization, then a [AuthFailError] error will be returned. If the correct authorization values are not known, then the
// only way to recover from this is to clear the TPM either by calling this function with the [WithClearBeforeProvision]
// option (and providing the correct authorization value for the lockout hierarchy), or by using the physical presence interface.
//
// If the [ProvisionWithoutLockout] option is not supplied, then owner clear will be disabled, and the parameters of the TPM's
// dictionary attack logic will be configured to appropriate values. The authorization value for the lockout hierarchy will
// be set to the value supplied to [WithProvisionNewLockoutAuthValue], or the empty value if not supplied.
//
// If the [ProvisionWithoutLockout] option is not supplied, this function performs operations that require the use of the lockout
// hierarchy (detailed above), and knowledge of the lockout hierarchy's authorization value. This must be provided by calling
// Connection.LockoutHandleContext().SetAuthValue() prior to this call. If the wrong lockout hierarchy authorization value is
// provided, then a [AuthFailError] error will be returned. If this happens, the TPM will have entered dictionary attack lockout
// mode for the lockout hierarchy. Further calls will result in a [ErrTPMLockout] error being returned. The only way to recover
// from this is to either wait for the pre-programmed recovery time to expire, or to clear the TPM via the physical presence
// interface by calling [RequestTPMClearUsingPPI]. If the lockout hierarchy authorization value is not known then the
// [ProvisionWithoutLockout] option should be supplied, with the caveat that this mode cannot fully provision the TPM.
//
// If [WithClearBeforeProvision] is not supplied, this function will not affect the ability to recover sealed keys that
// can currently be recovered.
func (t *Connection) EnsureProvisioned(options ...EnsureProvisionedOption) error {
	params := &ensureProvisionedParams{
		mode:                   provisionModeFull,
		useExistingSrkTemplate: true,
	}
	for _, opt := range options {
		opt(params)
	}
	if params.srkTemplate != nil && !params.srkTemplate.IsStorageParent() {
		return errors.New("supplied SRK template is not valid for a parent key")
	}

	session := t.HmacSession()

	val, err := t.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	if err != nil {
		return fmt.Errorf("cannot fetch permanent properties: %w", err)
	}
	if params.mode == provisionModeClear {
		if tpm2.PermanentAttributes(val)&tpm2.AttrDisableClear > 0 {
			return ErrTPMClearRequiresPPI
		}

		// Use HMAC session to authenticate with lockout hierarchy.
		if err := t.Clear(t.LockoutHandleContext(), session); err != nil {
			switch {
			case isAuthFailError(err, tpm2.CommandClear, 1):
				return AuthFailError{tpm2.HandleLockout}
			case tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandClear):
				return ErrTPMLockout
			}
			return fmt.Errorf("cannot clear the TPM: %w", err)
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
			return fmt.Errorf("cannot provision endorsement key: %w", err)
		}
	}

	// Reinitialize the connection, which creates a new session that's salted with a value protected with the newly provisioned EK.
	// This will have a symmetric algorithm for parameter encryption during HierarchyChangeAuth.
	if err := t.init(); err != nil {
		return fmt.Errorf("cannot reinitialize TPM connection after provisioning endorsement key: %w", err)
	}
	session = t.HmacSession()

	// Provision a storage root key
	if !params.useExistingSrkTemplate && params.mode != provisionModeClear {
		// If we're not reusing the existing custom template, remove it. We don't
		// need to do this if mode == provisionModeClear because it will have already
		// been removed.
		if err := removeStoredSrkTemplate(t.TPMContext, session); err != nil {
			return fmt.Errorf("cannot remove stored custom SRK template: %w", err)
		}
	}
	if params.srkTemplate != nil {
		// Persist the new custom template
		if err := storeSrkTemplate(t.TPMContext, params.srkTemplate, session); err != nil {
			return fmt.Errorf("cannot store custom SRK template: %w", err)
		}
	}

	srk, err := provisionStoragePrimaryKey(t.TPMContext, session)
	if err != nil {
		switch {
		case isAuthFailError(err, tpm2.AnyCommandCode, 1):
			return AuthFailError{tpm2.HandleOwner}
		default:
			return fmt.Errorf("cannot provision storage root key: %w", err)
		}
	}
	t.provisionedSrk = srk

	if params.mode == provisionModeWithoutLockout {
		val, err := t.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
		if err != nil {
			return fmt.Errorf("cannot fetch permanent properties to determine if lockout hierarchy is required: %w", err)
		}
		required := tpm2.AttrLockoutAuthSet | tpm2.AttrDisableClear
		mask := required | tpm2.AttrInLockout
		if tpm2.PermanentAttributes(val)&mask != required {
			return ErrTPMProvisioningRequiresLockout
		}

		props, err := t.GetCapabilityTPMProperties(tpm2.PropertyMaxAuthFail, 3)
		if err != nil {
			return fmt.Errorf("cannot fetch DA parameters to determine if lockout hierarchy is required: %w", err)
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

	// Set the DA parameters. Pass the HMAC session here so we don't supply the cleartext auth
	// value for the lockout hierarchy.
	if err := t.DictionaryAttackParameters(t.LockoutHandleContext(), maxTries, recoveryTime, lockoutRecovery, session); err != nil {
		switch {
		case isAuthFailError(err, tpm2.CommandDictionaryAttackParameters, 1):
			return AuthFailError{tpm2.HandleLockout}
		case tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandDictionaryAttackParameters):
			return ErrTPMLockout
		}
		return fmt.Errorf("cannot configure dictionary attack parameters: %w", err)
	}

	// Clear any lockout if there is one. This has to happen after setting the DA parameters
	// because we can't clear a lockout if maxTries is 0.
	if err := t.DictionaryAttackLockReset(t.LockoutHandleContext(), session); err != nil {
		switch {
		case isAuthFailError(err, tpm2.CommandDictionaryAttackLockReset, 1):
			return AuthFailError{tpm2.HandleLockout}
		case tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandDictionaryAttackLockReset):
			return ErrTPMLockout
		}
		return fmt.Errorf("cannot reset dictionary attack protection: %w", err)
	}

	// Disable owner clear. Pass the HMAC session here so we don't supply the cleartext auth
	// value for the lockout hierarchy.
	if err := t.ClearControl(t.LockoutHandleContext(), true, session); err != nil {
		// Lockout auth failure or lockout mode would have been caught by DictionaryAttackParameters
		return fmt.Errorf("cannot disable owner clear: %w", err)
	}

	// Set the lockout hierarchy authorization. Use command parameter encryption here for the new value.
	// Note that this only offers protections against passive interposers.
	if err := t.HierarchyChangeAuth(t.LockoutHandleContext(), params.newLockoutAuthValue, session.IncludeAttrs(tpm2.AttrCommandEncrypt)); err != nil {
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
