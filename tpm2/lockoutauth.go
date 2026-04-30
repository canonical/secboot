// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/policyutil"
)

var (
	// ErrEmptyLockoutAuthValue is returned from Connection.ResetDictionaryAttackLock if
	// the authorization value for the lockout hierarchy is unset.
	ErrEmptyLockoutAuthValue = errors.New("the authorization value for the lockout hierarchy is empty")

	// ErrInvalidLockoutAuthPolicy is returned from Connection.ResetDictionaryAttackLock if
	// the authorization policy for the lockout hierarchy is not consistent with the supplied
	// data.
	ErrInvalidLockoutAuthPolicy = errors.New("the authorization policy for the lockout hierarchy is invalid")
)

// InvalidLockoutAuthDataError is returned from [Connection.ResetDictionaryAttackLock] if the
// supplied lockout hierarchy authorization data is invalid.
type InvalidLockoutAuthDataError struct {
	err error
}

func (e *InvalidLockoutAuthDataError) Error() string {
	return "invalid lockout hierarchy authorization data: " + e.err.Error()
}

func (e *InvalidLockoutAuthDataError) Unwrap() error {
	return e.err
}

type lockoutAuthParamsJson struct {
	AuthValue     []byte `json:"auth-value"`
	AuthPolicy    []byte `json:"auth-policy,omitempty"`
	NewAuthValue  []byte `json:"new-auth-value,omitempty"`
	NewAuthPolicy []byte `json:"new-auth-policy,omitempty"`
}

type lockoutAuthParams struct {
	AuthValue     tpm2.Auth
	AuthPolicy    *policyutil.Policy
	NewAuthValue  tpm2.Auth
	NewAuthPolicy *policyutil.Policy
}

func (p *lockoutAuthParams) MarshalJSON() ([]byte, error) {
	j := &lockoutAuthParamsJson{
		AuthValue:    p.AuthValue,
		NewAuthValue: p.NewAuthValue,
	}
	if p.AuthPolicy != nil {
		data, err := mu.MarshalToBytes(p.AuthPolicy)
		if err != nil {
			return nil, fmt.Errorf("cannot encode auth-policy: %w", err)
		}
		j.AuthPolicy = data
	}
	if p.NewAuthPolicy != nil {
		data, err := mu.MarshalToBytes(p.NewAuthPolicy)
		if err != nil {
			return nil, fmt.Errorf("cannot encode new-auth-policy: %w", err)
		}
		j.NewAuthPolicy = data
	}

	return json.Marshal(j)
}

func (p *lockoutAuthParams) UnmarshalJSON(data []byte) error {
	var j *lockoutAuthParamsJson
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}

	*p = lockoutAuthParams{
		AuthValue:    j.AuthValue,
		NewAuthValue: j.NewAuthValue,
	}
	if len(j.AuthPolicy) > 0 {
		if _, err := mu.UnmarshalFromBytes(j.AuthPolicy, &p.AuthPolicy); err != nil {
			return fmt.Errorf("cannot decode auth-policy: %w", err)
		}
	}
	if len(j.NewAuthPolicy) > 0 {
		if _, err := mu.UnmarshalFromBytes(j.NewAuthPolicy, &p.NewAuthPolicy); err != nil {
			return fmt.Errorf("cannot decode new-auth-policy: %w", err)
		}
	}

	return nil
}

func (t *Connection) resetDictionaryAttackLockImpl(params *lockoutAuthParams) error {
	if len(params.NewAuthValue) > 0 || params.NewAuthPolicy != nil {
		return errors.New("lockout hierarchy auth value change not supported yet")
	}

	var authValue []byte

	val, err := t.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	if err != nil {
		return fmt.Errorf("cannot obtain value of TPM_PT_PERMANENT: %w", err)
	}
	lockoutAuthSet := tpm2.PermanentAttributes(val)&tpm2.AttrLockoutAuthSet > 0
	if lockoutAuthSet {
		authValue = params.AuthValue
	}

	var session tpm2.SessionContext
	switch {
	case params.AuthPolicy == nil:
		session = t.HmacSession()
	default:
		session, err = t.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, defaultSessionHashAlgorithm)
		if err != nil {
			return fmt.Errorf("cannot start policy session: %w", err)
		}
		defer t.FlushContext(session)

		// Execute policy session, constraining the use to the TPM2_DictionaryAttackLockReset command so
		// that the correct branch executes.
		_, err := params.AuthPolicy.Execute(
			policyutil.NewPolicyExecuteSession(t.TPMContext, session),
			policyutil.WithSessionUsageCommandConstraint(tpm2.CommandDictionaryAttackLockReset, []policyutil.NamedHandle{t.LockoutHandleContext()}),
		)
		if err != nil {
			return ErrInvalidLockoutAuthPolicy
		}
	}

	t.LockoutHandleContext().SetAuthValue(authValue)
	defer t.LockoutHandleContext().SetAuthValue(nil)

	switch err := t.DictionaryAttackLockReset(t.LockoutHandleContext(), session); {
	case isAuthFailError(err, tpm2.CommandDictionaryAttackLockReset, 1):
		return AuthFailError{tpm2.HandleLockout}
	case tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandDictionaryAttackLockReset):
		return ErrTPMLockout
	case tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandDictionaryAttackLockReset, 1):
		return ErrInvalidLockoutAuthPolicy
	case err != nil:
		return fmt.Errorf("cannot reset dictionary attack counter: %w", err)
	}

	if !lockoutAuthSet {
		return ErrEmptyLockoutAuthValue
	}
	return nil
}

// ResetDictionaryAttackLock resets the TPM's dictionary attack counter using the
// TPM2_DictionaryAttackLockReset command. The caller supplies authorization data for the TPM's
// lockout hierarchy which will have been supplied by a previous call to
// [Connection.EnsureProvisioned] (XXX: in a future PR).
//
// If the supplied authorization data is invalid, a *[InvalidLockoutAuthDataError] error will
// be returned.
//
// If the TPM indicates that the lockout hierarchy has an empty authorization value, this function
// will still succeed but will return an [ErrEmptyLockoutAuthValue] error.
//
// If authorization of the TPM's lockout hierarchy fails, an [AuthFailError] error will be returned.
// In this case, the lockout hierarchy will become unavailable for the current lockout recovery
// time ([Connection.EnsureProvisioned] sets it to 86400 seconds).
//
// If the TPM's lockout hierarchy is unavailable because of a previous authorization failure, an
// [ErrTPMLockout] error will be returned.
//
// If the authorization policy for the TPM's lockout hierarchy is invalid, an
// [ErrInvalidLockoutAuthPolicy] error will be returned.
func (t *Connection) ResetDictionaryAttackLock(lockoutAuthData []byte) error {
	var params *lockoutAuthParams
	if err := json.Unmarshal(lockoutAuthData, &params); err != nil {
		return &InvalidLockoutAuthDataError{err: err}
	}
	return t.resetDictionaryAttackLockImpl(params)
}

// ResetDictionaryAttackLockWithAuthValue resets the TPM's dictionary attack counter using the
// TPM2_DictionaryAttackLockReset command. The caller supplies the authorization value for the
// TPM's lockout hierarchy. This API is for systems that were configured with an older version
// of [Connection.EnsureProvisioned] (XXX: not yet) where an authorization value was chosen and
// supplied by the caller.
//
// If the TPM indicates that the lockout hierarchy has an empty authorization value, this function
// will still succeed but will return an [ErrEmptyLockoutAuthValue] error.
//
// If authorization of the TPM's lockout hierarchy fails, an [AuthFailError] error will be returned.
// In this case, the lockout hierarchy will become unavailable for the current lockout recovery
// time ([Connection.EnsureProvisioned] sets it to 86400 seconds).
//
// If the TPM's lockout hierarchy is unavailable because of a previous authorization failure, an
// [ErrTPMLockout] error will be returned.
func (t *Connection) ResetDictionaryAttackLockWithAuthValue(lockoutAuthValue []byte) error {
	return t.resetDictionaryAttackLockImpl(&lockoutAuthParams{
		AuthValue: lockoutAuthValue,
	})
}
