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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/policyutil"
	internal_crypto "github.com/snapcore/secboot/internal/crypto"
	"golang.org/x/crypto/hkdf"
)

var (
	// ErrInvalidLockoutAuthPolicy is returned from [Connection.ResetDictionaryAttackLock] or
	// [Connection.EnsureProvisioned] if the authorization policy for the lockout hierarchy is
	// not consistent with the supplied data. [Connection.EnsureProvisioned] should be called
	// with the [WithProvisionNewLockoutAuthData] option in order to fix this.
	ErrInvalidLockoutAuthPolicy = errors.New("the authorization policy for the lockout hierarchy is inconsistent with the supplied data")

	// ErrLockoutAuthInitialized is returned from [Connection.EnsureProvisioned] when called with
	// the [WithUnconfiguredLockoutAuth] option if the authorization parameters for the lockout
	// hierarchy have already been configured.
	ErrLockoutAuthInitialized = errors.New("the authorization parameters for the lockout hierarchy are already initialized")

	// ErrLockoutAuthNotInitialized is returned from [Connection.ResetDictionaryAttackLock] if
	// the authorization parameters for the lockout hierarchy need to be initialized.
	// [Connection.EnsureProvisioned] should be called with the [WithProvisionNewLockoutAuthData]
	// option in order to fix this.
	ErrLockoutAuthNotInitialized = errors.New("the authorization parameters for the lockout hierarchy are not fully initialized")

	// ErrLockoutAuthUpdateInterrupted is returned from [Connection.ResetDictionaryAttackLock] or
	// [Connection.EnsureProvisioned] if a previous update to the authorization value for the lockout
	// hierarchy was interrupted. [Connection.EnsureProvisioned] should be called with the
	// [WithProvisionNewLockoutAuthData] option in order to fix this.
	ErrLockoutAuthUpdateInterrupted = errors.New("a previous attempt to update the authorization parameters for the lockout hierarchy was interrupted")

	// ErrLockoutAuthUpdateUnsupported is returned from [Connection.EnsureProvisioned] when called
	// with the [WithProvisionNewLockoutAuthData] option if the authorization value for the
	// lockout hierarchy is already set and the system does not support updating it.
	ErrLockoutAuthUpdateUnsupported = errors.New("updating the authorization parameters for the lockout hierarchy is not supported")

	errLockoutAuthPolicyNotSupported = errors.New("lockout auth policies not supported")
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

	// noAuthValue is a special value only set by WithUnconfiguredLockoutAuth so
	// that we can return an appropriate error rather than triggering a lockout
	// if the option is supplied when the lockout hierarchy already has an
	// authorization value.
	noAuthValue bool
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

// newDefaultLockoutAuthPolicy returns a new policy that permits use of an authorization value with
// the TPM2_DictionaryAttackLockReset, TPM2_DictionaryAttackParameters, TPM2_Clear, TPM2_ClearControl,
// and TPM2_SetPrimaryPolicy commands.
func newDefaultLockoutAuthPolicy(alg tpm2.HashAlgorithmId) (tpm2.Digest, *policyutil.Policy, error) {
	builder := policyutil.NewPolicyBuilder(alg)
	builder.RootBranch().AddBranchNode(func(n *policyutil.PolicyBuilderBranchNode) {
		n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandDictionaryAttackLockReset)
		})
		n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandDictionaryAttackParameters)
		})
		n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandClearControl)
		})
		n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandClear)
		})
		n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandSetPrimaryPolicy)
		})
	})
	builder.RootBranch().PolicyAuthValue()

	return builder.Policy()
}

func newUpdateLockoutAuthValueKey(ikm []byte) (*ecdsa.PrivateKey, *tpm2.Public, error) {
	r := hkdf.Expand(crypto.SHA256.New, ikm, []byte("UPDATE-AUTH-VALUE"))
	key, err := internal_crypto.GenerateECDSAKey(elliptic.P256(), r)
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return key, pubKey, nil
}

// newUpdateAuthValueLockoutAuthPolicy returns a new policy that permits the use of a signed
// authorization with the TPM2_HierarchyChangeAuth command in order to change the authorization
// value to the specified value. It also supports using an authorization value with the
// TPM2_SetPrimaryPolicy command.
func newUpdateAuthValueLockoutAuthPolicy(alg tpm2.HashAlgorithmId, oldAuthValue []byte) (tpm2.Digest, *policyutil.Policy, *ecdsa.PrivateKey, *tpm2.Public, error) {
	key, pubKey, err := newUpdateLockoutAuthValueKey(oldAuthValue)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot create temporary signing key: %w", err)
	}
	builder := policyutil.NewPolicyBuilder(alg)
	builder.RootBranch().AddBranchNode(func(n *policyutil.PolicyBuilderBranchNode) {
		n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandSetPrimaryPolicy)
			b.PolicyAuthValue()
		})
		n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
			// Note that this branch permits setting the authorization value without any
			// dictionary attack protection. This is only a transient state so this is
			// ok but not ideal. I would have liked to have used a TPM2_PolicyCpHash
			// assertion here to bind the policy to the new authorization value so that
			// this branch would require knowledge of both the old and new values.
			// However, TPM2_PolicyCpHash doesn't work here because we use parameter
			// encryption and the CpHash is computed after the command parameters are
			// encrypted.
			//
			// As the policy is not hardcoded in the metadata, it would be trivial to
			// update this policy branch in the future in order to make improvements.
			b.PolicyCommandCode(tpm2.CommandHierarchyChangeAuth)
			b.PolicySigned(pubKey, []byte("UPDATE-AUTH-VALUE"))
		})
	})

	digest, policy, err := builder.Policy()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return digest, policy, key, pubKey, nil
}

type lockoutAuthValueUpdateStateMachineState func() (lockoutAuthValueUpdateStateMachineState, error)

type lockoutAuthValueUpdateStateMachine struct {
	rand io.Reader
	tpm  *Connection

	authParams *lockoutAuthParams

	next lockoutAuthValueUpdateStateMachineState
	err  error

	updateAuthKey    *ecdsa.PrivateKey
	updateAuthPubKey *tpm2.Public
}

func newLockoutAuthValueUpdateStateMachine(rand io.Reader, tpm *Connection, authParams *lockoutAuthParams) (*lockoutAuthValueUpdateStateMachine, error) {
	m := &lockoutAuthValueUpdateStateMachine{
		rand:       rand,
		tpm:        tpm,
		authParams: authParams,
	}

	switch {
	default:
		m.next = m.prepare
	case len(authParams.NewAuthValue) > 0 && authParams.NewAuthPolicy != nil:
		// prepare was completed already.
		algs := authParams.NewAuthPolicy.DigestAlgs()
		if len(algs) == 0 {
			return nil, &InvalidLockoutAuthDataError{err: errors.New("new-auth-policy has no computed digests")}
		}
		digest, err := authParams.NewAuthPolicy.Digest(algs[0])
		if err != nil {
			return nil, &InvalidLockoutAuthDataError{err: fmt.Errorf("cannot obtain new-auth-policy digest: %w", err)}
		}
		m.updateAuthKey, m.updateAuthPubKey, err = newUpdateLockoutAuthValueKey(authParams.AuthValue)
		if err != nil {
			return nil, fmt.Errorf("cannot create temporary signing key: %w", err)
		}
		m.next = func() (lockoutAuthValueUpdateStateMachineState, error) {
			return m.setNewAuthValuePolicy(algs[0], digest)
		}
	case len(authParams.NewAuthValue) > 0:
		// setNewAuthValuePolicy was completed already.
		if authParams.AuthPolicy == nil {
			return nil, &InvalidLockoutAuthDataError{err: errors.New("missing auth-policy")}
		}
		algs := authParams.AuthPolicy.DigestAlgs()
		if len(algs) == 0 {
			return nil, &InvalidLockoutAuthDataError{err: errors.New("auth-policy has no computed digests")}
		}
		var err error
		m.updateAuthKey, m.updateAuthPubKey, err = newUpdateLockoutAuthValueKey(authParams.AuthValue)
		if err != nil {
			return nil, fmt.Errorf("cannot create temporary signing key: %w", err)
		}
		m.next = func() (lockoutAuthValueUpdateStateMachineState, error) {
			return m.setNewAuthValue(algs[0])
		}
	case authParams.NewAuthPolicy != nil:
		// setNewAuthValue was completed already.
		algs := authParams.NewAuthPolicy.DigestAlgs()
		if len(algs) == 0 {
			return nil, &InvalidLockoutAuthDataError{err: errors.New("new-auth-policy has no computed digests")}
		}
		digest, err := authParams.NewAuthPolicy.Digest(algs[0])
		if err != nil {
			return nil, &InvalidLockoutAuthDataError{err: fmt.Errorf("cannot obtain new-auth-policy digest: %w", err)}
		}
		m.next = func() (lockoutAuthValueUpdateStateMachineState, error) {
			return m.setDefaultPolicy(algs[0], digest)
		}
	}

	return m, nil
}

func (m *lockoutAuthValueUpdateStateMachine) authorizeLockout(allowFallbackToHMACSession bool, command tpm2.CommandCode) (session tpm2.SessionContext, done func(), err error) {
	return m.tpm.authorizeLockout(m.authParams, allowFallbackToHMACSession, command, m.signedAuthorizer)
}

func (m *lockoutAuthValueUpdateStateMachine) signedAuthorizer(sessionAlg tpm2.HashAlgorithmId, sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*policyutil.PolicySignedAuthorization, error) {
	params := &policyutil.PolicySignedParams{
		HashAlg:  sessionAlg,
		NonceTPM: sessionNonce,
	}
	return policyutil.SignPolicySignedAuthorization(rand.Reader, params, m.updateAuthPubKey, policyRef, m.updateAuthKey, tpm2.HashAlgorithmSHA256)
}

// prepare creates a new authorization value and a temporary authorization policy that can be used to
// update the lockout hierarchy's authorization value to the new value.
//
// On completion, the updated state can still be used to authorize the lockout hierarchy using the
// default policy which requires an authorization value for all supported commands.
func (m *lockoutAuthValueUpdateStateMachine) prepare() (lockoutAuthValueUpdateStateMachineState, error) {
	if m.rand == nil {
		return nil, errors.New("no entropy source provided")
	}

	val, err := m.tpm.GetCapabilityTPMProperty(tpm2.PropertyContextHash)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain value of TPM_PT_CONTEXT_HASH: %w", err)
	}

	contextHash := tpm2.HashAlgorithmId(val)
	if !contextHash.IsValid() {
		return nil, fmt.Errorf("unexpected TPM_PT_CONTEXT_HASH value: %v", contextHash)
	}

	m.authParams.NewAuthValue = make([]byte, contextHash.Size())
	if _, err := m.rand.Read(m.authParams.NewAuthValue); err != nil {
		return nil, fmt.Errorf("cannot create new auth value")
	}

	var newPolicyDigest tpm2.Digest
	newPolicyDigest, m.authParams.NewAuthPolicy, m.updateAuthKey, m.updateAuthPubKey, err = newUpdateAuthValueLockoutAuthPolicy(contextHash, m.authParams.AuthValue)
	if err != nil {
		return nil, fmt.Errorf("cannot create temporary auth policy: %w", err)
	}

	return func() (lockoutAuthValueUpdateStateMachineState, error) {
		return m.setNewAuthValuePolicy(contextHash, newPolicyDigest)
	}, nil
}

// setNewAuthValuePolicy sets the authorization policy for the lockout hierarchy to the temporary
// policy that permits updating the hierarchy's authorization value.
//
// On completion, the updated state can only be used to authorize the lockout hierarchy using the
// temporary policy to update it's authorization value to a specific value, and to update it's policy
// using it's authorization value. Note that it is not safe to use the authorization value yet though.
func (m *lockoutAuthValueUpdateStateMachine) setNewAuthValuePolicy(policyAlg tpm2.HashAlgorithmId, policyDigest tpm2.Digest) (lockoutAuthValueUpdateStateMachineState, error) {
	session, done, err := m.authorizeLockout(true, tpm2.CommandSetPrimaryPolicy)
	switch {
	case errors.Is(err, errLockoutAuthPolicyNotSupported):
		return m.setAuthValueWithoutPolicy, nil
	case err != nil:
		return nil, err
	}
	defer done()

	if err := m.tpm.SetPrimaryPolicy(m.tpm.LockoutHandleContext(), policyDigest, policyAlg, session); err != nil {
		return nil, fmt.Errorf("cannot set temporary auth policy: %w", err)
	}

	m.authParams.AuthPolicy = m.authParams.NewAuthPolicy
	m.authParams.NewAuthPolicy = nil

	return func() (lockoutAuthValueUpdateStateMachineState, error) {
		return m.setNewAuthValue(policyAlg)
	}, nil
}

func (m *lockoutAuthValueUpdateStateMachine) setAuthValueWithoutPolicy() (lockoutAuthValueUpdateStateMachineState, error) {
	m.authParams.AuthPolicy = nil
	m.authParams.NewAuthPolicy = nil

	session, done, err := m.authorizeLockout(false, tpm2.CommandHierarchyChangeAuth)
	if err != nil {
		return nil, err
	}
	defer done()

	if len(m.tpm.LockoutHandleContext().AuthValue()) > 0 {
		return nil, ErrLockoutAuthUpdateUnsupported
	}

	// We use command parameter encryption here to protect the new authorization value.
	if err := m.tpm.HierarchyChangeAuth(m.tpm.LockoutHandleContext(), m.authParams.NewAuthValue, session.IncludeAttrs(tpm2.AttrCommandEncrypt)); err != nil {
		return nil, fmt.Errorf("cannot set new auth value without policy: %w", err)
	}

	m.authParams.AuthValue = m.authParams.NewAuthValue
	m.authParams.NewAuthValue = nil
	m.authParams.noAuthValue = false

	return nil, nil
}

// setNewAuthValue updates the authorization value for the lockout hierarchy.
//
// On completion, the updated state can only be used to authorize the lockout hierarchy using the
// temporary policy to set a new policy using an authorization value.
func (m *lockoutAuthValueUpdateStateMachine) setNewAuthValue(policyAlg tpm2.HashAlgorithmId) (lockoutAuthValueUpdateStateMachineState, error) {
	session, done, err := m.authorizeLockout(false, tpm2.CommandHierarchyChangeAuth)
	if err != nil {
		return nil, err
	}
	defer done()

	// We use command parameter encryption here to protect the new authorization value.
	switch {
	case session.Handle().Type() == tpm2.HandleTypePolicySession:
		// We're using policy auth so need to supply the HMAC session as an extra
		// session for parameter encryption.
		err = m.tpm.HierarchyChangeAuth(m.tpm.LockoutHandleContext(), m.authParams.NewAuthValue, session, m.tpm.HmacSession().IncludeAttrs(tpm2.AttrCommandEncrypt))
	default:
		// We're using HMAC auth
		err = m.tpm.HierarchyChangeAuth(m.tpm.LockoutHandleContext(), m.authParams.NewAuthValue, session.IncludeAttrs(tpm2.AttrCommandEncrypt))
	}
	if err != nil {
		return nil, fmt.Errorf("cannot set new auth value: %w", err)
	}

	m.authParams.AuthValue = m.authParams.NewAuthValue
	m.authParams.NewAuthValue = nil
	m.authParams.noAuthValue = false

	var newPolicyDigest tpm2.Digest
	newPolicyDigest, m.authParams.NewAuthPolicy, err = newDefaultLockoutAuthPolicy(policyAlg)
	if err != nil {
		return nil, fmt.Errorf("cannot create default auth policy: %w", err)
	}

	return func() (lockoutAuthValueUpdateStateMachineState, error) {
		return m.setDefaultPolicy(policyAlg, newPolicyDigest)
	}, nil
}

// setDefaultPolicy sets the authorization policy for the lockout hierarchy to the default policy.
func (m *lockoutAuthValueUpdateStateMachine) setDefaultPolicy(policyAlg tpm2.HashAlgorithmId, policyDigest tpm2.Digest) (lockoutAuthValueUpdateStateMachineState, error) {
	session, done, err := m.authorizeLockout(false, tpm2.CommandSetPrimaryPolicy)
	if err != nil {
		return nil, err
	}
	defer done()

	if err := m.tpm.SetPrimaryPolicy(m.tpm.LockoutHandleContext(), policyDigest, policyAlg, session); err != nil {
		return nil, fmt.Errorf("cannot set temporary auth policy: %w", err)
	}

	m.authParams.AuthPolicy = m.authParams.NewAuthPolicy
	m.authParams.NewAuthPolicy = nil

	// Done!
	return nil, nil
}

func (m *lockoutAuthValueUpdateStateMachine) hasMoreWork() bool {
	return m.next != nil && m.err == nil
}

func (m *lockoutAuthValueUpdateStateMachine) runNext() error {
	if m.err != nil {
		return fmt.Errorf("error occurred during previous state: %w", m.err)
	}
	if m.next == nil {
		return errors.New("no more work to do")
	}

	m.next, m.err = m.next()
	return m.err
}

// authorizeLockout authorizes the use of the lockout hierarchy using the supplied parameters for the
// specified command code. On success, a session is returned that can be used to authorize the specified
// command. The session is either a newly created policy session or the HMAC session returned from
// Connection.HmacSession.
//
// After using the authorization, the caller must execute the returned callback.
func (t *Connection) authorizeLockout(authParams *lockoutAuthParams, allowFallbackToHMACSession bool, command tpm2.CommandCode, signAuthFn policyutil.SignedAuthorizer) (session tpm2.SessionContext, done func(), err error) {
	// Select the correct policy based on the current policy digest for the lockout hierarchy.
	var (
		policy    *policyutil.Policy
		policyAlg tpm2.HashAlgorithmId
	)
	if authParams.AuthPolicy != nil || authParams.NewAuthPolicy != nil {
		// Only do this if there is policy data.
		switch currentPolicyDigest, err := t.GetCapabilityAuthPolicy(tpm2.HandleLockout); {
		case tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandGetCapability, 1):
			// TPM_CAP_AUTH_POLICIES is unsupported on TPMs older than v1.38 of the
			// reference library spec.
			return nil, nil, errLockoutAuthPolicyNotSupported
		case err != nil:
			return nil, nil, fmt.Errorf("cannot obtain current TPM lockout auth policy: %w", err)
		case currentPolicyDigest.HashAlg == tpm2.HashAlgorithmNull:
			// Lockout hierarchy has no policy set yet. Always fall back to HMAC
			// auth in this case. This is safe because we aren't in the process of
			// updating the authorization value.
		default:
			// We have the current policy digest for the lockout hierarchy.
			for _, p := range []*policyutil.Policy{authParams.AuthPolicy, authParams.NewAuthPolicy} {
				if p == nil {
					continue
				}
				algs := p.DigestAlgs()
				if len(algs) == 0 {
					continue
				}
				if algs[0] != currentPolicyDigest.HashAlg {
					continue
				}
				digest, err := p.Digest(algs[0])
				if err != nil {
					return nil, nil, fmt.Errorf("cannot obtain computed digest from policy: %w", err)
				}
				if bytes.Equal(digest, currentPolicyDigest.Digest()) {
					// This is the matching policy.
					policy = p
					policyAlg = algs[0]
					break
				}
			}
			if policy == nil && !allowFallbackToHMACSession {
				return nil, nil, ErrInvalidLockoutAuthPolicy
			}
		}
	}

	var authValue []byte

	// Determine if the lockout hierarchy has an authorization value set. This is to avoid specifying
	// an invalid value if none is set, which can happen after a TPM is cleared or a system board change.
	val, err := t.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot obtain value of TPM_PT_PERMANENT: %w", err)
	}
	switch lockoutAuthSet := tpm2.PermanentAttributes(val)&tpm2.AttrLockoutAuthSet > 0; {
	case lockoutAuthSet && authParams.noAuthValue:
		return nil, nil, ErrLockoutAuthInitialized
	case lockoutAuthSet:
		authValue = authParams.AuthValue
	}

	var authValueNeeded bool
	switch {
	case policy == nil:
		// There is no policy, fall back to using a HMAC auth.
		session = t.HmacSession()
		authValueNeeded = true
	default:
		// Execute the selected policy with the supplied command code as a constraint so that the correct
		// branch executes.
		session, err = t.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, policyAlg)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot start policy session: %w", err)
		}
		sessionInternal := session
		defer func() {
			if err == nil {
				return
			}
			t.FlushContext(sessionInternal)
		}()

		result, err := policy.Execute(
			policyutil.NewPolicyExecuteSession(t.TPMContext, session),                           // the session to execute the policy in
			policyutil.WithTPMHelper(t.TPMContext),                                              // to execute extra TPM commands (TPM2_LoadExternal)
			policyutil.WithResources(t.TPMContext, policyutil.WithSignedAuthorizer(signAuthFn)), // to obtain signed authorizations
			policyutil.WithSessionUsageCommandCodeConstraint(command),                           // constrain to the specified command
		)
		var pe *policyutil.NoAppropriatePathError
		switch {
		case errors.As(err, &pe):
			// If a path cannot be selected, assume that a previous update was interrutped.
			return nil, nil, ErrLockoutAuthUpdateInterrupted
		case err != nil:
			// Treat any other error as invalid auth data.
			return nil, nil, &InvalidLockoutAuthDataError{err: fmt.Errorf("cannot execute policy: %w", err)}
		}

		authValueNeeded = result.AuthValueNeeded
	}

	origAuthValue := t.LockoutHandleContext().AuthValue()
	if authValueNeeded {
		t.LockoutHandleContext().SetAuthValue(authValue)
	}

	return session, func() {
		if policy != nil {
			t.FlushContext(session)
		}
		t.LockoutHandleContext().SetAuthValue(origAuthValue)
	}, nil
}

func (t *Connection) updateLockoutAuthValue(rand io.Reader, params *lockoutAuthParams, syncParams func() error) error {
	m, err := newLockoutAuthValueUpdateStateMachine(rand, t, params)
	if err != nil {
		return err
	}

	for m.hasMoreWork() {
		if err := m.runNext(); err != nil {
			return err
		}
		if syncParams != nil {
			if err := syncParams(); err != nil {
				return fmt.Errorf("cannot sync updated auth params: %w", err)
			}
		}
	}

	return nil
}

func (t *Connection) resetDictionaryAttackLockImpl(params *lockoutAuthParams) error {
	session, done, err := t.authorizeLockout(params, false, tpm2.CommandDictionaryAttackLockReset, nil)
	switch {
	case errors.Is(err, errLockoutAuthPolicyNotSupported):
		return &InvalidLockoutAuthDataError{err: err}
	case err != nil:
		return err
	}
	defer done()

	switch err := t.DictionaryAttackLockReset(t.LockoutHandleContext(), session); {
	case isAuthFailError(err, tpm2.CommandDictionaryAttackLockReset, 1):
		return AuthFailError{tpm2.HandleLockout}
	case tpm2.IsTPMWarning(err, tpm2.WarningLockout, tpm2.CommandDictionaryAttackLockReset):
		return ErrTPMLockout
	case err != nil:
		return fmt.Errorf("cannot reset dictionary attack counter: %w", err)
	}

	switch {
	case len(t.LockoutHandleContext().AuthValue()) == 0:
		// authorization was performed with an empty auth value.
		return ErrLockoutAuthNotInitialized
	case params.AuthPolicy != nil && session.Handle().Type() == tpm2.HandleTypeHMACSession:
		// authorization was performed with a HMAC session when we have policy data,
		// which only happens if the lockout hierarchy has no policy set.
		return ErrLockoutAuthNotInitialized
	}
	return nil
}

// ResetDictionaryAttackLock resets the TPM's dictionary attack counter using the
// TPM2_DictionaryAttackLockReset command. The caller supplies authorization data for the TPM's
// lockout hierarchy which will have been supplied by a previous call to
// [Connection.EnsureProvisioned] with the [WithProvisionNewLockoutAuthData] option.
//
// If the supplied authorization data is invalid, a *[InvalidLockoutAuthDataError] error will
// be returned.
//
// If the TPM indicates that the lockout hierarchy has an empty authorization value or policy,
// this function will still succeed but will return an [ErrLockoutAuthNotInitialized] error.
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
//
// If a previous call to [Connection.EnsureProvisioned] with the [WithProvisionNewLockoutAuthData]
// option was interrupted, this may return a [ErrLockoutAuthUpdateInterrupted] error. In this case,
// Connection.EnsureProvisioned] should be called again with the [WithProvisionNewLockoutAuthData]
// option in order to complete the previous operation.
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
// of [Connection.EnsureProvisioned] where an authorization value was chosen and supplied by the
// caller.
//
// If the TPM indicates that the lockout hierarchy has an empty authorization value, this function
// will still succeed but will return an [ErrLockoutAuthNotInitialized] error.
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
