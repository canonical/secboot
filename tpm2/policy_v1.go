// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2021 Canonical Ltd
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
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/util"

	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
)

// computeV1PcrPolicyCounterAuthPolicies computes the authorization policy digests passed to
// TPM2_PolicyOR for a PCR policy counter that can be updated with the key associated with
// updateKeyName.
func computeV1PcrPolicyCounterAuthPolicies(alg tpm2.HashAlgorithmId, updateKeyName tpm2.Name) tpm2.DigestList {
	// The NV index requires 2 policies:
	// - A policy to initialize the index with no authorization
	// - A policy for updating the index to revoke old PCR policies using a signed assertion. This isn't done for security
	//   reasons, but just to make it harder to accidentally increment the counter for anyone interacting with the TPM.
	// This is simpler than the policy required for the v0 PIN NV index because it doesn't require additional authorization
	// policy branches to allow its authorization value to be changed, or to be able to read the counter value or use it in
	// a policy assertion without knowing the authorization value (reading the value of this counter does require the
	// authorization value, but it is always empty and this policy doesn't allow it to be changed).
	var authPolicies tpm2.DigestList

	if !updateKeyName.IsValid() {
		// avoid a panic if updateKeyName is invalid. Note that this will
		// produce invalid policies - callers should take steps to ensure that
		// updateKeyName is valid.
		updateKeyName = tpm2.Name(mu.MustMarshalToBytes(tpm2.HandleUnassigned))
	}

	trial := util.ComputeAuthPolicy(alg)
	trial.PolicyNvWritten(false)
	authPolicies = append(authPolicies, trial.GetDigest())

	trial = util.ComputeAuthPolicy(alg)
	trial.PolicySigned(updateKeyName, nil)
	authPolicies = append(authPolicies, trial.GetDigest())

	return authPolicies
}

// computeV1PcrPolicyRefFromCounterName computes the reference used for authorization of signed
// PCR policies from the supplied PCR policy counter name. If name is empty, then the name of
// the null handle is assumed. The policy ref serves 2 purposes:
//  1. It limits the scope of the signed policy to just PCR policies (the dynamic authorization
//     policy key may be able to sign different types of policy in the future, for example, to
//     permit recovery with a signed assertion.
//  2. It binds the name of the PCR policy counter to the static authorization policy.
func computeV1PcrPolicyRefFromCounterName(name tpm2.Name) tpm2.Nonce {
	if len(name) == 0 {
		name = make(tpm2.Name, binary.Size(tpm2.Handle(0)))
		binary.BigEndian.PutUint32(name, uint32(tpm2.HandleNull))
	}

	h := tpm2.HashAlgorithmSHA256.NewHash()
	h.Write([]byte("AUTH-PCR-POLICY"))
	h.Write(name)

	return h.Sum(nil)
}

// computeV1PcrPolicyRefFromCounterContext computes the reference used for authorization of signed PCR policies from the supplied
// ResourceContext.
func computeV1PcrPolicyRefFromCounterContext(context tpm2.ResourceContext) tpm2.Nonce {
	var name tpm2.Name
	if context != nil {
		name = context.Name()
	}

	return computeV1PcrPolicyRefFromCounterName(name)
}

// staticPolicyData_v1 represents version 1 of the metadata for executing a
// policy session that never changes for the life of a key.
type staticPolicyData_v1 struct {
	AuthPublicKey          *tpm2.Public
	PCRPolicyCounterHandle tpm2.Handle
	PCRPolicyRef           tpm2.Nonce // unused
}

// pcrPolicyData_v1 represents version 1 of the PCR policy metadata for
// executing a policy session, and can be updated. It has the same format
// as version 0.
type pcrPolicyData_v1 = pcrPolicyData_v0

// keyDataPolicy_v1 represents version 1 of the metadata for executing a
// policy session.
type keyDataPolicy_v1 struct {
	StaticData *staticPolicyData_v1
	PCRData    *pcrPolicyData_v1
}

func (p *keyDataPolicy_v1) PCRPolicyCounterHandle() tpm2.Handle {
	return p.StaticData.PCRPolicyCounterHandle
}

func (p *keyDataPolicy_v1) PCRPolicySequence() uint64 {
	return p.PCRData.PolicySequence
}

// UpdatePCRPolicy updates the PCR policy associated with this keyDataPolicy. The PCR policy asserts
// that the following are true:
//   - The selected PCRs contain expected values - ie, one of the sets of permitted values specified by
//     the caller to this function, indicating that the device is in an expected state. This is done by a
//     single PolicyPCR assertion and then one or more PolicyOR assertions (depending on how many sets of
//     permitted PCR values there are).
//   - The PCR policy hasn't been revoked. This is done using a PolicyNV assertion to assert that the
//     value of an optional NV counter is not greater than the PCR policy sequence.
//
// The computed PCR policy digest is authorized with the supplied key. The signature of this is
// validated during execution before executing the corresponding PolicyAuthorize assertion as part of the
// static policy.
func (p *keyDataPolicy_v1) UpdatePCRPolicy(alg tpm2.HashAlgorithmId, params *pcrPolicyParams) error {
	pcrData := p.PCRData.new(params)

	trial := util.ComputeAuthPolicy(alg)
	if err := pcrData.addPcrAssertions(alg, trial, params.pcrDigests); err != nil {
		return xerrors.Errorf("cannot compute base PCR policy: %w", err)
	}

	if params.policyCounterName != nil {
		pcrData.addRevocationCheck(trial, params.policyCounterName)
	}

	key, err := createECDSAPrivateKeyFromTPM(p.StaticData.AuthPublicKey, tpm2.ECCParameter(params.key))
	if err != nil {
		return xerrors.Errorf("cannot create auth key: %w", err)
	}

	scheme := &tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgECDSA,
		Details: &tpm2.SigSchemeU{
			ECDSA: &tpm2.SigSchemeECDSA{
				HashAlg: p.StaticData.AuthPublicKey.NameAlg}}}
	if err := pcrData.authorizePolicy(key, scheme, trial.GetDigest(), computeV1PcrPolicyRefFromCounterName(params.policyCounterName)); err != nil {
		return xerrors.Errorf("cannot authorize policy: %w", err)
	}

	p.PCRData = pcrData
	return nil
}

func (p *keyDataPolicy_v1) SetPCRPolicyFrom(src keyDataPolicy) {
	p.PCRData = src.(*keyDataPolicy_v1).PCRData
}

func (p *keyDataPolicy_v1) ExecutePCRPolicy(tpm *tpm2.TPMContext, policySession, hmacSession tpm2.SessionContext) error {
	if err := p.PCRData.executePcrAssertions(tpm, policySession); err != nil {
		return xerrors.Errorf("cannot execute PCR assertions: %w", err)
	}

	pcrPolicyCounterHandle := p.StaticData.PCRPolicyCounterHandle
	if pcrPolicyCounterHandle != tpm2.HandleNull && pcrPolicyCounterHandle.Type() != tpm2.HandleTypeNVIndex {
		return policyDataError{fmt.Errorf("invalid handle %v for PCR policy counter", pcrPolicyCounterHandle)}
	}

	var pcrPolicyCounter tpm2.ResourceContext
	if pcrPolicyCounterHandle != tpm2.HandleNull {
		var err error
		pcrPolicyCounter, err = tpm.CreateResourceContextFromTPM(pcrPolicyCounterHandle)
		switch {
		case tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle):
			// If there is no NV index at the expected handle then the key file is invalid and must be recreated.
			return policyDataError{errors.New("no PCR policy counter found")}
		case err != nil:
			return err
		}

		if err := p.PCRData.executeRevocationCheck(tpm, pcrPolicyCounter, policySession, nil); err != nil {
			return err
		}
	}

	authPublicKey := p.StaticData.AuthPublicKey
	authorizeKey, err := tpm.LoadExternal(nil, authPublicKey, tpm2.HandleOwner)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandLoadExternal, 2) {
			// StaticData.AuthPublicKey is invalid
			return policyDataError{xerrors.Errorf("public area of dynamic authorization policy signing key is invalid: %w", err)}
		}
		return err
	}
	defer tpm.FlushContext(authorizeKey)

	pcrPolicyRef := computeV1PcrPolicyRefFromCounterContext(pcrPolicyCounter)

	pcrPolicyDigest, err := util.ComputePolicyAuthorizeDigest(authPublicKey.NameAlg, p.PCRData.AuthorizedPolicy, pcrPolicyRef)
	if err != nil {
		return policyDataError{xerrors.Errorf("cannot compute PCR policy digest: %w", err)}
	}

	authorizeTicket, err := tpm.VerifySignature(authorizeKey, pcrPolicyDigest, p.PCRData.AuthorizedPolicySignature)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandVerifySignature, 2) {
			// PCRData.AuthorizedPolicySignature is invalid.
			return policyDataError{xerrors.Errorf("cannot verify PCR policy signature: %w", err)}
		}
		return err
	}

	if err := tpm.PolicyAuthorize(policySession, p.PCRData.AuthorizedPolicy, pcrPolicyRef, authorizeKey.Name(), authorizeTicket); err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyAuthorize, 1) {
			// d.PCRData.AuthorizedPolicy is invalid or the auth key isn't associated with
			// this object.
			return policyDataError{errors.New("the PCR policy is invalid")}
		}
		return err
	}

	// For metadata versions > 0, PIN support was implemented by requiring knowlege of the authorization value for
	// the sealed key object when this policy session is used to unseal it, although this support was never
	// used and has been removed.
	// XXX: This mechanism will be re-used as part of the passphrase integration in the future, although the
	//  authorization value will be a passphrase derived key.
	if err := tpm.PolicyAuthValue(policySession); err != nil {
		return err
	}

	return nil
}

type pcrPolicyCounterContext_v1 struct {
	tpm       *tpm2.TPMContext
	index     tpm2.ResourceContext
	session   tpm2.SessionContext
	updateKey *tpm2.Public
}

func (c *pcrPolicyCounterContext_v1) Get() (uint64, error) {
	return c.tpm.NVReadCounter(c.index, c.index, c.session)
}

func (c *pcrPolicyCounterContext_v1) Increment(key secboot.PrimaryKey) error {
	ecdsaKey, err := createECDSAPrivateKeyFromTPM(c.updateKey, tpm2.ECCParameter(key))
	if err != nil {
		return xerrors.Errorf("cannot create auth key: %w", err)
	}

	// Begin a policy session to increment the index.
	policySession, err := c.tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, c.index.Name().Algorithm())
	if err != nil {
		return err
	}
	defer c.tpm.FlushContext(policySession)

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	keyLoaded, err := c.tpm.LoadExternal(nil, c.updateKey, tpm2.HandleEndorsement)
	if err != nil {
		return err
	}
	defer c.tpm.FlushContext(keyLoaded)

	// Create a signed authorization. keyData.validate checks that this scheme is compatible with the key
	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgECDSA,
		Details: &tpm2.SigSchemeU{
			ECDSA: &tpm2.SigSchemeECDSA{
				HashAlg: c.updateKey.NameAlg}}}
	signature, err := util.SignPolicyAuthorization(ecdsaKey, &scheme, policySession.NonceTPM(), nil, nil, 0)
	if err != nil {
		return xerrors.Errorf("cannot sign authorization: %w", err)
	}

	if _, _, err := c.tpm.PolicySigned(keyLoaded, policySession, true, nil, nil, 0, signature); err != nil {
		return err
	}
	authPolicies := computeV1PcrPolicyCounterAuthPolicies(c.index.Name().Algorithm(), c.updateKey.Name())
	if err := c.tpm.PolicyOR(policySession, authPolicies); err != nil {
		return err
	}

	// Increment the index.
	return c.tpm.NVIncrement(c.index, c.index, policySession, c.session.IncludeAttrs(tpm2.AttrAudit))
}

func (p *keyDataPolicy_v1) PCRPolicyCounterContext(tpm *tpm2.TPMContext, pub *tpm2.NVPublic, session tpm2.SessionContext) (pcrPolicyCounterContext, error) {
	if pub.Index != p.StaticData.PCRPolicyCounterHandle {
		return nil, errors.New("NV index public area is inconsistent with metadata")
	}

	index, err := tpm2.CreateNVIndexResourceContextFromPublic(pub)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for NV index: %w", err)
	}

	return &pcrPolicyCounterContext_v1{
		tpm:       tpm,
		index:     index,
		session:   session,
		updateKey: p.StaticData.AuthPublicKey}, nil
}

func (p *keyDataPolicy_v1) ValidateAuthKey(key secboot.PrimaryKey) error {
	pub, ok := p.StaticData.AuthPublicKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return policyDataError{errors.New("unexpected dynamic authorization policy public key type")}
	}

	expectedX, expectedY := pub.Curve.ScalarBaseMult(key)
	if expectedX.Cmp(pub.X) != 0 || expectedY.Cmp(pub.Y) != 0 {
		return policyDataError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
	}

	return nil
}
