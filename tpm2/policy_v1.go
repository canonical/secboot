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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/util"

	"golang.org/x/xerrors"
)

// computeV1PcrPolicyCounterAuthPolicies computes the authorization policy digests passed to TPM2_PolicyOR for a PCR
// policy counter that can be updated with the key associated with updateKeyName.
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

	trial := util.ComputeAuthPolicy(alg)
	trial.PolicyNvWritten(false)
	authPolicies = append(authPolicies, trial.GetDigest())

	trial = util.ComputeAuthPolicy(alg)
	trial.PolicySigned(updateKeyName, nil)
	authPolicies = append(authPolicies, trial.GetDigest())

	return authPolicies
}

// computeV1PcrPolicyRefFromCounterName computes the reference used for authorization of signed PCR policies from the supplied
// PCR policy counter name. If name is empty, then the name of the null handle is assumed. The policy ref serves 2 purposes:
// 1) It limits the scope of the signed policy to just PCR policies (the dynamic authorization policy key may be able to sign
//    different types of policy in the future, for example, to permit recovery with a signed assertion.
// 2) It binds the name of the PCR policy counter to the static authorization policy.
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

// staticPolicyDataRaw_v1 is version 1 of the on-disk format of staticPolicyData.
type staticPolicyDataRaw_v1 struct {
	AuthPublicKey          *tpm2.Public
	PCRPolicyCounterHandle tpm2.Handle
	PCRPolicyRef           tpm2.Nonce
}

func (d *staticPolicyDataRaw_v1) data() *staticPolicyData {
	return &staticPolicyData{
		authPublicKey:          d.AuthPublicKey,
		pcrPolicyCounterHandle: d.PCRPolicyCounterHandle}
}

// makeStaticPolicyDataRaw_v1 converts staticPolicyData to version 1 of the on-disk format.
func makeStaticPolicyDataRaw_v1(data *staticPolicyData) *staticPolicyDataRaw_v1 {
	return &staticPolicyDataRaw_v1{
		AuthPublicKey:          data.authPublicKey,
		PCRPolicyCounterHandle: data.pcrPolicyCounterHandle}
}

func computeDynamicPolicyV1(alg tpm2.HashAlgorithmId, input *dynamicPolicyComputeParams) (*dynamicPolicyData, error) {
	if len(input.pcrDigests) == 0 {
		return nil, errors.New("no PCR digests specified")
	}

	// Compute the policy digest that would result from a TPM2_PolicyPCR assertion for each condition
	var pcrOrDigests tpm2.DigestList
	for _, d := range input.pcrDigests {
		trial := util.ComputeAuthPolicy(alg)
		trial.PolicyPCR(d, input.pcrs)
		pcrOrDigests = append(pcrOrDigests, trial.GetDigest())
	}

	trial := util.ComputeAuthPolicy(alg)
	pcrOrData := computePolicyORData(alg, trial, pcrOrDigests)

	if len(input.policyCounterName) > 0 {
		operandB := make([]byte, 8)
		binary.BigEndian.PutUint64(operandB, input.policyCount)
		trial.PolicyNV(input.policyCounterName, operandB, 0, tpm2.OpUnsignedLE)
	}

	authorizedPolicy := trial.GetDigest()

	// Create a digest to sign
	h := input.signAlg.NewHash()
	h.Write(authorizedPolicy)
	h.Write(computeV1PcrPolicyRefFromCounterName(input.policyCounterName))

	// Sign the digest
	sigR, sigS, err := ecdsa.Sign(rand.Reader, input.key.(*ecdsa.PrivateKey), h.Sum(nil))
	if err != nil {
		return nil, xerrors.Errorf("cannot provide signature for initializing NV index: %w", err)
	}

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgECDSA,
		Signature: &tpm2.SignatureU{
			ECDSA: &tpm2.SignatureECDSA{
				Hash:       input.signAlg,
				SignatureR: sigR.Bytes(),
				SignatureS: sigS.Bytes()}}}

	return &dynamicPolicyData{
		pcrSelection:              input.pcrs,
		pcrOrData:                 pcrOrData,
		policyCount:               input.policyCount,
		authorizedPolicy:          authorizedPolicy,
		authorizedPolicySignature: &signature}, nil
}

func executePolicySessionV1(tpm *tpm2.TPMContext, policySession tpm2.SessionContext, staticInput *staticPolicyData,
	dynamicInput *dynamicPolicyData, hmacSession tpm2.SessionContext) error {
	if err := tpm.PolicyPCR(policySession, nil, dynamicInput.pcrSelection); err != nil {
		return xerrors.Errorf("cannot execute PCR assertion: %w", err)
	}

	if err := executePolicyORAssertions(tpm, policySession, dynamicInput.pcrOrData); err != nil {
		switch {
		case tpm2.IsTPMError(err, tpm2.AnyErrorCode, tpm2.CommandPolicyGetDigest):
			return xerrors.Errorf("cannot execute OR assertions: %w", err)
		case tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyOR, 1):
			// The dynamic authorization policy data is invalid.
			return dynamicPolicyDataError{errors.New("cannot complete OR assertions: invalid data")}
		}
		return dynamicPolicyDataError{xerrors.Errorf("cannot complete OR assertions: %w", err)}
	}

	pcrPolicyCounterHandle := staticInput.pcrPolicyCounterHandle
	if pcrPolicyCounterHandle != tpm2.HandleNull && pcrPolicyCounterHandle.Type() != tpm2.HandleTypeNVIndex {
		return staticPolicyDataError{errors.New("invalid handle for PCR policy counter")}
	}

	var policyCounter tpm2.ResourceContext
	if pcrPolicyCounterHandle != tpm2.HandleNull {
		var err error
		policyCounter, err = tpm.CreateResourceContextFromTPM(pcrPolicyCounterHandle)
		switch {
		case tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle):
			// If there is no NV index at the expected handle then the key file is invalid and must be recreated.
			return staticPolicyDataError{errors.New("no PCR policy counter found")}
		case err != nil:
			return xerrors.Errorf("cannot obtain context for PCR policy counter: %w", err)
		}

		operandB := make([]byte, 8)
		binary.BigEndian.PutUint64(operandB, dynamicInput.policyCount)
		if err := tpm.PolicyNV(policyCounter, policyCounter, policySession, operandB, 0, tpm2.OpUnsignedLE, nil); err != nil {
			switch {
			case tpm2.IsTPMError(err, tpm2.ErrorPolicy, tpm2.CommandPolicyNV):
				// The PCR policy has been revoked.
				return dynamicPolicyDataError{errors.New("the PCR policy has been revoked")}
			case tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandPolicyNV, 1):
				// Either staticInput.v0PinIndexAuthPolicies is invalid or the NV index isn't what's expected, so the key file is invalid.
				return staticPolicyDataError{errors.New("invalid PCR policy counter or associated authorization policy metadata")}
			}
			return xerrors.Errorf("PCR policy revocation check failed: %w", err)
		}
	}

	authPublicKey := staticInput.authPublicKey
	if !authPublicKey.NameAlg.Available() {
		return staticPolicyDataError{errors.New("public area of dynamic authorization policy signing key has an unsupported name algorithm")}
	}
	authorizeKey, err := tpm.LoadExternal(nil, authPublicKey, tpm2.HandleOwner)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandLoadExternal, 2) {
			// staticInput.AuthPublicKey is invalid
			return staticPolicyDataError{errors.New("public area of dynamic authorization policy signing key is invalid")}
		}
		return xerrors.Errorf("cannot load public area for dynamic authorization policy signing key: %w", err)
	}
	defer tpm.FlushContext(authorizeKey)

	pcrPolicyRef := computeV1PcrPolicyRefFromCounterContext(policyCounter)

	h := authPublicKey.NameAlg.NewHash()
	h.Write(dynamicInput.authorizedPolicy)
	h.Write(pcrPolicyRef)

	authorizeTicket, err := tpm.VerifySignature(authorizeKey, h.Sum(nil), dynamicInput.authorizedPolicySignature)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandVerifySignature, 2) {
			// dynamicInput.AuthorizedPolicySignature or the computed policy ref is invalid.
			// XXX: It's not possible to determine whether this is broken dynamic or static metadata -
			//  we should just do away with the distinction here tbh
			return dynamicPolicyDataError{errors.New("cannot verify PCR policy signature")}
		}
		return xerrors.Errorf("cannot verify PCR policy signature: %w", err)
	}

	if err := tpm.PolicyAuthorize(policySession, dynamicInput.authorizedPolicy, pcrPolicyRef, authorizeKey.Name(), authorizeTicket); err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyAuthorize, 1) {
			// dynamicInput.AuthorizedPolicy is invalid.
			return dynamicPolicyDataError{errors.New("the PCR policy is invalid")}
		}
		return xerrors.Errorf("PCR policy check failed: %w", err)
	}

	// For metadata versions > 0, PIN support was implemented by requiring knowlege of the authorization value for
	// the sealed key object when this policy session is used to unseal it, although this support was never
	// used and has been removed.
	// XXX: This mechanism will be re-used as part of the passphrase integration in the future, although the
	//  authorization value will be a passphrase derived key.
	if err := tpm.PolicyAuthValue(policySession); err != nil {
		return xerrors.Errorf("cannot execute PolicyAuthValue assertion: %w", err)
	}

	return nil
}

type pcrPolicyCounterV1 struct {
	pcrPolicyCounterCommon
}

func (c *pcrPolicyCounterV1) Get(tpm *tpm2.TPMContext, session tpm2.SessionContext) (uint64, error) {
	index, err := tpm2.CreateNVIndexResourceContextFromPublic(c.pub)
	if err != nil {
		return 0, xerrors.Errorf("cannot create context for NV index: %w", err)
	}

	value, err := tpm.NVReadCounter(index, index, nil, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return 0, xerrors.Errorf("cannot read counter: %w", err)
	}

	return value, nil
}

func (c *pcrPolicyCounterV1) Increment(tpm *tpm2.TPMContext, key crypto.PrivateKey, session tpm2.SessionContext) error {
	index, err := tpm2.CreateNVIndexResourceContextFromPublic(c.pub)
	if err != nil {
		return xerrors.Errorf("cannot create context for NV index: %w", err)
	}

	// Begin a policy session to increment the index.
	policySession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, c.pub.NameAlg)
	if err != nil {
		return xerrors.Errorf("cannot begin policy session: %w", err)
	}
	defer tpm.FlushContext(policySession)

	// Load the public part of the key in to the TPM. There's no integrity protection for this command as if it's altered in
	// transit then either the signature verification fails or the policy digest will not match the one associated with the NV
	// index.
	keyLoaded, err := tpm.LoadExternal(nil, c.updateKey, tpm2.HandleEndorsement)
	if err != nil {
		return xerrors.Errorf("cannot load public part of key used to verify authorization signature: %w", err)
	}
	defer tpm.FlushContext(keyLoaded)

	// Create a signed authorization. keyData.validate checks that this scheme is compatible with the key
	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgECDSA,
		Details: &tpm2.SigSchemeU{
			ECDSA: &tpm2.SigSchemeECDSA{
				HashAlg: c.updateKey.NameAlg}}}
	signature, err := util.SignPolicyAuthorization(key, &scheme, policySession.NonceTPM(), nil, nil, 0)
	if err != nil {
		return xerrors.Errorf("cannot sign authorization: %w", err)
	}

	if _, _, err := tpm.PolicySigned(keyLoaded, policySession, true, nil, nil, 0, signature); err != nil {
		return xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
	}
	if err := tpm.PolicyOR(policySession, c.authPolicies); err != nil {
		return xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
	}

	// Increment the index.
	if err := tpm.NVIncrement(index, index, policySession, session.IncludeAttrs(tpm2.AttrAudit)); err != nil {
		return xerrors.Errorf("cannot increment NV index: %w", err)
	}

	return nil
}

// newPcrPolicyCounterHandleV1 creates a handle to perform operations on a V1 PCR policy counter
// NV index, created with createPcrPolicyCounter. The key passed to createPcrPolicyCounter must
// be supplied via the updateKey argument.
func newPcrPolicyCounterHandleV1(pub *tpm2.NVPublic, updateKey *tpm2.Public) (pcrPolicyCounterHandle, error) {
	updateKeyName, err := updateKey.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute name of update key: %w", err)
	}

	authPolicies := computeV1PcrPolicyCounterAuthPolicies(pub.NameAlg, updateKeyName)
	return &pcrPolicyCounterV1{pcrPolicyCounterCommon{pub: pub, updateKey: updateKey, authPolicies: authPolicies}}, nil
}
