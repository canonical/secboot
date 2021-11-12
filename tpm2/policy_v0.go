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
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/util"

	"golang.org/x/xerrors"
)

// computeV0PinNVIndexPostInitAuthPolicies computes the authorization policy digests associated with the post-initialization
// actions on a NV index created with the removed createPinNVIndex for version 0 key files. These are:
// - A policy for updating the index to revoke old dynamic authorization policies, requiring an assertion signed by the key
//   associated with updateKeyName.
// - A policy for updating the authorization value (PIN / passphrase), requiring knowledge of the current authorization value.
// - A policy for reading the counter value without knowing the authorization value, as the value isn't secret.
// - A policy for using the counter value in a TPM2_PolicyNV assertion without knowing the authorization value.
func computeV0PinNVIndexPostInitAuthPolicies(alg tpm2.HashAlgorithmId, updateKeyName tpm2.Name) tpm2.DigestList {
	var out tpm2.DigestList
	// Compute a policy for incrementing the index to revoke dynamic authorization policies, requiring an assertion signed by the
	// key associated with updateKeyName.
	trial := util.ComputeAuthPolicy(alg)
	trial.PolicyCommandCode(tpm2.CommandNVIncrement)
	trial.PolicyNvWritten(true)
	trial.PolicySigned(updateKeyName, nil)
	out = append(out, trial.GetDigest())

	// Compute a policy for updating the authorization value of the index, requiring knowledge of the current authorization value.
	trial = util.ComputeAuthPolicy(alg)
	trial.PolicyCommandCode(tpm2.CommandNVChangeAuth)
	trial.PolicyAuthValue()
	out = append(out, trial.GetDigest())

	// Compute a policy for reading the counter value without knowing the authorization value.
	trial = util.ComputeAuthPolicy(alg)
	trial.PolicyCommandCode(tpm2.CommandNVRead)
	out = append(out, trial.GetDigest())

	// Compute a policy for using the counter value in a TPM2_PolicyNV assertion without knowing the authorization value.
	trial = util.ComputeAuthPolicy(alg)
	trial.PolicyCommandCode(tpm2.CommandPolicyNV)
	out = append(out, trial.GetDigest())

	return out
}

// dynamicPolicyDataRaw_v0 is version 0 of the on-disk format of dynamicPolicyData.
type dynamicPolicyDataRaw_v0 struct {
	PCRSelection              tpm2.PCRSelectionList
	PCROrData                 policyOrDataTree
	PolicyCount               uint64
	AuthorizedPolicy          tpm2.Digest
	AuthorizedPolicySignature *tpm2.Signature
}

func (d *dynamicPolicyDataRaw_v0) data() *dynamicPolicyData {
	return &dynamicPolicyData{
		pcrSelection:              d.PCRSelection,
		pcrOrData:                 d.PCROrData,
		policyCount:               d.PolicyCount,
		authorizedPolicy:          d.AuthorizedPolicy,
		authorizedPolicySignature: d.AuthorizedPolicySignature}
}

// makeDynamicPolicyDataRaw_v0 converts dynamicPolicyData to version 0 of the on-disk format.
func makeDynamicPolicyDataRaw_v0(data *dynamicPolicyData) *dynamicPolicyDataRaw_v0 {
	return &dynamicPolicyDataRaw_v0{
		PCRSelection:              data.pcrSelection,
		PCROrData:                 data.pcrOrData,
		PolicyCount:               data.policyCount,
		AuthorizedPolicy:          data.authorizedPolicy,
		AuthorizedPolicySignature: data.authorizedPolicySignature}
}

// staticPolicyDataRaw_v0 is version 0 of the on-disk format of staticPolicyData.
type staticPolicyDataRaw_v0 struct {
	AuthPublicKey        *tpm2.Public
	PinIndexHandle       tpm2.Handle
	PinIndexAuthPolicies tpm2.DigestList
}

func (d *staticPolicyDataRaw_v0) data() *staticPolicyData {
	return &staticPolicyData{
		authPublicKey:          d.AuthPublicKey,
		pcrPolicyCounterHandle: d.PinIndexHandle,
		v0PinIndexAuthPolicies: d.PinIndexAuthPolicies}
}

// makeStaticPolicyDataRaw_v0 converts staticPolicyData to version 0 of the on-disk format.
func makeStaticPolicyDataRaw_v0(data *staticPolicyData) *staticPolicyDataRaw_v0 {
	return &staticPolicyDataRaw_v0{
		AuthPublicKey:        data.authPublicKey,
		PinIndexHandle:       data.pcrPolicyCounterHandle,
		PinIndexAuthPolicies: data.v0PinIndexAuthPolicies}
}

// computeDynamicPolicy computes the PCR policy associated with a sealed key object, and can be updated without having to create a
// new sealed key object as it takes advantage of the PolicyAuthorize assertion. The PCR policy asserts that the following are true:
// - The selected PCRs contain expected values - ie, one of the sets of permitted values specified by the caller to this function,
//   indicating that the device is in an expected state. This is done by a single PolicyPCR assertion and then one or more PolicyOR
//   assertions (depending on how many sets of permitted PCR values there are).
// - The PCR policy hasn't been revoked. This is done using a PolicyNV assertion to assert that the value of an optional NV counter
//   is not greater than the expected value.
// The computed PCR policy digest is signed with the supplied asymmetric key, and the signature of this is validated before executing
// the corresponding PolicyAuthorize assertion as part of the static policy.
func computeDynamicPolicyV0(alg tpm2.HashAlgorithmId, input *dynamicPolicyComputeParams) (*dynamicPolicyData, error) {
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

	// Sign the digest
	sig, err := rsa.SignPSS(rand.Reader, input.key.(*rsa.PrivateKey), input.signAlg.GetHash(), h.Sum(nil),
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return nil, xerrors.Errorf("cannot provide signature for initializing NV index: %w", err)
	}

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSAPSS,
		Signature: &tpm2.SignatureU{
			RSAPSS: &tpm2.SignatureRSAPSS{
				Hash: input.signAlg,
				Sig:  tpm2.PublicKeyRSA(sig)}}}

	return &dynamicPolicyData{
		pcrSelection:              input.pcrs,
		pcrOrData:                 pcrOrData,
		policyCount:               input.policyCount,
		authorizedPolicy:          authorizedPolicy,
		authorizedPolicySignature: &signature}, nil
}

func executePolicySessionV0(tpm *tpm2.TPMContext, policySession tpm2.SessionContext, staticInput *staticPolicyData,
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
	if pcrPolicyCounterHandle.Type() != tpm2.HandleTypeNVIndex {
		return staticPolicyDataError{errors.New("invalid handle for PCR policy counter")}
	}

	policyCounter, err := tpm.CreateResourceContextFromTPM(pcrPolicyCounterHandle)
	switch {
	case tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle):
		// If there is no NV index at the expected handle then the key file is invalid and must be recreated.
		return staticPolicyDataError{errors.New("no PCR policy counter found")}
	case err != nil:
		return xerrors.Errorf("cannot obtain context for PCR policy counter: %w", err)
	}

	policyCounterPub, _, err := tpm.NVReadPublic(policyCounter)
	if err != nil {
		return xerrors.Errorf("cannot read public area for PCR policy counter: %w", err)
	}
	if !policyCounterPub.NameAlg.Available() {
		//If the NV index has an unsupported name algorithm, then this key file is invalid and must be recreated.
		return staticPolicyDataError{errors.New("PCR policy counter has an unsupported name algorithm")}
	}

	revocationCheckSession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, policyCounterPub.NameAlg)
	if err != nil {
		return xerrors.Errorf("cannot create session for PCR policy revocation check: %w", err)
	}
	defer tpm.FlushContext(revocationCheckSession)

	// See the comment for computeV0PinNVIndexPostInitAuthPolicies for a description of the authorization policy
	// for the v0 NV index. Because the v0 NV index was also used for the PIN, it needed an authorization policy to
	// permit using the counter value in an assertion without knowing the authorization value of the index.
	if err := tpm.PolicyCommandCode(revocationCheckSession, tpm2.CommandPolicyNV); err != nil {
		return xerrors.Errorf("cannot execute assertion for PCR policy revocation check: %w", err)
	}
	if err := tpm.PolicyOR(revocationCheckSession, staticInput.v0PinIndexAuthPolicies); err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyOR, 1) {
			// staticInput.v0PinIndexAuthPolicies is invalid.
			return staticPolicyDataError{errors.New("authorization policy metadata for PCR policy counter is invalid")}
		}
		return xerrors.Errorf("cannot execute assertion for PCR policy revocation check: %w", err)
	}

	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, dynamicInput.policyCount)
	if err := tpm.PolicyNV(policyCounter, policyCounter, policySession, operandB, 0, tpm2.OpUnsignedLE, revocationCheckSession); err != nil {
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

	h := authPublicKey.NameAlg.NewHash()
	h.Write(dynamicInput.authorizedPolicy)

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

	if err := tpm.PolicyAuthorize(policySession, dynamicInput.authorizedPolicy, nil, authorizeKey.Name(), authorizeTicket); err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyAuthorize, 1) {
			// dynamicInput.AuthorizedPolicy is invalid.
			return dynamicPolicyDataError{errors.New("the PCR policy is invalid")}
		}
		return xerrors.Errorf("PCR policy check failed: %w", err)
	}

	// For metadata version 0, PIN support was implemented by asserting knowlege of the authorization value
	// for the PCR policy counter, although this support was never used and has been removed.
	if _, _, err := tpm.PolicySecret(policyCounter, policySession, nil, nil, 0, hmacSession); err != nil {
		return xerrors.Errorf("cannot execute PolicySecret assertion: %w", err)
	}

	// Execute required TPM2_PolicyNV assertion that was used for legacy locking with v0 files -
	// this is only here because the existing policy for v0 files requires it. It is not expected that
	// this will fail unless the NV index has been removed or altered, at which point the key is
	// non-recoverable anyway.
	index, err := tpm.CreateResourceContextFromTPM(lockNVHandle)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for lock NV index: %w", err)
	}
	if err := tpm.PolicyNV(index, index, policySession, nil, 0, tpm2.OpEq, nil); err != nil {
		return xerrors.Errorf("policy lock check failed: %w", err)
	}

	return nil
}

type pcrPolicyCounterV0 struct {
	pcrPolicyCounterCommon
}

func (c *pcrPolicyCounterV0) Get(tpm *tpm2.TPMContext, session tpm2.SessionContext) (uint64, error) {
	authSession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, c.pub.NameAlg)
	if err != nil {
		return 0, xerrors.Errorf("cannot begin policy session: %w", err)
	}
	defer tpm.FlushContext(authSession)

	// See the comment for computeV0PinNVIndexPostInitAuthPolicies for a description of the authorization policy
	// for the v0 NV index. Because the v0 NV index was also used for the PIN, it needed an authorization policy
	// to permit reading the counter value without knowing the authorization value of the index.
	if err := tpm.PolicyCommandCode(authSession, tpm2.CommandNVRead); err != nil {
		return 0, xerrors.Errorf("cannot execute assertion to read counter: %w", err)
	}
	if err := tpm.PolicyOR(authSession, c.authPolicies); err != nil {
		return 0, xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
	}

	index, err := tpm2.CreateNVIndexResourceContextFromPublic(c.pub)
	if err != nil {
		return 0, xerrors.Errorf("cannot create context for NV index: %w", err)
	}

	value, err := tpm.NVReadCounter(index, index, authSession, session.IncludeAttrs(tpm2.AttrAudit))
	if err != nil {
		return 0, xerrors.Errorf("cannot read counter: %w", err)
	}

	return value, nil
}

func (c *pcrPolicyCounterV0) Increment(tpm *tpm2.TPMContext, key crypto.PrivateKey, session tpm2.SessionContext) error {
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
		Scheme: tpm2.SigSchemeAlgRSAPSS,
		Details: &tpm2.SigSchemeU{
			RSAPSS: &tpm2.SigSchemeRSAPSS{
				HashAlg: c.updateKey.NameAlg}}}
	signature, err := util.SignPolicyAuthorization(key, &scheme, policySession.NonceTPM(), nil, nil, 0)
	if err != nil {
		return xerrors.Errorf("cannot sign authorization: %w", err)
	}

	// See the comment for computeV0PinNVIndexPostInitAuthPolicies for a description of the authorization policy
	// for the v0 NV index.
	if err := tpm.PolicyCommandCode(policySession, tpm2.CommandNVIncrement); err != nil {
		return xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
	}
	if err := tpm.PolicyNvWritten(policySession, true); err != nil {
		return xerrors.Errorf("cannot execute assertion to increment counter: %w", err)
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

// newPcrPolicyCounterHandleV0 creates a handle to perform operations on a legacy V0 PIN NV index,
// originally created with createPinNVIndex (which has since been deleted). The key originally passed
// to createPinNVIndex must be supplied via the updateKey argument, and the authorization
// policy digests returned from createPinNVIndex must be supplied via the authPolicies argument.
func newPcrPolicyCounterHandleV0(pub *tpm2.NVPublic, updateKey *tpm2.Public, authPolicies tpm2.DigestList) pcrPolicyCounterHandle {
	return &pcrPolicyCounterV0{pcrPolicyCounterCommon{pub: pub, updateKey: updateKey, authPolicies: authPolicies}}
}
