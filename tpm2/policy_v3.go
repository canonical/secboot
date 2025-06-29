// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019-2023 Canonical Ltd
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
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/policyutil"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/xerrors"

	"github.com/snapcore/secboot"
	internal_crypto "github.com/snapcore/secboot/internal/crypto"
)

// computeV3PcrPolicyRef computes the reference used for authorization of signed PCR policies
// from the supplied role and PCR policy counter name. If name is empty, then the name of the
// null handle is assumed. The policy ref serves 2 purposes:
//  1. It limits the scope of the signed policy to just PCR policies for keys with the same role
//     (the key may be able to sign different types of policy in the future, for example, to permit
//     recovery with a signed assertion).
//  2. It binds the name of the PCR policy counter to the static authorization policy.
func computeV3PcrPolicyRef(alg tpm2.HashAlgorithmId, role []byte, counterName tpm2.Name) tpm2.Nonce {
	if len(role) > math.MaxUint16 {
		// This avoids a panic in MustMarshalToWriter. We check
		// the length of this is valid during key creation in
		// newKeyDataPolicy. It's an error to have to truncate it
		// but the error will be caught elsewhere because we'll
		// generate the wrong policy ref.
		role = role[:math.MaxUint16]
	}
	if len(counterName) == 0 {
		counterName = tpm2.Name(mu.MustMarshalToBytes(tpm2.HandleNull))
	}

	// Hash the role and PCR policy counter name
	// TODO: Maybe have a dummy TPM2_PolicyNV assertion in the static policy
	//  to bind it to the PCR policy counter as an alternative to hashing
	//  its name here.
	h := alg.NewHash()
	mu.MustMarshalToWriter(h, role, counterName)
	digest := h.Sum(nil)

	// Hash again with a string literal prefix
	h = alg.NewHash()
	h.Write([]byte("PCR-POLICY"))
	h.Write(digest)

	return h.Sum(nil)
}

// computeV3PcrPolicyRefFromCounterContext computes the reference used for authorization of
// signed PCR policies from the supplied ResourceContext.
func computeV3PcrPolicyRefFromCounterContext(alg tpm2.HashAlgorithmId, role []byte, context tpm2.ResourceContext) tpm2.Nonce {
	var name tpm2.Name
	if context != nil {
		name = context.Name()
	}

	return computeV3PcrPolicyRef(alg, role, name)
}

// computeV3PcrPolicyCounterAuthPolicies computes the authorization policy digests passed to
// TPM2_PolicyOR for a PCR policy counter that can be updated with the key associated with
// updateKeyName.
func computeV3PcrPolicyCounterAuthPolicies(alg tpm2.HashAlgorithmId, updateKey *tpm2.Public) (tpm2.DigestList, error) {
	if !alg.Available() {
		return nil, errors.New("digest algorithm is not available")
	}

	// The NV index requires 3 policies:
	// - A policy to read the index with no authorization.
	// - A policy to use the index with TPM2_PolicyNV with no authorization.
	// - A policy to initialize the index with no authorization.
	// - A policy for updating the index to revoke old PCR policies using a signed assertion.
	var authPolicies tpm2.DigestList

	builder := policyutil.NewPolicyBuilder(alg)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVRead)
	digest, err := builder.Digest()
	if err != nil {
		return nil, err
	}
	authPolicies = append(authPolicies, digest)

	builder = policyutil.NewPolicyBuilder(alg)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandPolicyNV)
	digest, err = builder.Digest()
	if err != nil {
		return nil, err
	}
	authPolicies = append(authPolicies, digest)

	builder = policyutil.NewPolicyBuilder(alg)
	builder.RootBranch().PolicyNvWritten(false)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVIncrement)
	digest, err = builder.Digest()
	if err != nil {
		return nil, err
	}
	authPolicies = append(authPolicies, digest)

	builder = policyutil.NewPolicyBuilder(alg)
	builder.RootBranch().PolicySigned(updateKey, []byte("PCR-POLICY-REVOKE"))
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVIncrement)
	digest, err = builder.Digest()
	if err != nil {
		return nil, err
	}
	authPolicies = append(authPolicies, digest)

	return authPolicies, nil
}

// deriveV3PolicyAuthKey derives an elliptic curve key for signing authorization policies from the
// supplied input key. Pre-v3 key objects stored the private part of the elliptic curve key inside
// the sealed key, but v3 keys are wrapped by secboot.KeyData which protects an auxiliary key that
// is used as an input key to derive various context-specific keys, such as this one.
func deriveV3PolicyAuthKey(alg crypto.Hash, key secboot.PrimaryKey) (*ecdsa.PrivateKey, error) {
	r := hkdf.Expand(func() hash.Hash { return alg.New() }, key, []byte("TPM2-POLICY-AUTH"))
	return internal_crypto.GenerateECDSAKey(elliptic.P256(), r)
}

// staticPolicyData_v3 represents version 3 of the metadata for executing a
// policy session that never changes for the life of a key.
type staticPolicyData_v3 struct {
	AuthPublicKey          *tpm2.Public
	PCRPolicyRef           tpm2.Nonce
	PCRPolicyCounterHandle tpm2.Handle
	RequireAuthValue       bool
}

// policyOrData_v3 is the version 3 on-disk representation of policyOrTree.
// It is a flattened tree which suitable for serializing - the tree is just
// a slice of nodes, with each node specifying an offset to its parent node.
type policyOrData_v3 = policyOrData_v0

// pcrPolicyData_v3 represents version 3 of the PCR policy metadata for
// executing a policy session, and can be updated. It has the same format
// as version 2.
type pcrPolicyData_v3 struct {
	// This is mostly the same as v0-v2, with the only difference being
	// how the call to executeRevocationCheck works.
	pcrPolicyData_v2
}

func (d *pcrPolicyData_v3) executeRevocationCheck(tpm *tpm2.TPMContext, counter tpm2.ResourceContext, updateKey *tpm2.Public, policySession tpm2.SessionContext) error {
	operandB := make([]byte, 8)
	binary.BigEndian.PutUint64(operandB, d.PolicySequence)

	// We create a new policy session in order to authorize running TPM2_PolicyNV
	// against the PCR policy counter NV index, which has a policy branch that
	// permits using TPM2_PolicyNV without any additional authorization or requirements
	// (it only contains a TPM2_PolicyCommandCode assertion).
	// In the future, when policies are executed with policyutil.Policy.Execute,
	// having branches that permit TPM2_PolicyNV and TPM2_NV_Read without any extra
	// authorization aids in the automatic branch selection.
	//
	// The TPM2_PolicyNV assertion is executed on and updates the main policy session
	// supplied to this function - this extra policy session is just to permit the
	// TPM2_PolicyNV assertion to be executed against the NV counter index.
	//
	// XXX(chrisccoulson): This is the 3rd session we open here, with all 3 loaded
	// on the TPM. PC Client TPMs are only guaranteed to support 3 loaded sessions,
	// so we're pushing things a bit close to the wire here. This code does execute
	// during early boot, but it might be better to make the HMAC session associated
	// with the TPM connection unloaded by default (context saved), and only context
	// load it when needed.
	revocationCheckSession, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, counter.Name().Algorithm())
	if err != nil {
		return fmt.Errorf("cannot create policy session for revocation check: %w", err)
	}
	defer tpm.FlushContext(revocationCheckSession)

	authPolicies, err := computeV3PcrPolicyCounterAuthPolicies(counter.Name().Algorithm(), updateKey)
	if err != nil {
		return policyDataError{fmt.Errorf("cannot compute auth policies for PCR policy counter: %w", err)}
	}
	if err := tpm.PolicyCommandCode(revocationCheckSession, tpm2.CommandPolicyNV); err != nil {
		return err
	}
	if err := tpm.PolicyOR(revocationCheckSession, authPolicies); err != nil {
		return err
	}

	if err := tpm.PolicyNV(counter, counter, policySession, operandB, 0, tpm2.OpUnsignedLE, revocationCheckSession); err != nil {
		switch {
		case tpm2.IsTPMError(err, tpm2.ErrorPolicy, tpm2.CommandPolicyNV):
			// The PCR policy has been revoked.
			return policyDataError{errors.New("the PCR policy has been revoked")}
		case tpm2.IsTPMSessionError(err, tpm2.ErrorPolicyFail, tpm2.CommandPolicyNV, 1):
			// Either StaticData.PCRPolicyCounterAuthPolicies is invalid or the NV index isn't what's expected, so the key file is invalid.
			return policyDataError{errors.New("invalid PCR policy counter or associated authorization policy metadata")}
		}
		return xerrors.Errorf("cannot complete PCR policy revocation check: %w", err)
	}

	return nil
}

// keyDataPolicy_v3 represents version 3 of the metadata for executing a
// policy session.
type keyDataPolicy_v3 struct {
	StaticData *staticPolicyData_v3
	PCRData    *pcrPolicyData_v3
}

func (p *keyDataPolicy_v3) PCRPolicyCounterHandle() tpm2.Handle {
	return p.StaticData.PCRPolicyCounterHandle
}

func (p *keyDataPolicy_v3) PCRPolicySequence() uint64 {
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
func (p *keyDataPolicy_v3) UpdatePCRPolicy(alg tpm2.HashAlgorithmId, params *pcrPolicyParams) error {
	pcrData := new(pcrPolicyData_v3)

	builder, err := pcrData.addPcrAssertions(alg, params.pcrs, params.pcrDigests)
	if err != nil {
		return xerrors.Errorf("cannot compute base PCR policy: %w", err)
	}

	if params.policyCounter != nil {
		pcrData.addRevocationCheck(builder, params.policyCounter, params.policySequence)
	}

	key, err := deriveV3PolicyAuthKey(p.StaticData.AuthPublicKey.NameAlg.GetHash(), params.key)
	if err != nil {
		return xerrors.Errorf("cannot derive auth key: %w", err)
	}

	approvedPolicy, err := builder.Digest()
	if err != nil {
		return fmt.Errorf("cannot compute approved policy: %w", err)
	}

	var policyCounterName tpm2.Name
	if params.policyCounter != nil {
		policyCounterName = params.policyCounter.Name()
	}
	p.StaticData.PCRPolicyRef = computeV3PcrPolicyRef(alg, params.role, policyCounterName)
	if err := pcrData.authorizePolicy(approvedPolicy, p.StaticData.AuthPublicKey, p.StaticData.PCRPolicyRef, key, p.StaticData.AuthPublicKey.NameAlg); err != nil {
		return xerrors.Errorf("cannot authorize policy: %w", err)
	}

	p.PCRData = pcrData
	return nil
}

func (p *keyDataPolicy_v3) SetPCRPolicyFrom(src keyDataPolicy) {
	p.PCRData = src.(*keyDataPolicy_v3).PCRData
}

func (p *keyDataPolicy_v3) ExecutePCRPolicy(tpm *tpm2.TPMContext, policySession, _ tpm2.SessionContext) error {
	if err := p.PCRData.executePcrAssertions(tpm, policySession); err != nil {
		return xerrors.Errorf("cannot execute PCR assertions: %w", err)
	}

	pcrPolicyCounterHandle := p.StaticData.PCRPolicyCounterHandle
	if pcrPolicyCounterHandle != tpm2.HandleNull && pcrPolicyCounterHandle.Type() != tpm2.HandleTypeNVIndex {
		return policyDataError{fmt.Errorf("invalid handle %v for PCR policy counter", pcrPolicyCounterHandle)}
	}

	authPublicKey := p.StaticData.AuthPublicKey

	var pcrPolicyCounter tpm2.ResourceContext
	if pcrPolicyCounterHandle != tpm2.HandleNull {
		var err error
		pcrPolicyCounter, err = tpm.NewResourceContext(pcrPolicyCounterHandle)
		switch {
		case tpm2.IsResourceUnavailableError(err, pcrPolicyCounterHandle):
			// If there is no NV index at the expected handle then the key file is invalid and must be recreated.
			return policyDataError{errors.New("no PCR policy counter found")}
		case err != nil:
			return err
		}

		if err := p.PCRData.executeRevocationCheck(tpm, pcrPolicyCounter, authPublicKey, policySession); err != nil {
			return err
		}
	}

	authorizeKey, err := tpm.LoadExternal(nil, authPublicKey, tpm2.HandleOwner)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandLoadExternal, 2) {
			// StaticData.AuthPublicKey is invalid
			return policyDataError{xerrors.Errorf("public area of dynamic authorization policy signing key is invalid: %w", err)}
		}
		return err
	}
	defer tpm.FlushContext(authorizeKey)

	pcrPolicyRef := p.StaticData.PCRPolicyRef

	if !authPublicKey.NameAlg.Available() {
		return policyDataError{errors.New("name algorithm for auth public key is not available")}
	}
	pcrPolicyDigest := policyutil.ComputePolicyAuthorizationTBSDigest(authPublicKey.NameAlg.GetHash(), p.PCRData.AuthorizedPolicy, pcrPolicyRef)

	authorizeTicket, err := tpm.VerifySignature(authorizeKey, pcrPolicyDigest, p.PCRData.AuthorizedPolicySignature)
	if err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.AnyErrorCode, tpm2.CommandVerifySignature, 2) {
			// d.PCRData.AuthorizedPolicySignature, d.StaticData.PCRPolicyRef or d.PCRData.AuthorizedPolicy
			// is invalid. The public key could also be incorrect, but this would be detected when
			// attempting to update the PCR policy.
			return pcrPolicyDataError{xerrors.Errorf("cannot verify PCR policy signature: %w", err)}
		}
		return err
	}

	if err := tpm.PolicyAuthorize(policySession, p.PCRData.AuthorizedPolicy, pcrPolicyRef, authorizeKey.Name(), authorizeTicket); err != nil {
		if tpm2.IsTPMParameterError(err, tpm2.ErrorValue, tpm2.CommandPolicyAuthorize, 1) {
			// d.PCRData.AuthorizedPolicy is invalid.
			return pcrPolicyDataError{errors.New("the PCR policy is invalid")}
		}
		return err
	}

	if p.StaticData.RequireAuthValue {
		if err := tpm.PolicyAuthValue(policySession); err != nil {
			return err
		}
	}

	return nil
}

type pcrPolicyCounterContext_v3 struct {
	tpm       *tpm2.TPMContext
	index     tpm2.ResourceContext
	updateKey *tpm2.Public
}

func (c *pcrPolicyCounterContext_v3) Get() (uint64, error) {
	return c.tpm.NVReadCounter(c.index, c.index, nil)
}

func (c *pcrPolicyCounterContext_v3) Increment(key secboot.PrimaryKey) error {
	ecdsaKey, err := deriveV3PolicyAuthKey(c.updateKey.NameAlg.GetHash(), key)
	if err != nil {
		return xerrors.Errorf("cannot derive auth key: %w", err)
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
	params := &policyutil.PolicySignedParams{NonceTPM: policySession.State().NonceTPM}
	auth, err := policyutil.SignPolicySignedAuthorization(rand.Reader, params, c.updateKey, []byte("PCR-POLICY-REVOKE"), ecdsaKey, c.updateKey.NameAlg)
	if err != nil {
		return xerrors.Errorf("cannot sign authorization: %w", err)
	}

	if _, _, err := c.tpm.PolicySigned(keyLoaded, policySession, true, nil, []byte("PCR-POLICY-REVOKE"), 0, auth.Signature); err != nil {
		return err
	}
	if err := c.tpm.PolicyCommandCode(policySession, tpm2.CommandNVIncrement); err != nil {
		return err
	}
	authPolicies, err := computeV3PcrPolicyCounterAuthPolicies(c.index.Name().Algorithm(), c.updateKey)
	if err != nil {
		return fmt.Errorf("cannot compute OR policies for index: %w", err)
	}
	if err := c.tpm.PolicyOR(policySession, authPolicies); err != nil {
		return err
	}

	// Increment the index.
	return c.tpm.NVIncrement(c.index, c.index, policySession)
}

func (p *keyDataPolicy_v3) PCRPolicyCounterContext(tpm *tpm2.TPMContext, pub *tpm2.NVPublic) (pcrPolicyCounterContext, error) {
	if pub.Index != p.StaticData.PCRPolicyCounterHandle {
		return nil, errors.New("NV index public area is inconsistent with metadata")
	}

	index, err := tpm2.NewNVIndexResourceContextFromPub(pub)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context for NV index: %w", err)
	}

	return &pcrPolicyCounterContext_v3{
		tpm:       tpm,
		index:     index,
		updateKey: p.StaticData.AuthPublicKey}, nil
}

func (p *keyDataPolicy_v3) RequireUserAuth() bool {
	return p.StaticData.RequireAuthValue
}

func (p *keyDataPolicy_v3) ValidateAuthKey(key secboot.PrimaryKey) error {
	priv, err := deriveV3PolicyAuthKey(p.StaticData.AuthPublicKey.NameAlg.GetHash(), key)
	if err != nil {
		return xerrors.Errorf("cannot derive private key: %w", err)
	}

	pub, ok := p.StaticData.AuthPublicKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return policyDataError{errors.New("unexpected dynamic authorization policy public key type")}
	}

	expectedX, expectedY := pub.Curve.ScalarBaseMult(priv.D.Bytes())
	if expectedX.Cmp(pub.X) != 0 || expectedY.Cmp(pub.Y) != 0 {
		return policyDataError{errors.New("dynamic authorization policy signing private key doesn't match public key")}
	}

	return nil
}
